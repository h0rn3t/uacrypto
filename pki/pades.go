package pki

import (
	"bytes"
	"cmp"
	"compress/zlib"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
)

// Limits on what VerifyPAdES and SignPAdES read from an untrusted PDF.
const (
	maxPDFDepth        = 64      // nesting of arrays and dictionaries
	maxPDFXrefSections = 1024    // revisions in the /Prev chain
	maxPDFFieldDepth   = 32      // nesting of form fields through /Kids
	maxPDFRefChain     = 16      // an indirect object that names another
	maxPDFStream       = 1 << 24 // a decoded stream of the DSS
)

// padesContentsSize is the space SignPAdES reserves for the CMS in /Contents,
// in bytes, as in the ЦЗО examples.
const padesContentsSize = 10240

// A PDFSignature is a signature of a PDF document that VerifyPAdES verified.
type PDFSignature struct {
	// SubFilter is the /SubFilter of the signature dictionary:
	// ETSI.CAdES.detached or adbe.pkcs7.detached for a signature,
	// ETSI.RFC3161 for a document time-stamp.
	SubFilter string
	// ByteRange is the /ByteRange: the signed bytes are
	// [ByteRange[0], ByteRange[0]+ByteRange[1]) and
	// [ByteRange[2], ByteRange[2]+ByteRange[3]), all of the document of that
	// revision but the /Contents hex string.
	ByteRange [4]int64
	// CoversDocument reports that the signed bytes reach the end of the file:
	// no incremental update was appended after the signature. A B-LT or
	// B-LTA signature does not cover the DSS and the document time-stamp
	// added after it; what a later update changed is for the caller to judge.
	CoversDocument bool
	// DigestAlgorithm is the digest algorithm of the SignerInfo: of the
	// signer, or of the TSA for a document time-stamp.
	DigestAlgorithm asn1.ObjectIdentifier
	// Signer is the verified CAdES signer, as VerifySignedData returns it.
	// PAdES leaves the signingTime attribute out, so SigningTime is the /M of
	// the signature dictionary, what the signer claims. Chain and OCSP come
	// from the DSS of the document when the signature itself holds no
	// validation data. For a document time-stamp only Signer.TimeStamp is
	// set.
	Signer Signer
}

// VerifyPAdES verifies every signature of the PDF document pdf (ETSI EN
// 319 142-1, PAdES) as IIT writes them: B-B, B-T, B-LT and B-LTA with
// DSTU 4145 and GOST 34.311 or Kupyna-256. The signatures are the values of
// the signature fields of the interactive form, in every revision; it
// returns them in the order they were made, by the end of their byte range.
//
// A signature dictionary with /SubFilter ETSI.CAdES.detached or
// adbe.pkcs7.detached holds a CAdES signature of one signer over the byte
// range, verified as VerifySignedData does with certs; one with
// ETSI.RFC3161 is a document time-stamp, verified as VerifyTimeStamp does.
// The byte range must start at 0 and leave out exactly the /Contents hex
// string of its signature dictionary. The certificates of the document
// security store (/DSS and its /VRI entries) join certs, and its OCSP
// responses make Signer.Chain and Signer.OCSP as for CAdES-X Long of every
// CAdES signer without validation data of its own, so a DSS must hold the
// path of each such signer to a root; CRLs of the DSS are not read.
//
// VerifyPAdES reads PDFs with cross-reference tables, the form signing tools
// append; a revision with a cross-reference stream, and objects only an
// object stream holds, are errors.ErrUnsupported, as are filters other than
// FlateDecode in the DSS. A signature that does not verify is
// ErrInvalidSignature; a document without signatures is an error.
func VerifyPAdES(pdf []byte, certs []*x509.Certificate) ([]PDFSignature, error) {
	f, err := parsePDF(pdf)
	if err != nil {
		return nil, err
	}
	refs, err := f.signatureValues()
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, errors.New("pki: no signature in the PDF document")
	}
	dss, err := f.documentSecurityStore()
	if err != nil {
		return nil, fmt.Errorf("pki: PDF DSS: %w", err)
	}
	pool := append(slices.Clone(certs), dss.certs...)

	sigs := make([]PDFSignature, 0, len(refs))
	for _, ref := range refs {
		sig, err := f.verifySignature(ref, pool, dss)
		if err != nil {
			return nil, fmt.Errorf("pki: PDF signature %d %d R: %w", ref.num, ref.gen, err)
		}
		sigs = append(sigs, sig)
	}
	slices.SortStableFunc(sigs, func(a, b PDFSignature) int {
		return cmp.Compare(a.ByteRange[2]+a.ByteRange[3], b.ByteRange[2]+b.ByteRange[3])
	})
	return sigs, nil
}

// verifySignature verifies the signature dictionary ref.
func (f *pdfFile) verifySignature(ref pdfRef, pool []*x509.Certificate, dss longTermData) (PDFSignature, error) {
	var sig PDFSignature
	off, ok := f.xref[ref.num]
	if !ok || off < 0 {
		return sig, errors.New("no such object")
	}
	v, end, err := f.objectAt(off, ref.num, false)
	if err != nil {
		return sig, err
	}
	d, ok := v.(pdfDict)
	if !ok {
		return sig, errors.New("the signature value is not a dictionary")
	}
	subFilter, _ := d["SubFilter"].(pdfName)
	sig.SubFilter = string(subFilter)
	contents, ok := d["Contents"].(pdfString)
	if !ok {
		return sig, errors.New("no /Contents string")
	}
	if sig.ByteRange, err = byteRange(d["ByteRange"]); err != nil {
		return sig, err
	}

	// the gap of the byte range is exactly the /Contents of this dictionary
	br := sig.ByteRange
	if br[0] != 0 || br[1] <= off || br[2] <= br[1]+1 || br[2] > int64(end) || br[2]+br[3] > int64(len(f.data)) ||
		f.data[br[1]] != '<' || f.data[br[2]-1] != '>' {
		return sig, fmt.Errorf("/ByteRange %v does not leave out the /Contents of the signature", br)
	}
	gap := make([]byte, hex.DecodedLen(int(br[2]-br[1]-2)))
	if _, err := hex.Decode(gap, f.data[br[1]+1:br[2]-1]); err != nil || !bytes.Equal(gap, contents) {
		return sig, fmt.Errorf("/ByteRange %v does not leave out the /Contents of the signature", br)
	}
	sig.CoversDocument = br[2]+br[3] == int64(len(f.data))
	signed := slices.Concat(f.data[:br[1]], f.data[br[2]:br[2]+br[3]])

	// /Contents is zero-padded after the CMS
	der, rest, err := berValue(contents, 0)
	if err != nil {
		return sig, fmt.Errorf("/Contents: %w", err)
	}
	if slices.ContainsFunc(rest, func(b byte) bool { return b != 0 }) {
		return sig, errors.New("/Contents: data after the CMS")
	}
	sd, err := parseSignedData(der)
	if err != nil {
		return sig, err
	}
	if len(sd.SignerInfos) != 1 {
		return sig, fmt.Errorf("%d signers, PAdES allows one", len(sd.SignerInfos))
	}
	sig.DigestAlgorithm = sd.SignerInfos[0].DigestAlgorithm.Algorithm

	switch sig.SubFilter {
	case "ETSI.CAdES.detached", "adbe.pkcs7.detached":
		_, signers, err := VerifySignedData(der, signed, pool)
		if err != nil {
			return sig, err
		}
		sig.Signer = signers[0]
		if m, ok := d["M"].(pdfString); ok && sig.Signer.SigningTime.IsZero() {
			if sig.Signer.SigningTime, err = parsePDFDate(string(m)); err != nil {
				return sig, err
			}
		}
		if sig.Signer.Chain == nil {
			if sig.Signer.Chain, sig.Signer.OCSP, err = dss.verify(sig.Signer.Certificate, pool); err != nil {
				return sig, fmt.Errorf("DSS: %w", err)
			}
		}
	case "ETSI.RFC3161":
		if sig.Signer.TimeStamp, _, err = verifyTimeStamp(der, signed, pool); err != nil {
			return sig, err
		}
	default:
		return sig, fmt.Errorf("/SubFilter %q: %w", sig.SubFilter, errors.ErrUnsupported)
	}
	return sig, nil
}

// byteRange reads a /ByteRange of four non-negative integers.
func byteRange(v any) ([4]int64, error) {
	var br [4]int64
	a, ok := v.(pdfArray)
	if !ok || len(a) != 4 {
		return br, errors.New("/ByteRange is not four integers")
	}
	for i, n := range a {
		num, ok := n.(pdfNumber)
		x, err := strconv.ParseInt(string(num), 10, 64)
		if !ok || err != nil || x < 0 {
			return br, errors.New("/ByteRange is not four integers")
		}
		br[i] = x
	}
	return br, nil
}

// parsePDFDate parses a PDF date, D:YYYYMMDDHHmmSSOHH'mm', where everything
// after the year may be left out.
func parsePDFDate(s string) (time.Time, error) {
	s = strings.TrimPrefix(s, "D:")
	n := 0
	for n < len(s) && n < 14 && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n < 4 || n%2 != 0 {
		return time.Time{}, fmt.Errorf("date %q", s)
	}
	zone := time.UTC
	if tz := s[n:]; tz != "" && tz[0] != 'Z' {
		hh, mm, _ := strings.Cut(strings.TrimSuffix(tz[1:], "'"), "'")
		h, err1 := strconv.Atoi(hh)
		m, err2 := strconv.Atoi(cmp.Or(mm, "0"))
		if (tz[0] != '+' && tz[0] != '-') || err1 != nil || err2 != nil || h > 23 || m > 59 {
			return time.Time{}, fmt.Errorf("date %q", s)
		}
		offset := h*3600 + m*60
		if tz[0] == '-' {
			offset = -offset
		}
		zone = time.FixedZone("", offset)
	}
	t, err := time.ParseInLocation("20060102150405"[:n], s[:n], zone)
	if err != nil {
		return time.Time{}, fmt.Errorf("date %q: %w", s, err)
	}
	return t, nil
}

// signatureValues returns the signature dictionaries of the signature
// fields of the interactive form, the /V of every field whose /FT, its own
// or inherited, is /Sig.
func (f *pdfFile) signatureValues() ([]pdfRef, error) {
	catalog, err := f.dict(f.trailer["Root"])
	if err != nil {
		return nil, fmt.Errorf("pki: PDF catalog: %w", err)
	}
	form, err := f.dict(catalog["AcroForm"])
	if err != nil {
		return nil, fmt.Errorf("pki: PDF /AcroForm: %w", err)
	}
	fields, err := f.array(form["Fields"])
	if err != nil {
		return nil, fmt.Errorf("pki: PDF /Fields: %w", err)
	}
	var values []pdfRef
	seen := map[pdfRef]bool{}
	var walk func(v any, ft pdfName, depth int) error
	walk = func(v any, ft pdfName, depth int) error {
		if depth > maxPDFFieldDepth {
			return errors.New("pki: PDF form fields nested too deep")
		}
		if ref, ok := v.(pdfRef); ok {
			if seen[ref] {
				return nil
			}
			seen[ref] = true
		}
		field, err := f.dict(v)
		if err != nil {
			return fmt.Errorf("pki: PDF form field: %w", err)
		}
		if t, ok := field["FT"].(pdfName); ok {
			ft = t
		}
		if ft == "Sig" && field["V"] != nil {
			value, ok := field["V"].(pdfRef)
			if !ok {
				return errors.New("pki: PDF signature value is not an indirect object")
			}
			if !slices.Contains(values, value) {
				values = append(values, value)
			}
		}
		kids, err := f.array(field["Kids"])
		if err != nil {
			return fmt.Errorf("pki: PDF /Kids: %w", err)
		}
		for _, kid := range kids {
			if err := walk(kid, ft, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, field := range fields {
		if err := walk(field, "", 0); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// documentSecurityStore returns the certificates and OCSP responses of the
// /DSS of the catalog and of its /VRI entries.
func (f *pdfFile) documentSecurityStore() (longTermData, error) {
	var d longTermData
	catalog, err := f.dict(f.trailer["Root"])
	if err != nil {
		return d, err
	}
	dss, err := f.dict(catalog["DSS"])
	if err != nil {
		return d, err
	}
	vri, err := f.dict(dss["VRI"])
	if err != nil {
		return d, fmt.Errorf("/VRI: %w", err)
	}
	stores := []pdfDict{{"Cert": dss["Certs"], "OCSP": dss["OCSPs"]}}
	for _, key := range slices.Sorted(maps.Keys(vri)) {
		entry, err := f.dict(vri[key])
		if err != nil {
			return d, fmt.Errorf("/VRI: %w", err)
		}
		stores = append(stores, entry)
	}
	for _, store := range stores {
		certs, err := f.streams(store["Cert"])
		if err != nil {
			return d, fmt.Errorf("certificates: %w", err)
		}
		for _, der := range certs {
			if slices.ContainsFunc(d.rawCerts, func(c []byte) bool { return bytes.Equal(c, der) }) {
				continue
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return d, fmt.Errorf("certificate: %w", err)
			}
			d.rawCerts = append(d.rawCerts, der)
			d.certs = append(d.certs, c)
		}
		responses, err := f.streams(store["OCSP"])
		if err != nil {
			return d, fmt.Errorf("OCSP responses: %w", err)
		}
		for _, der := range responses {
			basic, err := basicOCSPResponse(der)
			if err != nil {
				return d, fmt.Errorf("OCSP response: %w", err)
			}
			if !slices.ContainsFunc(d.basics, func(b []byte) bool { return bytes.Equal(b, basic) }) {
				d.basics = append(d.basics, basic)
			}
		}
	}
	return d, nil
}

// streams returns the decoded data of the array of streams v.
func (f *pdfFile) streams(v any) ([][]byte, error) {
	a, err := f.array(v)
	if err != nil {
		return nil, err
	}
	var data [][]byte
	for _, s := range a {
		s, err := f.resolve(s)
		if err != nil {
			return nil, err
		}
		stream, ok := s.(pdfStream)
		if !ok {
			return nil, errors.New("not a stream")
		}
		d, err := stream.decode()
		if err != nil {
			return nil, err
		}
		data = append(data, d)
	}
	return data, nil
}

// SignPAdES signs the PDF document pdf with key and returns it with a
// PAdES-B-B signature appended as an incremental update, as IIT writes it:
// a signature field (a widget annotation of the first page with an empty
// /Rect and no appearance, not added to the page's /Annots) in the
// interactive form with /SigFlags 3, and a signature dictionary with
// /Filter /Adobe.PPKLite, /SubFilter /ETSI.CAdES.detached and /M now, whose
// /Contents of 10240 bytes holds a detached CAdES signature of the byte
// range with the signed attributes contentType, messageDigest and
// signingCertificateV2 (PAdES leaves signingTime out), hashed as SignData
// hashes with opts. opts.Detached is ignored. When tsa is not nil, the
// signature value is time-stamped as by AddSignatureTimeStamp: PAdES-B-T.
// random, normally crypto/rand.Reader, provides the per-signature secret.
//
// SignPAdES appends a cross-reference table, so the last revision of pdf
// must end with one: a cross-reference stream there is
// errors.ErrUnsupported, as is an encrypted document. It fails if key does
// not belong to cert or the signature does not fit in /Contents.
func SignPAdES(ctx context.Context, random io.Reader, pdf []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions, tsa *TSAClient) ([]byte, error) {
	f, err := parsePDF(pdf)
	if err != nil {
		return nil, err
	}
	if f.trailer["Encrypt"] != nil {
		return nil, fmt.Errorf("pki: encrypted PDF: %w", errors.ErrUnsupported)
	}
	rootRef, ok := f.trailer["Root"].(pdfRef)
	if !ok {
		return nil, errors.New("pki: PDF trailer without /Root")
	}
	catalog, err := f.dict(rootRef)
	if err != nil {
		return nil, fmt.Errorf("pki: PDF catalog: %w", err)
	}
	size, err := strconv.ParseInt(string(asNumber(f.trailer["Size"])), 10, 64)
	if err != nil || size < 1 || size > 1<<32 {
		return nil, errors.New("pki: PDF trailer without /Size")
	}

	next := size
	newRef := func() pdfRef {
		next++
		return pdfRef{num: next - 1}
	}
	fieldRef, sigRef := newRef(), newRef()
	now := pdfDate(time.Now())
	field := pdfDict{
		"Type": pdfName("Annot"), "Subtype": pdfName("Widget"), "FT": pdfName("Sig"),
		"F": pdfNumber("132"), "Rect": pdfArray{pdfNumber("0"), pdfNumber("0"), pdfNumber("0"), pdfNumber("0")},
		"T": pdfString("Signature" + strconv.FormatInt(fieldRef.num, 10)), "M": now, "V": sigRef,
	}
	if page, ok := f.firstPage(catalog); ok {
		field["P"] = page
	}
	objects := map[pdfRef]any{fieldRef: field}

	// the form: a new one, or the catalog's with the field added
	catalog = maps.Clone(catalog)
	addField := func(form pdfDict) (pdfDict, error) {
		fields, err := f.array(form["Fields"])
		if err != nil {
			return nil, fmt.Errorf("pki: PDF /Fields: %w", err)
		}
		form = maps.Clone(form)
		form["Fields"] = append(slices.Clone(fields), fieldRef)
		form["SigFlags"] = pdfNumber("3")
		return form, nil
	}
	switch form := catalog["AcroForm"].(type) {
	case nil:
		formRef := newRef()
		objects[formRef] = pdfDict{"Fields": pdfArray{fieldRef}, "SigFlags": pdfNumber("3")}
		catalog["AcroForm"] = formRef
	case pdfRef:
		d, err := f.dict(form)
		if err != nil {
			return nil, fmt.Errorf("pki: PDF /AcroForm: %w", err)
		}
		if objects[form], err = addField(d); err != nil {
			return nil, err
		}
	case pdfDict:
		if catalog["AcroForm"], err = addField(form); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("pki: PDF /AcroForm is not a dictionary")
	}
	objects[rootRef] = catalog

	var b bytes.Buffer
	b.Write(pdf)
	if !bytes.HasSuffix(pdf, []byte("\n")) && !bytes.HasSuffix(pdf, []byte("\r")) {
		b.WriteByte('\n')
	}
	offsets := map[int64]int{}
	for _, ref := range slices.SortedFunc(maps.Keys(objects), func(a, b pdfRef) int { return cmp.Compare(a.num, b.num) }) {
		offsets[ref.num] = b.Len()
		fmt.Fprintf(&b, "%d %d obj\n", ref.num, ref.gen)
		writePDFValue(&b, objects[ref])
		b.WriteString("\nendobj\n")
	}
	offsets[sigRef.num] = b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<</Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M ", sigRef.num)
	writePDFValue(&b, now)
	b.WriteString(" /ByteRange ")
	byteRangeAt := b.Len()
	b.WriteString(strings.Repeat(" ", 64)) // room for [0 a b c]
	b.WriteString(" /Contents ")
	contentsAt := b.Len()
	b.WriteString("<" + strings.Repeat("0", 2*padesContentsSize) + ">")
	contentsEnd := b.Len()
	b.WriteString(">>\nendobj\n")

	xrefAt := b.Len()
	b.WriteString("xref\n")
	nums := slices.Sorted(maps.Keys(offsets))
	for i := 0; i < len(nums); {
		j := i + 1
		for j < len(nums) && nums[j] == nums[j-1]+1 {
			j++
		}
		fmt.Fprintf(&b, "%d %d\n", nums[i], j-i)
		for _, n := range nums[i:j] {
			fmt.Fprintf(&b, "%010d 00000 n\r\n", offsets[n])
		}
		i = j
	}
	trailer := pdfDict{"Size": pdfNumber(strconv.FormatInt(next, 10)), "Root": rootRef, "Prev": pdfNumber(strconv.FormatInt(f.startxref, 10))}
	for _, k := range []pdfName{"Info", "ID"} {
		if v, ok := f.trailer[k]; ok {
			trailer[k] = v
		}
	}
	b.WriteString("trailer\n")
	writePDFValue(&b, trailer)
	fmt.Fprintf(&b, "\nstartxref\n%d\n%%%%EOF\n", xrefAt)

	out := b.Bytes()
	copy(out[byteRangeAt:], fmt.Sprintf("[0 %d %d %d]", contentsAt, contentsEnd, len(out)-contentsEnd))
	sd, err := signContent(random, oidData, slices.Concat(out[:contentsAt], out[contentsEnd:]), key, cert, SignOptions{Detached: true, GOST34311: opts.GOST34311}, false)
	if err != nil {
		return nil, err
	}
	der, err := sd.marshal()
	if err != nil {
		return nil, err
	}
	if tsa != nil {
		if der, err = AddSignatureTimeStamp(ctx, der, tsa); err != nil {
			return nil, err
		}
	}
	if len(der) > padesContentsSize {
		return nil, fmt.Errorf("pki: the signature of %d bytes does not fit in /Contents of %d", len(der), padesContentsSize)
	}
	copy(out[contentsAt+1:], strings.ToUpper(hex.EncodeToString(der)))
	return out, nil
}

// firstPage returns the first page of the page tree of catalog; the
// signature field names it, but does without when the tree is out of reach.
func (f *pdfFile) firstPage(catalog pdfDict) (pdfRef, bool) {
	node := catalog["Pages"]
	for range maxPDFFieldDepth {
		ref, ok := node.(pdfRef)
		if !ok {
			return pdfRef{}, false
		}
		d, err := f.dict(ref)
		if err != nil {
			return pdfRef{}, false
		}
		if d["Type"] == pdfName("Page") {
			return ref, true
		}
		kids, err := f.array(d["Kids"])
		if err != nil || len(kids) == 0 {
			return pdfRef{}, false
		}
		node = kids[0]
	}
	return pdfRef{}, false
}

// pdfDate formats t as a PDF date, D:YYYYMMDDHHmmSS+HH'mm'.
func pdfDate(t time.Time) pdfString {
	_, offset := t.Zone()
	sign := '+'
	if offset < 0 {
		sign, offset = '-', -offset
	}
	return pdfString(fmt.Sprintf("D:%s%c%02d'%02d'", t.Format("20060102150405"), sign, offset/3600, offset%3600/60))
}

// The PDF objects (ISO 32000-1, 7.3) as parsePDF reads them. A number keeps
// its text, so that a rewritten object writes it as it was; a name keeps the
// text after the slash, #-escapes and all.
type (
	pdfName   string
	pdfNumber string
	pdfString []byte
	pdfArray  []any
	pdfDict   map[pdfName]any
	pdfRef    struct{ num, gen int64 }
	pdfStream struct {
		dict pdfDict
		raw  []byte
	}
)

// asNumber returns v if it is a number, "" otherwise.
func asNumber(v any) pdfNumber {
	n, _ := v.(pdfNumber)
	return n
}

// decode returns the data of s, which may be compressed with FlateDecode.
func (s pdfStream) decode() ([]byte, error) {
	filter := s.dict["Filter"]
	if a, ok := filter.(pdfArray); ok && len(a) == 1 {
		filter = a[0]
	}
	switch filter {
	case nil:
		return s.raw, nil
	case pdfName("FlateDecode"):
		if s.dict["DecodeParms"] != nil {
			return nil, fmt.Errorf("stream /DecodeParms: %w", errors.ErrUnsupported)
		}
		r, err := zlib.NewReader(bytes.NewReader(s.raw))
		if err != nil {
			return nil, fmt.Errorf("stream: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(r, maxPDFStream+1))
		if err != nil {
			return nil, fmt.Errorf("stream: %w", err)
		}
		if len(data) > maxPDFStream {
			return nil, fmt.Errorf("stream exceeds %d bytes", maxPDFStream)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("stream /Filter %v: %w", filter, errors.ErrUnsupported)
	}
}

// pdfFile is a PDF document with its cross-reference tables read.
type pdfFile struct {
	data      []byte
	xref      map[int64]int64 // object number → offset in the newest revision; -1 when free
	trailer   pdfDict         // of the newest revision
	startxref int64
}

// parsePDF reads the cross-reference tables of data, from the last
// startxref back through /Prev.
func parsePDF(data []byte) (*pdfFile, error) {
	i := bytes.LastIndex(data, []byte("startxref"))
	if i < 0 {
		return nil, errors.New("pki: not a PDF document: no startxref")
	}
	p := &pdfParser{b: data, pos: i + len("startxref")}
	off, err := p.integer()
	if err != nil {
		return nil, fmt.Errorf("pki: PDF startxref: %w", err)
	}
	f := &pdfFile{data: data, xref: map[int64]int64{}, startxref: off}
	seen := map[int64]bool{}
	for range maxPDFXrefSections {
		if seen[off] || off >= int64(len(data)) {
			return nil, fmt.Errorf("pki: PDF cross-reference table at %d", off)
		}
		seen[off] = true
		trailer, err := f.xrefSection(off)
		if err != nil {
			return nil, err
		}
		if f.trailer == nil {
			f.trailer = trailer
		}
		prev, ok := trailer["Prev"]
		if !ok {
			return f, nil
		}
		if off, err = strconv.ParseInt(string(asNumber(prev)), 10, 64); err != nil || off < 0 {
			return nil, errors.New("pki: PDF trailer /Prev is not an offset")
		}
	}
	return nil, fmt.Errorf("pki: PDF has more than %d revisions", maxPDFXrefSections)
}

// xrefSection reads the cross-reference table at off into f.xref, where
// newer revisions already read keep their entries, and returns its trailer.
func (f *pdfFile) xrefSection(off int64) (pdfDict, error) {
	p := &pdfParser{b: f.data, pos: int(off)}
	if !p.keyword("xref") {
		return nil, fmt.Errorf("pki: PDF has no cross-reference table at %d (a cross-reference stream?): %w", off, errors.ErrUnsupported)
	}
	for !p.keyword("trailer") {
		start, err := p.integer()
		if err != nil {
			return nil, fmt.Errorf("pki: PDF cross-reference table: %w", err)
		}
		count, err := p.integer()
		if err != nil || start > 1<<32 || count > 1<<32 {
			return nil, fmt.Errorf("pki: PDF cross-reference subsection at %d", p.pos)
		}
		for num := start; num < start+count; num++ {
			offset, err := p.integer()
			if err != nil {
				return nil, fmt.Errorf("pki: PDF cross-reference entry: %w", err)
			}
			if _, err := p.integer(); err != nil {
				return nil, fmt.Errorf("pki: PDF cross-reference entry: %w", err)
			}
			p.skipSpace()
			kind := p.regular()
			if kind != "n" && kind != "f" {
				return nil, fmt.Errorf("pki: PDF cross-reference entry of type %q", kind)
			}
			if _, newer := f.xref[num]; newer {
				continue
			}
			if kind == "f" {
				offset = -1
			}
			f.xref[num] = offset
		}
	}
	v, err := p.value(0)
	if err != nil {
		return nil, fmt.Errorf("pki: PDF trailer: %w", err)
	}
	trailer, ok := v.(pdfDict)
	if !ok {
		return nil, errors.New("pki: PDF trailer is not a dictionary")
	}
	return trailer, nil
}

// objectAt parses the indirect object num at offset and returns its value
// and the offset after endobj. With noStream it stops after the value: a
// stream /Length that names an object reads it so, and cannot recurse.
func (f *pdfFile) objectAt(offset, num int64, noStream bool) (any, int, error) {
	if offset >= int64(len(f.data)) {
		return nil, 0, fmt.Errorf("object %d at %d is beyond the end", num, offset)
	}
	p := &pdfParser{b: f.data, pos: int(offset)}
	if n, err := p.integer(); err != nil || n != num {
		return nil, 0, fmt.Errorf("object %d is not at %d", num, offset)
	}
	if _, err := p.integer(); err != nil || !p.keyword("obj") {
		return nil, 0, fmt.Errorf("object %d is not at %d", num, offset)
	}
	v, err := p.value(0)
	if err != nil {
		return nil, 0, fmt.Errorf("object %d: %w", num, err)
	}
	if noStream {
		return v, p.pos, nil
	}
	if d, ok := v.(pdfDict); ok && p.keyword("stream") {
		if bytes.HasPrefix(p.b[p.pos:], []byte("\r\n")) {
			p.pos += 2
		} else if bytes.HasPrefix(p.b[p.pos:], []byte("\n")) {
			p.pos++
		}
		length := d["Length"]
		if ref, ok := length.(pdfRef); ok {
			if off, ok := f.xref[ref.num]; ok && off >= 0 {
				if length, _, err = f.objectAt(off, ref.num, true); err != nil {
					return nil, 0, err
				}
			}
		}
		l, err := strconv.ParseInt(string(asNumber(length)), 10, 64)
		if err != nil || l < 0 || l > int64(len(p.b)-p.pos) {
			return nil, 0, fmt.Errorf("object %d: stream /Length", num)
		}
		v = pdfStream{dict: d, raw: p.b[p.pos : p.pos+int(l)]}
		p.pos += int(l)
		if !p.keyword("endstream") {
			return nil, 0, fmt.Errorf("object %d: no endstream", num)
		}
	}
	if !p.keyword("endobj") {
		return nil, 0, fmt.Errorf("object %d: no endobj", num)
	}
	return v, p.pos, nil
}

// resolve returns the object v names, or v when it is a direct object.
func (f *pdfFile) resolve(v any) (any, error) {
	for range maxPDFRefChain {
		ref, ok := v.(pdfRef)
		if !ok {
			return v, nil
		}
		off, ok := f.xref[ref.num]
		if !ok || off < 0 {
			return nil, fmt.Errorf("object %d %d R is in no cross-reference table (an object stream?): %w", ref.num, ref.gen, errors.ErrUnsupported)
		}
		var err error
		if v, _, err = f.objectAt(off, ref.num, false); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("references nested too deep")
}

// dict resolves v to a dictionary; null is an empty one.
func (f *pdfFile) dict(v any) (pdfDict, error) {
	v, err := f.resolve(v)
	if err != nil {
		return nil, err
	}
	d, ok := v.(pdfDict)
	if !ok && v != nil {
		return nil, errors.New("not a dictionary")
	}
	return d, nil
}

// array resolves v to an array; null is an empty one.
func (f *pdfFile) array(v any) (pdfArray, error) {
	v, err := f.resolve(v)
	if err != nil {
		return nil, err
	}
	a, ok := v.(pdfArray)
	if !ok && v != nil {
		return nil, errors.New("not an array")
	}
	return a, nil
}

// pdfParser reads PDF tokens and objects from b at pos.
type pdfParser struct {
	b   []byte
	pos int
}

func isPDFSpace(c byte) bool {
	return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func isPDFDelimiter(c byte) bool {
	return strings.IndexByte("()<>[]{}/%", c) >= 0
}

// skipSpace skips white space and comments.
func (p *pdfParser) skipSpace() {
	for p.pos < len(p.b) {
		switch c := p.b[p.pos]; {
		case isPDFSpace(c):
			p.pos++
		case c == '%':
			for p.pos < len(p.b) && p.b[p.pos] != '\n' && p.b[p.pos] != '\r' {
				p.pos++
			}
		default:
			return
		}
	}
}

// regular reads a run of regular characters: a number or a keyword.
func (p *pdfParser) regular() string {
	start := p.pos
	for p.pos < len(p.b) && !isPDFSpace(p.b[p.pos]) && !isPDFDelimiter(p.b[p.pos]) {
		p.pos++
	}
	return string(p.b[start:p.pos])
}

// keyword reads the keyword kw if it comes next.
func (p *pdfParser) keyword(kw string) bool {
	p.skipSpace()
	start := p.pos
	if p.regular() == kw {
		return true
	}
	p.pos = start
	return false
}

// integer reads a non-negative integer of digits only.
func (p *pdfParser) integer() (int64, error) {
	p.skipSpace()
	start := p.pos
	token := p.regular()
	if token == "" || strings.Trim(token, "0123456789") != "" {
		return 0, fmt.Errorf("no integer at %d", start)
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("no integer at %d", start)
	}
	return n, nil
}

// value reads a direct object, or a reference num gen R.
func (p *pdfParser) value(depth int) (any, error) {
	if depth > maxPDFDepth {
		return nil, errors.New("objects nested too deep")
	}
	p.skipSpace()
	if p.pos >= len(p.b) {
		return nil, errors.New("unexpected end")
	}
	switch p.b[p.pos] {
	case '/':
		p.pos++
		return pdfName(p.regular()), nil
	case '(':
		return p.literalString()
	case '<':
		if bytes.HasPrefix(p.b[p.pos:], []byte("<<")) {
			p.pos += 2
			return p.dict(depth)
		}
		return p.hexString()
	case '[':
		p.pos++
		a := pdfArray{}
		for {
			p.skipSpace()
			if p.pos < len(p.b) && p.b[p.pos] == ']' {
				p.pos++
				return a, nil
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
	}
	start := p.pos
	token := p.regular()
	switch token {
	case "":
		return nil, fmt.Errorf("unexpected %q at %d", p.b[start], start)
	case "true", "false":
		return token == "true", nil
	case "null":
		return nil, nil //nolint:nilnil // nil is the PDF null object, an absent dictionary entry

	}
	if strings.Trim(token, "+-.0123456789") != "" {
		return nil, fmt.Errorf("unexpected %q at %d", token, start)
	}
	if strings.Trim(token, "0123456789") == "" {
		num, err := strconv.ParseInt(token, 10, 64)
		after := p.pos
		if gen, genErr := p.integer(); err == nil && genErr == nil && p.keyword("R") {
			return pdfRef{num: num, gen: gen}, nil
		}
		p.pos = after
	}
	if _, err := strconv.ParseFloat(token, 64); err != nil {
		return nil, fmt.Errorf("bad number %q at %d", token, start)
	}
	return pdfNumber(token), nil
}

// dict reads the entries of a dictionary after its <<.
func (p *pdfParser) dict(depth int) (pdfDict, error) {
	d := pdfDict{}
	for {
		p.skipSpace()
		if bytes.HasPrefix(p.b[p.pos:], []byte(">>")) {
			p.pos += 2
			return d, nil
		}
		k, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		key, ok := k.(pdfName)
		if !ok {
			return nil, fmt.Errorf("dictionary key at %d is not a name", p.pos)
		}
		if d[key], err = p.value(depth + 1); err != nil {
			return nil, err
		}
	}
}

// literalString reads a string in parentheses.
func (p *pdfParser) literalString() (pdfString, error) {
	start := p.pos
	p.pos++
	s := pdfString{}
	nesting := 0
	for p.pos < len(p.b) {
		c := p.b[p.pos]
		p.pos++
		switch c {
		case '(':
			nesting++
		case ')':
			if nesting == 0 {
				return s, nil
			}
			nesting--
		case '\\':
			if p.pos >= len(p.b) {
				return nil, fmt.Errorf("string at %d is not closed", start)
			}
			c = p.b[p.pos]
			p.pos++
			switch c {
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case '\r', '\n': // the string continues on the next line
				if c == '\r' && p.pos < len(p.b) && p.b[p.pos] == '\n' {
					p.pos++
				}
				continue
			case '0', '1', '2', '3', '4', '5', '6', '7':
				n := int(c - '0')
				for i := 0; i < 2 && p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '7'; i++ {
					n = n*8 + int(p.b[p.pos]-'0')
					p.pos++
				}
				c = byte(n) //nolint:gosec // G115: three octal digits, the high bit dropped as ISO 32000 says
			}
		}
		s = append(s, c)
	}
	return nil, fmt.Errorf("string at %d is not closed", start)
}

// hexString reads a string in angle brackets.
func (p *pdfParser) hexString() (pdfString, error) {
	end := bytes.IndexByte(p.b[p.pos:], '>')
	if end < 0 {
		return nil, fmt.Errorf("hex string at %d is not closed", p.pos)
	}
	digits := make([]byte, 0, end)
	for _, c := range p.b[p.pos+1 : p.pos+end] {
		if !isPDFSpace(c) {
			digits = append(digits, c)
		}
	}
	if len(digits)%2 != 0 {
		digits = append(digits, '0')
	}
	s := make(pdfString, len(digits)/2)
	if _, err := hex.Decode(s, digits); err != nil {
		return nil, fmt.Errorf("hex string at %d: %w", p.pos, err)
	}
	p.pos += end + 1
	return s, nil
}

// writePDFValue writes v, an object parsePDF reads, in PDF syntax; strings
// become hex strings, and dictionary entries are sorted by key.
func writePDFValue(b *bytes.Buffer, v any) {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case pdfName:
		b.WriteString("/" + string(v))
	case pdfNumber:
		b.WriteString(string(v))
	case pdfString:
		b.WriteString("<" + strings.ToUpper(hex.EncodeToString(v)) + ">")
	case pdfRef:
		fmt.Fprintf(b, "%d %d R", v.num, v.gen)
	case pdfArray:
		b.WriteString("[")
		for i, e := range v {
			if i > 0 {
				b.WriteString(" ")
			}
			writePDFValue(b, e)
		}
		b.WriteString("]")
	case pdfDict:
		b.WriteString("<<")
		for _, k := range slices.Sorted(maps.Keys(v)) {
			b.WriteString("/" + string(k) + " ")
			writePDFValue(b, v[k])
			b.WriteString(" ")
		}
		b.WriteString(">>")
	}
}
