package pki

import (
	"bytes"
	"cmp"
	"compress/zlib"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/bits"
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
	maxPDFStream       = 1 << 24 // a decoded stream
	maxPDFObjects      = 8388607 // objects in a document, the limit of ISO 32000-1, Annex C
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
// VerifyPAdES reads PDFs with cross-reference tables, cross-reference streams
// or both (hybrid files), and objects in object streams; filters other than
// FlateDecode, and predictors other than PNG, are errors.ErrUnsupported. A signature that does not verify is
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
	e, ok := f.xref[ref.num]
	if e.stream != 0 {
		return sig, errors.New("the signature dictionary is in an object stream, outside the bytes a byte range names")
	}
	off := e.offset
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
	if err := f.checkByteRange(br, off, end, contents); err != nil {
		return sig, err
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

// checkByteRange validates all offsets before arithmetic or slicing.
func (f *pdfFile) checkByteRange(br [4]int64, off int64, end int, contents []byte) error {
	if br[0] != 0 || br[1] <= off || br[1] >= int64(len(f.data)) || br[2] > int64(end) ||
		br[2] <= br[1] || br[2]-br[1] < 2 || br[3] > int64(len(f.data))-br[2] ||
		f.data[br[1]] != '<' || f.data[br[2]-1] != '>' {
		return fmt.Errorf("/ByteRange %v does not leave out the /Contents of the signature", br)
	}
	gap := make([]byte, hex.DecodedLen(int(br[2]-br[1]-2)))
	if _, err := hex.Decode(gap, f.data[br[1]+1:br[2]-1]); err != nil || !bytes.Equal(gap, contents) {
		return fmt.Errorf("/ByteRange %v does not leave out the /Contents of the signature", br)
	}
	return nil
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
// AddPAdESValidationData and AddPAdESDocumentTimeStamp go on to B-LT and
// B-LTA.
//
// SignPAdES appends a cross-reference table, so the last revision of pdf
// must end with one: a cross-reference stream there is
// errors.ErrUnsupported, as is an encrypted document. It fails if key does
// not belong to cert or the signature does not fit in /Contents.
func SignPAdES(ctx context.Context, random io.Reader, pdf []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions, tsa *TSAClient) ([]byte, error) {
	u, err := newPDFUpdate(pdf)
	if err != nil {
		return nil, err
	}
	return u.appendSignature("Sig", "ETSI.CAdES.detached", func(signed []byte) ([]byte, error) {
		sd, err := signContent(random, oidData, signed, key, cert, SignOptions{Detached: true, GOST34311: opts.GOST34311}, false)
		if err != nil {
			return nil, err
		}
		der, err := sd.marshal()
		if err != nil || tsa == nil {
			return der, err
		}
		return AddSignatureTimeStamp(ctx, der, tsa)
	})
}

// AddPAdESDocumentTimeStamp appends to the PDF document pdf a document
// time-stamp from tsa as an incremental update, as IIT writes PAdES-B-LTA:
// a signature field as SignPAdES adds it and a dictionary with /Type
// /DocTimeStamp, /SubFilter /ETSI.RFC3161 and /M now, whose /Contents of
// 10240 bytes holds the time-stamp token of the byte range. Unlike IIT it
// also writes /Filter /Adobe.PPKLite, which ISO 32000-1, 12.8.1 requires.
// Added after AddPAdESValidationData, it makes B-LTA of B-LT. pdf must end
// with a cross-reference table, as for SignPAdES.
func AddPAdESDocumentTimeStamp(ctx context.Context, pdf []byte, tsa *TSAClient) ([]byte, error) {
	u, err := newPDFUpdate(pdf)
	if err != nil {
		return nil, err
	}
	return u.appendSignature("DocTimeStamp", "ETSI.RFC3161", func(signed []byte) ([]byte, error) {
		token, _, err := tsa.TimeStamp(ctx, signed)
		return token, err
	})
}

// AddPAdESValidationData turns the PAdES-B-T signatures of the PDF document
// pdf into B-LT as IIT writes them, with "full CA data": it appends an
// incremental update with a document security store (/DSS of the catalog,
// /Certs and /OCSPs, FlateDecode streams, no /VRI). For every signature of
// the document, verified first as VerifyPAdES does with certs, it builds the
// path from the signer certificate to a self-signed root and the path of the
// TSA certificate of its signature time-stamp (of a document time-stamp, the
// TSA path alone) out of certs and the certificates of the signature, and
// asks ocsp about every certificate of the paths but the roots. The DSS
// holds the certificates of the paths but the signers, then the OCSP
// responder certificates, each once, and the responses in the order asked.
//
// Every CAdES signature must have a signature time-stamp, added by passing
// a TSA to SignPAdES, every certificate asked about must be good, and the
// document must have no DSS yet. With ocsp.URL empty, each certificate is
// checked at the OCSP server it names. pdf must end with a cross-reference
// table, as for SignPAdES.
func AddPAdESValidationData(ctx context.Context, pdf []byte, certs []*x509.Certificate, ocsp *OCSPClient) ([]byte, error) {
	u, err := newPDFUpdate(pdf)
	if err != nil {
		return nil, err
	}
	if u.catalog["DSS"] != nil {
		return nil, errors.New("pki: the PDF document already has a DSS")
	}
	sigs, err := VerifyPAdES(pdf, certs)
	if err != nil {
		return nil, err
	}
	type certPath struct {
		certs  []*x509.Certificate
		signer bool // the first certificate is in the CMS and stays out of the DSS
	}
	var paths []certPath
	for i, sig := range sigs {
		if sig.Signer.Certificate != nil {
			path, err := certificatePath(sig.Signer.Certificate, certs)
			if err != nil {
				return nil, fmt.Errorf("pki: PDF signature %d: %w", i, err)
			}
			paths = append(paths, certPath{path, true})
		}
		if sig.Signer.TimeStamp == nil {
			return nil, fmt.Errorf("pki: PDF signature %d has no signature time-stamp: pass a TSA to SignPAdES", i)
		}
		path, err := certificatePath(sig.Signer.TimeStamp.Certificate, certs)
		if err != nil {
			return nil, fmt.Errorf("pki: PDF signature %d time-stamp: %w", i, err)
		}
		paths = append(paths, certPath{path, false})
	}

	var stored, responders []*x509.Certificate
	var responses [][]byte
	add := func(list []*x509.Certificate, c *x509.Certificate) []*x509.Certificate {
		if slices.ContainsFunc(stored, c.Equal) || slices.ContainsFunc(list, c.Equal) {
			return list
		}
		return append(list, c)
	}
	for _, path := range paths {
		for j, c := range path.certs {
			if j > 0 || !path.signer {
				stored = add(stored, c)
			}
		}
		for j, c := range path.certs[:len(path.certs)-1] {
			resp, err := ocsp.Check(ctx, c, path.certs[j+1])
			if err != nil {
				return nil, err
			}
			if err := goodStatus(resp, c); err != nil {
				return nil, err
			}
			responses = append(responses, resp.Raw)
			responders = add(responders, resp.Certificate)
		}
	}
	stored = append(stored, responders...)

	refs := func(data [][]byte) (pdfArray, error) {
		var a pdfArray
		for _, d := range data {
			var z bytes.Buffer
			w := zlib.NewWriter(&z)
			if _, err := w.Write(d); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			ref := u.newRef()
			u.objects[ref] = pdfStream{dict: pdfDict{"Filter": pdfName("FlateDecode")}, raw: z.Bytes()}
			a = append(a, ref)
		}
		return a, nil
	}
	raw := make([][]byte, len(stored))
	for i, c := range stored {
		raw[i] = c.Raw
	}
	dssRef := u.newRef()
	certRefs, err := refs(raw)
	if err != nil {
		return nil, fmt.Errorf("pki: PDF DSS: %w", err)
	}
	ocspRefs, err := refs(responses)
	if err != nil {
		return nil, fmt.Errorf("pki: PDF DSS: %w", err)
	}
	u.objects[dssRef] = pdfDict{"Type": pdfName("DSS"), "Certs": certRefs, "OCSPs": ocspRefs}
	u.catalog["DSS"] = dssRef
	return u.write(pdfRef{}, nil), nil
}

// A pdfUpdate is an incremental update of a PDF document being built: the
// objects it adds or replaces, the catalog among them.
type pdfUpdate struct {
	pdf     []byte
	f       *pdfFile
	rootRef pdfRef
	catalog pdfDict // a copy, written with the update
	next    int64   // the next free object number
	objects map[pdfRef]any
}

func newPDFUpdate(pdf []byte) (*pdfUpdate, error) {
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
	return &pdfUpdate{pdf: pdf, f: f, rootRef: rootRef, catalog: maps.Clone(catalog), next: size, objects: map[pdfRef]any{}}, nil
}

func (u *pdfUpdate) newRef() pdfRef {
	u.next++
	return pdfRef{num: u.next - 1}
}

// write returns the document with the update appended: the objects and the
// catalog, then the object raw writes as rawRef when raw is not nil, a
// cross-reference table and a trailer that names the previous one.
func (u *pdfUpdate) write(rawRef pdfRef, raw func(b *bytes.Buffer)) []byte {
	u.objects[u.rootRef] = u.catalog
	var b bytes.Buffer
	b.Write(u.pdf)
	if !bytes.HasSuffix(u.pdf, []byte("\n")) && !bytes.HasSuffix(u.pdf, []byte("\r")) {
		b.WriteByte('\n')
	}
	offsets := map[pdfRef]int{}
	for _, ref := range slices.SortedFunc(maps.Keys(u.objects), func(a, b pdfRef) int { return cmp.Compare(a.num, b.num) }) {
		offsets[ref] = b.Len()
		fmt.Fprintf(&b, "%d %d obj\n", ref.num, ref.gen)
		if s, ok := u.objects[ref].(pdfStream); ok {
			d := maps.Clone(s.dict)
			d["Length"] = pdfNumber(strconv.Itoa(len(s.raw)))
			writePDFValue(&b, d)
			b.WriteString("\nstream\n")
			b.Write(s.raw)
			b.WriteString("\nendstream")
		} else {
			writePDFValue(&b, u.objects[ref])
		}
		b.WriteString("\nendobj\n")
	}
	if raw != nil {
		offsets[rawRef] = b.Len()
		raw(&b)
	}

	// The update's cross-reference section takes the form of the document's
	// last one: a stream after a stream, a table after a table.
	xrefAt := b.Len()
	var xrefRef pdfRef
	if u.f.xrefStream {
		xrefRef = u.newRef()
		offsets[xrefRef] = xrefAt
	}
	trailer := pdfDict{"Size": pdfNumber(strconv.FormatInt(u.next, 10)), "Root": u.rootRef, "Prev": pdfNumber(strconv.FormatInt(u.f.startxref, 10))}
	for _, k := range []pdfName{"Info", "ID"} {
		if v, ok := u.f.trailer[k]; ok {
			trailer[k] = v
		}
	}
	// subsections of consecutive object numbers
	refs := slices.SortedFunc(maps.Keys(offsets), func(a, b pdfRef) int { return cmp.Compare(a.num, b.num) })
	var runs [][]pdfRef
	for i := 0; i < len(refs); {
		j := i + 1
		for j < len(refs) && refs[j].num == refs[j-1].num+1 {
			j++
		}
		runs = append(runs, refs[i:j])
		i = j
	}

	if !u.f.xrefStream {
		b.WriteString("xref\n")
		for _, run := range runs {
			fmt.Fprintf(&b, "%d %d\n", run[0].num, len(run))
			for _, ref := range run {
				fmt.Fprintf(&b, "%010d %05d n\r\n", offsets[ref], ref.gen)
			}
		}
		b.WriteString("trailer\n")
		writePDFValue(&b, trailer)
		fmt.Fprintf(&b, "\nstartxref\n%d\n%%%%EOF\n", xrefAt)
		return b.Bytes()
	}

	// ISO 32000-1, 7.5.8: type 1 entries of a type byte, the offset in as
	// few bytes as the largest one (the stream's own) needs, a 2-byte
	// generation; uncompressed, as the stream may not be encrypted anyway
	ow := max(1, (bits.Len64(uint64(xrefAt))+7)/8) //nolint:gosec // G115: a buffer length is not negative
	var index pdfArray
	var rows []byte
	for _, run := range runs {
		index = append(index, pdfNumber(strconv.FormatInt(run[0].num, 10)), pdfNumber(strconv.Itoa(len(run))))
		for _, ref := range run {
			rows = append(rows, 1)
			rows = binary.BigEndian.AppendUint64(rows, uint64(offsets[ref])) //nolint:gosec // G115: an offset in the buffer is not negative
			rows = slices.Delete(rows, len(rows)-8, len(rows)-ow)
			rows = binary.BigEndian.AppendUint16(rows, uint16(ref.gen)) //nolint:gosec // G115: generations are 0 to 65535 (ISO 32000-1, 7.3.10)
		}
	}
	trailer["Type"] = pdfName("XRef")
	trailer["W"] = pdfArray{pdfNumber("1"), pdfNumber(strconv.Itoa(ow)), pdfNumber("2")}
	trailer["Index"] = index
	trailer["Length"] = pdfNumber(strconv.Itoa(len(rows)))
	fmt.Fprintf(&b, "%d 0 obj\n", xrefRef.num)
	writePDFValue(&b, trailer)
	b.WriteString("\nstream\n")
	b.Write(rows)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrefAt)
	return b.Bytes()
}

// appendSignature adds a signature field to the interactive form whose value
// is a signature dictionary of type typ ("Sig" or "DocTimeStamp") with
// subFilter, and returns the document with the update and /Contents filled
// with what sign returns for the bytes of the byte range.
func (u *pdfUpdate) appendSignature(typ, subFilter string, sign func(signed []byte) ([]byte, error)) ([]byte, error) {
	fieldRef, sigRef := u.newRef(), u.newRef()
	now := pdfDate(time.Now())
	field := pdfDict{
		"Type": pdfName("Annot"), "Subtype": pdfName("Widget"), "FT": pdfName("Sig"),
		"F": pdfNumber("132"), "Rect": pdfArray{pdfNumber("0"), pdfNumber("0"), pdfNumber("0"), pdfNumber("0")},
		"T": pdfString("Signature" + strconv.FormatInt(fieldRef.num, 10)), "M": now, "V": sigRef,
	}
	if page, ok := u.f.firstPage(u.catalog); ok {
		field["P"] = page
	}
	u.objects[fieldRef] = field

	// the form: a new one, or the catalog's with the field added
	addField := func(form pdfDict) (pdfDict, error) {
		fields, err := u.f.array(form["Fields"])
		if err != nil {
			return nil, fmt.Errorf("pki: PDF /Fields: %w", err)
		}
		form = maps.Clone(form)
		form["Fields"] = append(slices.Clone(fields), fieldRef)
		form["SigFlags"] = pdfNumber("3")
		return form, nil
	}
	var err error
	switch form := u.catalog["AcroForm"].(type) {
	case nil:
		formRef := u.newRef()
		u.objects[formRef] = pdfDict{"Fields": pdfArray{fieldRef}, "SigFlags": pdfNumber("3")}
		u.catalog["AcroForm"] = formRef
	case pdfRef:
		d, err := u.f.dict(form)
		if err != nil {
			return nil, fmt.Errorf("pki: PDF /AcroForm: %w", err)
		}
		if u.objects[form], err = addField(d); err != nil {
			return nil, err
		}
	case pdfDict:
		if u.catalog["AcroForm"], err = addField(form); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("pki: PDF /AcroForm is not a dictionary")
	}

	var byteRangeAt, contentsAt, contentsEnd int
	out := u.write(sigRef, func(b *bytes.Buffer) {
		fmt.Fprintf(b, "%d 0 obj\n<</Type /%s /Filter /Adobe.PPKLite /SubFilter /%s /M ", sigRef.num, typ, subFilter)
		writePDFValue(b, now)
		b.WriteString(" /ByteRange ")
		byteRangeAt = b.Len()
		b.WriteString(strings.Repeat(" ", 64)) // room for [0 a b c]
		b.WriteString(" /Contents ")
		contentsAt = b.Len()
		b.WriteString("<" + strings.Repeat("0", 2*padesContentsSize) + ">")
		contentsEnd = b.Len()
		b.WriteString(">>\nendobj\n")
	})
	copy(out[byteRangeAt:], fmt.Sprintf("[0 %d %d %d]", contentsAt, contentsEnd, len(out)-contentsEnd))
	der, err := sign(slices.Concat(out[:contentsAt], out[contentsEnd:]))
	if err != nil {
		return nil, err
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
	filter, parms := s.dict["Filter"], s.dict["DecodeParms"]
	if a, ok := filter.(pdfArray); ok && len(a) == 1 {
		filter = a[0]
	}
	if a, ok := parms.(pdfArray); ok && len(a) == 1 {
		parms = a[0]
	}
	switch filter {
	case nil:
		return s.raw, nil
	case pdfName("FlateDecode"):
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
		return unpredict(data, parms)
	default:
		return nil, fmt.Errorf("stream /Filter %v: %w", filter, errors.ErrUnsupported)
	}
}

// unpredict undoes the predictor that the FlateDecode parameters parms name
// (ISO 32000-1, 7.4.4.4): none, or the PNG filters (PNG 1.2, 6), a filter
// type byte before each row. The TIFF predictor is errors.ErrUnsupported.
func unpredict(data []byte, parms any) ([]byte, error) {
	if parms == nil {
		return data, nil
	}
	d, ok := parms.(pdfDict)
	if !ok {
		return nil, fmt.Errorf("stream /DecodeParms: %w", errors.ErrUnsupported)
	}
	param := func(k pdfName, def int64) int64 {
		v, ok := d[k]
		if !ok {
			return def
		}
		n, err := strconv.ParseInt(string(asNumber(v)), 10, 64)
		if err != nil || n < 0 || n > maxPDFStream {
			return -1
		}
		return n
	}
	predictor, colors, bpc, columns := param("Predictor", 1), param("Colors", 1), param("BitsPerComponent", 8), param("Columns", 1)
	switch {
	case predictor == 1:
		return data, nil
	case predictor < 10 || predictor > 15:
		return nil, fmt.Errorf("stream /Predictor %d: %w", predictor, errors.ErrUnsupported)
	case colors < 1 || colors > 32 || !slices.Contains([]int64{1, 2, 4, 8, 16}, bpc) || columns < 1:
		return nil, errors.New("stream /DecodeParms out of range")
	}
	bpp := int(max(1, colors*bpc/8))
	rowLen := int((colors*bpc*columns + 7) / 8)
	if len(data)%(rowLen+1) != 0 {
		return nil, fmt.Errorf("stream of %d bytes is not rows of %d", len(data), rowLen+1)
	}
	out := make([]byte, 0, len(data)/(rowLen+1)*rowLen)
	prev := make([]byte, rowLen)
	for row := range slices.Chunk(data, rowLen+1) {
		out = append(out, row[1:]...)
		line := out[len(out)-rowLen:]
		for i := range line {
			var a, c byte // left and upper left, zero in the first pixel
			if i >= bpp {
				a, c = line[i-bpp], prev[i-bpp]
			}
			b := prev[i]
			switch row[0] {
			case 0:
			case 1:
				line[i] += a
			case 2:
				line[i] += b
			case 3:
				line[i] += a>>1 + b>>1 + a&b&1 // ⌊(a+b)/2⌋ without overflow
			case 4:
				line[i] += paeth(a, b, c)
			default:
				return nil, fmt.Errorf("stream row of PNG filter type %d", row[0])
			}
		}
		prev = line
	}
	return out, nil
}

// paeth is the Paeth predictor of PNG 1.2, 6.6: of the left, upper and upper
// left bytes, the one nearest to left + upper - upper left.
func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	default:
		return c
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// pdfFile is a PDF document with its cross-reference sections read.
type pdfFile struct {
	data       []byte
	xref       map[int64]pdfXref // object number → entry of the newest revision
	trailer    pdfDict           // of the newest revision; the dictionary of a cross-reference stream
	startxref  int64
	xrefStream bool                 // the newest section is a cross-reference stream
	objStms    map[int64]*pdfObjStm // object streams decoded so far
	decoding   map[int64]bool       // object streams being decoded, against a /Length cycle
}

// A pdfXref is a cross-reference entry (ISO 32000-1, 7.5.4 and 7.5.8.3):
// the object is at offset in the file or, when stream is not 0, the
// index-th object of object stream stream. It is free when offset is -1.
type pdfXref struct{ offset, stream, index int64 }

// A pdfObjStm is a decoded object stream (ISO 32000-1, 7.5.7): the objects
// from /First on and, from the header, their numbers and offsets there.
type pdfObjStm struct {
	data    []byte
	nums    []int64
	offsets []int64
}

// parsePDF reads the cross-reference sections of data, from the last
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
	f := &pdfFile{data: data, xref: map[int64]pdfXref{}, startxref: off, objStms: map[int64]*pdfObjStm{}, decoding: map[int64]bool{}}
	seen := map[int64]bool{}
	for range maxPDFXrefSections {
		if seen[off] || off >= int64(len(data)) {
			return nil, fmt.Errorf("pki: PDF cross-reference table at %d", off)
		}
		seen[off] = true
		entries, trailer, stream, err := f.xrefSection(off)
		if err != nil {
			return nil, err
		}
		if f.trailer == nil {
			f.trailer, f.xrefStream = trailer, stream
		}
		for num, e := range entries {
			if _, newer := f.xref[num]; !newer {
				f.xref[num] = e
			}
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

// xrefSection reads the cross-reference section at off, a table or a stream
// (reported by stream), and returns its entries and its trailer. A table
// with /XRefStm is a hybrid one (ISO 32000-1, 7.5.8.4): the entries of that
// stream fill those the table lacks; a free one stays free, as poppler and
// pdf.js read it.
func (f *pdfFile) xrefSection(off int64) (entries map[int64]pdfXref, trailer pdfDict, stream bool, err error) {
	p := &pdfParser{b: f.data, pos: int(off)}
	if !p.keyword("xref") {
		entries, trailer, err := f.xrefStreamAt(off)
		return entries, trailer, true, err
	}
	entries = map[int64]pdfXref{}
	for !p.keyword("trailer") {
		start, err := p.integer()
		if err != nil {
			return nil, nil, false, fmt.Errorf("pki: PDF cross-reference table: %w", err)
		}
		count, err := p.integer()
		if err != nil || start > 1<<32 || count > 1<<32 {
			return nil, nil, false, fmt.Errorf("pki: PDF cross-reference subsection at %d", p.pos)
		}
		for num := start; num < start+count; num++ {
			offset, err := p.integer()
			if err != nil {
				return nil, nil, false, fmt.Errorf("pki: PDF cross-reference entry: %w", err)
			}
			if _, err := p.integer(); err != nil {
				return nil, nil, false, fmt.Errorf("pki: PDF cross-reference entry: %w", err)
			}
			p.skipSpace()
			kind := p.regular()
			if kind != "n" && kind != "f" {
				return nil, nil, false, fmt.Errorf("pki: PDF cross-reference entry of type %q", kind)
			}
			if _, dup := entries[num]; dup {
				continue
			}
			if kind == "f" {
				offset = -1
			}
			entries[num] = pdfXref{offset: offset}
		}
	}
	v, err := p.value(0)
	if err != nil {
		return nil, nil, false, fmt.Errorf("pki: PDF trailer: %w", err)
	}
	trailer, ok := v.(pdfDict)
	if !ok {
		return nil, nil, false, errors.New("pki: PDF trailer is not a dictionary")
	}
	if v, ok := trailer["XRefStm"]; ok {
		at, err := strconv.ParseInt(string(asNumber(v)), 10, 64)
		if err != nil || at < 0 || at >= int64(len(f.data)) {
			return nil, nil, false, errors.New("pki: PDF trailer /XRefStm is not an offset")
		}
		hidden, _, err := f.xrefStreamAt(at)
		if err != nil {
			return nil, nil, false, err
		}
		for num, e := range hidden {
			if _, ok := entries[num]; !ok {
				entries[num] = e
			}
		}
	}
	return entries, trailer, false, nil
}

// xrefStreamAt reads the cross-reference stream at off (ISO 32000-1, 7.5.8)
// and returns its entries and its dictionary, which is the trailer.
func (f *pdfFile) xrefStreamAt(off int64) (map[int64]pdfXref, pdfDict, error) {
	p := &pdfParser{b: f.data, pos: int(off)}
	num, err := p.integer()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: PDF has no cross-reference table or stream at %d", off)
	}
	v, _, err := f.objectAt(off, num, false)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: PDF cross-reference stream: %w", err)
	}
	s, ok := v.(pdfStream)
	if !ok || s.dict["Type"] != pdfName("XRef") {
		return nil, nil, fmt.Errorf("pki: PDF has no cross-reference table or stream at %d", off)
	}
	data, err := s.decode()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: PDF cross-reference %w", err)
	}
	integer := func(v any, limit int64) (int64, error) {
		n, err := strconv.ParseInt(string(asNumber(v)), 10, 64)
		if err != nil || n < 0 || n > limit {
			return 0, fmt.Errorf("pki: PDF cross-reference stream: %v is not an integer from 0 to %d", v, limit)
		}
		return n, nil
	}
	size, err := integer(s.dict["Size"], maxPDFObjects+1)
	if err != nil {
		return nil, nil, err
	}
	wa, ok := s.dict["W"].(pdfArray)
	if !ok || len(wa) != 3 {
		return nil, nil, errors.New("pki: PDF cross-reference stream without /W of three widths")
	}
	var w [3]int
	for i, v := range wa {
		n, err := integer(v, 8)
		if err != nil {
			return nil, nil, err
		}
		w[i] = int(n)
	}
	width := w[0] + w[1] + w[2]
	if width == 0 {
		return nil, nil, errors.New("pki: PDF cross-reference stream with /W [0 0 0]")
	}
	index := pdfArray{pdfNumber("0"), pdfNumber(strconv.FormatInt(size, 10))}
	if v, ok := s.dict["Index"]; ok {
		if index, ok = v.(pdfArray); !ok || len(index)%2 != 0 {
			return nil, nil, errors.New("pki: PDF cross-reference stream /Index is not pairs")
		}
	}
	field := func(b []byte) int64 {
		var n uint64
		for _, c := range b {
			n = n<<8 | uint64(c)
		}
		return int64(n) // a value past int64 turns negative and is rejected
	}
	entries := map[int64]pdfXref{}
	for pair := range slices.Chunk(index, 2) {
		start, err := integer(pair[0], size)
		if err != nil {
			return nil, nil, err
		}
		count, err := integer(pair[1], size-start)
		if err != nil {
			return nil, nil, err
		}
		for num := start; num < start+count; num++ {
			if len(data) < width {
				return nil, nil, errors.New("pki: PDF cross-reference stream ends before its entries")
			}
			typ := int64(1)
			if w[0] > 0 {
				typ = field(data[:w[0]])
			}
			a, b := field(data[w[0]:w[0]+w[1]]), field(data[w[0]+w[1]:width])
			data = data[width:]
			if _, dup := entries[num]; dup {
				continue
			}
			e, ok, err := xrefStreamEntry(num, typ, a, b)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				entries[num] = e
			}
		}
	}
	return entries, s.dict, nil
}

// xrefStreamEntry makes the entry of object num from the fields of a
// cross-reference stream row (ISO 32000-1, 7.5.8.3, Table 18); it reports
// false for the types other than 0, 1 and 2, references to the null object.
func xrefStreamEntry(num, typ, a, b int64) (pdfXref, bool, error) {
	switch typ {
	case 0:
		return pdfXref{offset: -1}, true, nil
	case 1:
		if a < 0 {
			return pdfXref{}, false, fmt.Errorf("pki: PDF cross-reference stream: object %d at %d", num, a)
		}
		return pdfXref{offset: a}, true, nil
	case 2:
		if a <= 0 || b < 0 {
			return pdfXref{}, false, fmt.Errorf("pki: PDF cross-reference stream: object %d in object stream %d", num, a)
		}
		return pdfXref{stream: a, index: b}, true, nil
	default:
		return pdfXref{}, false, nil
	}
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
			if e, ok := f.xref[ref.num]; ok {
				switch {
				case e.stream != 0:
					length, err = f.compressed(ref.num, e)
				case e.offset >= 0:
					length, _, err = f.objectAt(e.offset, ref.num, true)
				}
				if err != nil {
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
		e, ok := f.xref[ref.num]
		var err error
		switch {
		case e.stream != 0:
			v, err = f.compressed(ref.num, e)
		case !ok || e.offset < 0:
			return nil, fmt.Errorf("object %d %d R is in no cross-reference section", ref.num, ref.gen)
		default:
			v, _, err = f.objectAt(e.offset, ref.num, false)
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("references nested too deep")
}

// compressed returns object num, which entry e places in an object stream.
func (f *pdfFile) compressed(num int64, e pdfXref) (any, error) {
	s, err := f.objStm(e.stream)
	if err != nil {
		return nil, err
	}
	if e.index >= int64(len(s.nums)) || s.nums[e.index] != num {
		return nil, fmt.Errorf("object %d is not object %d of object stream %d", num, e.index, e.stream)
	}
	p := &pdfParser{b: s.data, pos: int(s.offsets[e.index])}
	v, err := p.value(0)
	if err != nil {
		return nil, fmt.Errorf("object %d: %w", num, err)
	}
	return v, nil
}

// objStm returns object stream num, decoded once. An object stream is never
// in another one (ISO 32000-1, 7.5.7); its /Length may be, which decoding
// bounds.
func (f *pdfFile) objStm(num int64) (*pdfObjStm, error) {
	if s, ok := f.objStms[num]; ok {
		return s, nil
	}
	e, ok := f.xref[num]
	if !ok || e.stream != 0 || e.offset < 0 {
		return nil, fmt.Errorf("object stream %d is not in the file", num)
	}
	if f.decoding[num] || len(f.decoding) >= maxPDFRefChain {
		return nil, fmt.Errorf("object stream %d: /Length in a cycle of object streams", num)
	}
	f.decoding[num] = true
	defer delete(f.decoding, num)
	v, _, err := f.objectAt(e.offset, num, false)
	if err != nil {
		return nil, err
	}
	st, ok := v.(pdfStream)
	if !ok || st.dict["Type"] != pdfName("ObjStm") {
		return nil, fmt.Errorf("object %d is not an object stream", num)
	}
	data, err := st.decode()
	if err != nil {
		return nil, fmt.Errorf("object stream %d: %w", num, err)
	}
	n, err := strconv.ParseInt(string(asNumber(st.dict["N"])), 10, 64)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("object stream %d: /N", num)
	}
	first, err := strconv.ParseInt(string(asNumber(st.dict["First"])), 10, 64)
	if err != nil || first < 0 || first > int64(len(data)) {
		return nil, fmt.Errorf("object stream %d: /First", num)
	}
	s := &pdfObjStm{data: data[first:]}
	p := &pdfParser{b: data[:first]}
	for range n {
		objNum, err := p.integer()
		if err != nil {
			return nil, fmt.Errorf("object stream %d header: %w", num, err)
		}
		off, err := p.integer()
		if err != nil || off >= int64(len(s.data)) {
			return nil, fmt.Errorf("object stream %d header: offset of object %d", num, objNum)
		}
		s.nums, s.offsets = append(s.nums, objNum), append(s.offsets, off)
	}
	f.objStms[num] = s
	return s, nil
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
