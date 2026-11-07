package pki

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"net/url"
	"slices"
	"strings"

	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kupyna"
)

// Associated Signature Containers (ETSI EN 319 162-1) with CAdES or XAdES
// signatures, as IIT writes them.
const (
	asicSType       = "application/vnd.etsi.asic-s+zip"
	asicEType       = "application/vnd.etsi.asic-e+zip"
	asicSSignature  = "META-INF/signature.p7s"
	asicESignature  = "META-INF/signature001.p7s"
	asicEManifest   = "META-INF/ASiCManifest001.xml"
	asicSXAdES      = "META-INF/signatures.xml"
	asicEXAdES      = "META-INF/signatures001.xml"
	asicEODF        = "META-INF/manifest.xml"
	asicNamespace   = "http://uri.etsi.org/02918/v1.2.1#"
	xmldsNamespace  = "http://www.w3.org/2000/09/xmldsig#"
	digestGOST34311 = "http://www.w3.org/2001/04/xmlenc#gost34311"
	digestKupyna256 = "http://www.w3.org/2001/04/xmlenc#dstu7564-256"
)

// maxASiCSize bounds the total uncompressed size of the entries VerifyASiC
// reads, so that a small container cannot expand without limit.
const maxASiCSize = 1 << 30

// An ASiCFile is a data object of an ASiC container: a file name inside the
// container, with "/" between directories, and its content.
type ASiCFile struct {
	Name string
	Data []byte
}

// CreateASiCS returns an ASiC-S container (application/vnd.etsi.asic-s+zip)
// holding file and META-INF/signature.p7s, the detached CAdES signature that
// sign returns for the file's data: for example SignData with
// SignOptions.Detached, extended by AddSignatureTimeStamp and
// AddValidationData.
func CreateASiCS(file ASiCFile, sign func(data []byte) ([]byte, error)) ([]byte, error) {
	if err := checkASiCName(file.Name); err != nil {
		return nil, err
	}
	signature, err := sign(file.Data)
	if err != nil {
		return nil, fmt.Errorf("pki: sign %s: %w", file.Name, err)
	}
	return writeASiC(asicSType, []ASiCFile{file, {Name: asicSSignature, Data: signature}})
}

// CreateASiCE returns an ASiC-E container (application/vnd.etsi.asic-e+zip)
// holding files, META-INF/ASiCManifest001.xml with their Kupyna-256 digests,
// or GOST 34.311 digests when gost34311Digest is set, and
// META-INF/signature001.p7s, the detached CAdES signature that sign returns
// for the manifest. The manifest is written as IIT writes it.
func CreateASiCE(files []ASiCFile, gost34311Digest bool, sign func(manifest []byte) ([]byte, error)) ([]byte, error) {
	if err := checkASiCFiles(files); err != nil {
		return nil, err
	}

	algorithm := digestKupyna256
	if gost34311Digest {
		algorithm = digestGOST34311
	}
	var m strings.Builder
	m.WriteString(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`)
	m.WriteString(`<asic:ASiCManifest xmlns:asic="` + asicNamespace + `" xmlns:ds="` + xmldsNamespace +
		`" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`)
	m.WriteString(`<asic:SigReference MimeType="application/x-pkcs7-signature" URI="` + asicESignature + `"/>`)
	for _, f := range files {
		digest, _ := asicDigest(algorithm, f.Data) // never fails: the algorithm is one of the two above
		m.WriteString(`<asic:DataObjectReference MimeType="application/octet-stream" URI="`)
		_ = xml.EscapeText(&m, []byte(f.Name)) // never fails: strings.Builder does not
		m.WriteString(`"><ds:DigestMethod Algorithm="` + algorithm + `"/><ds:DigestValue>`)
		m.WriteString(base64.StdEncoding.EncodeToString(digest))
		m.WriteString(`</ds:DigestValue></asic:DataObjectReference>`)
	}
	m.WriteString(`</asic:ASiCManifest>`)
	manifest := []byte(m.String())

	signature, err := sign(manifest)
	if err != nil {
		return nil, fmt.Errorf("pki: sign the ASiC manifest: %w", err)
	}
	entries := append(append([]ASiCFile(nil), files...),
		ASiCFile{Name: asicEManifest, Data: manifest}, ASiCFile{Name: asicESignature, Data: signature})
	return writeASiC(asicEType, entries)
}

// CreateASiCSXAdES returns an ASiC-S container holding file and
// META-INF/signatures.xml, the detached XAdES signature that sign returns
// for the file: for example SignXAdESDetached, extended by
// AddXAdESSignatureTimeStamp and AddXAdESValidationData. The signature goes
// into an asic:XAdESSignatures element as IIT writes it.
func CreateASiCSXAdES(file ASiCFile, sign func(files []ASiCFile) ([]byte, error)) ([]byte, error) {
	if err := checkASiCName(file.Name); err != nil {
		return nil, err
	}
	signatures, err := asicXAdES([]ASiCFile{file}, sign)
	if err != nil {
		return nil, err
	}
	return writeASiC(asicSType, []ASiCFile{file, {Name: asicSXAdES, Data: signatures}})
}

// CreateASiCEXAdES returns an ASiC-E container holding files, the
// OpenDocument manifest META-INF/manifest.xml that lists them and
// META-INF/signatures001.xml, the detached XAdES signature that sign returns
// for files, written as CreateASiCSXAdES writes it. The manifest is written
// as IIT writes it, with the MIME types SignXAdESDetached gives the files.
func CreateASiCEXAdES(files []ASiCFile, sign func(files []ASiCFile) ([]byte, error)) ([]byte, error) {
	if err := checkASiCFiles(files); err != nil {
		return nil, err
	}
	var m strings.Builder
	m.WriteString(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`)
	m.WriteString(`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">`)
	m.WriteString(`<manifest:file-entry manifest:full-path="/" manifest:media-type="` + asicEType + `"/>`)
	for _, f := range files {
		m.WriteString(`<manifest:file-entry manifest:full-path="`)
		_ = xml.EscapeText(&m, []byte(f.Name)) // never fails: strings.Builder does not
		m.WriteString(`" manifest:media-type="` + xadesMimeType(f.Name) + `"/>`)
	}
	m.WriteString(`</manifest:manifest>`)

	signatures, err := asicXAdES(files, sign)
	if err != nil {
		return nil, err
	}
	entries := append(slices.Clone(files), ASiCFile{Name: asicEODF, Data: []byte(m.String())}, ASiCFile{Name: asicEXAdES, Data: signatures})
	return writeASiC(asicEType, entries)
}

// asicXAdES returns the asic:XAdESSignatures document of the detached
// signature that sign returns for files. As IIT does, it writes the
// namespace declarations of ds:Signature and xades:QualifyingProperties
// after their other attributes; the order of attributes is not signed.
func asicXAdES(files []ASiCFile, sign func(files []ASiCFile) ([]byte, error)) ([]byte, error) {
	sig, err := sign(files)
	if err != nil {
		return nil, fmt.Errorf("pki: sign the ASiC files: %w", err)
	}
	root, _, err := parseXML(sig)
	if err != nil {
		return nil, err
	}
	if !root.is(xmldsNamespace, "Signature") || !bytes.HasPrefix(sig[root.end:], []byte("</")) {
		return nil, errors.New("pki: the XAdES signature for ASiC is not a ds:Signature document")
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`)
	b.WriteString(`<asic:XAdESSignatures xmlns:asic="` + asicNamespace + `" xmlns:ds="` + xmldsNamespace + `" xmlns:xades="` + nsXAdES +
		`" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`)
	pos := root.start
	for _, e := range []*xmlElement{root, root.child(xmldsNamespace, "Object").child(nsXAdES, "QualifyingProperties")} {
		if e == nil {
			continue
		}
		b.Write(sig[pos:e.start])
		writeDeclarationsLast(&b, e, sig[e.start:e.inner])
		pos = e.inner
	}
	end := root.end + bytes.IndexByte(sig[root.end:], '>') + 1 // past </ds:Signature>
	b.Write(sig[pos:end])
	b.WriteString(`</asic:XAdESSignatures>`)
	return b.Bytes(), nil
}

// writeDeclarationsLast writes the start tag of e, which is tag, with the
// namespace declarations after the other attributes.
func writeDeclarationsLast(b *bytes.Buffer, e *xmlElement, tag []byte) {
	isDecl := func(a xml.Attr) bool { return a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" }
	b.WriteByte('<')
	writeQName(b, e.prefix, e.local)
	for _, decls := range []bool{false, true} {
		for _, a := range e.attrs {
			if isDecl(a) != decls {
				continue
			}
			b.WriteByte(' ')
			writeQName(b, a.Name.Space, a.Name.Local)
			b.WriteString(`="`)
			escapeCanonical(b, a.Value, true)
			b.WriteByte('"')
		}
	}
	if bytes.HasSuffix(tag, []byte("/>")) {
		b.WriteByte('/')
	}
	b.WriteByte('>')
}

// checkASiCFiles checks the files of an ASiC-E container: at least one, each
// with a valid name, no name twice.
func checkASiCFiles(files []ASiCFile) error {
	if len(files) == 0 {
		return errors.New("pki: ASiC-E needs at least one file")
	}
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if err := checkASiCName(f.Name); err != nil {
			return err
		}
		if seen[f.Name] {
			return fmt.Errorf("pki: ASiC file %q appears twice", f.Name)
		}
		seen[f.Name] = true
	}
	return nil
}

// checkASiCName rejects names that are not a relative path to a file, and
// the names an ASiC container reserves.
func checkASiCName(name string) error {
	if !fs.ValidPath(name) || name == "." || name == "mimetype" || strings.HasPrefix(name, "META-INF/") {
		return fmt.Errorf("pki: %q is not a valid ASiC file name", name)
	}
	return nil
}

// writeASiC writes the mimetype entry first, stored and without an extra
// field, as ETSI EN 319 162-1 requires, then entries, deflated.
func writeASiC(mediaType string, entries []ASiCFile) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               "mimetype",
		Method:             zip.Store,
		CRC32:              crc32.ChecksumIEEE([]byte(mediaType)),
		CompressedSize64:   uint64(len(mediaType)),
		UncompressedSize64: uint64(len(mediaType)),
	})
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, mediaType); err != nil {
		return nil, err
	}
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.Name, Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// VerifyASiC verifies the signatures of an ASiC-S or ASiC-E container, with
// certs for the certificates the signatures leave out, and returns the signed
// files in container order and the signers. CAdES signatures are verified as
// VerifySignedData does: in ASiC-E every one signs a manifest, and the files
// are those the manifests list with matching digests. XAdES signatures
// (META-INF/signatures*.xml) are verified as VerifyXAdES does and sign the
// files themselves. A file no signature covers is not returned; a changed
// file is ErrInvalidSignature. A container with both kinds of signatures is
// errors.ErrUnsupported.
func VerifyASiC(container []byte, certs []*x509.Certificate) ([]ASiCFile, []Signer, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, nil, fmt.Errorf("pki: ASiC: %w", err)
	}
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
	}
	if total > maxASiCSize {
		return nil, nil, fmt.Errorf("pki: ASiC entries are %d bytes uncompressed, more than %d", total, maxASiCSize)
	}

	entries := make(map[string][]byte, len(zr.File))
	var data []ASiCFile // the data objects, in container order
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue // a directory
		}
		if _, dup := entries[f.Name]; dup {
			return nil, nil, fmt.Errorf("pki: ASiC entry %q appears twice", f.Name)
		}
		b, err := readZipEntry(f)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: ASiC entry %q: %w", f.Name, err)
		}
		entries[f.Name] = b
		if f.Name != "mimetype" && !strings.HasPrefix(f.Name, "META-INF/") {
			data = append(data, ASiCFile{Name: f.Name, Data: b})
		}
	}
	var xades []string // the XAdES signatures, in container order
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "META-INF/") && strings.Contains(f.Name, "signatures") && strings.HasSuffix(f.Name, ".xml") {
			xades = append(xades, f.Name)
		}
	}

	switch mediaType := string(entries["mimetype"]); {
	case mediaType != asicSType && mediaType != asicEType:
		return nil, nil, fmt.Errorf("pki: ASiC media type %q, want %s or %s", mediaType, asicSType, asicEType)
	case len(xades) > 0:
		return verifyASiCXAdES(mediaType, entries, data, xades, certs)
	case mediaType == asicSType:
		return verifyASiCS(entries, data, certs)
	default:
		return verifyASiCE(entries, data, certs)
	}
}

// verifyASiCXAdES verifies the XAdES signatures xades of a container, which
// sign its files directly: META-INF/signatures.xml the one file of ASiC-S,
// META-INF/signatures*.xml any files of ASiC-E.
func verifyASiCXAdES(mediaType string, entries map[string][]byte, data []ASiCFile, xades []string, certs []*x509.Certificate) ([]ASiCFile, []Signer, error) {
	for name := range entries {
		if strings.HasPrefix(name, "META-INF/") && strings.HasSuffix(name, ".p7s") {
			return nil, nil, fmt.Errorf("pki: ASiC with both XAdES and CAdES signatures: %w", errors.ErrUnsupported)
		}
	}
	if mediaType == asicSType && (len(data) != 1 || len(xades) != 1 || xades[0] != asicSXAdES) {
		return nil, nil, fmt.Errorf("pki: ASiC-S holds %d files and XAdES signatures %q, want 1 file and %s", len(data), xades, asicSXAdES)
	}
	files := make(map[string][]byte, len(data))
	for _, f := range data {
		files[f.Name] = f.Data
	}
	signed := make(map[string]bool)
	var signers []Signer
	for _, name := range xades {
		uris, s, err := VerifyXAdES(entries[name], files, certs)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: ASiC %s: %w", name, err)
		}
		for _, uri := range uris {
			file := uri
			if _, ok := files[file]; !ok {
				file, _ = url.PathUnescape(uri) // the other name VerifyXAdES looks up
			}
			if _, ok := files[file]; !ok {
				return nil, nil, fmt.Errorf("pki: ASiC %s signs %q, which is not a file of the container", name, uri)
			}
			signed[file] = true
		}
		signers = append(signers, s...)
	}

	var out []ASiCFile
	for _, f := range data {
		if signed[f.Name] {
			out = append(out, f)
		}
	}
	if mediaType == asicSType && len(out) != 1 {
		return nil, nil, fmt.Errorf("pki: ASiC-S %s does not sign %s", asicSXAdES, data[0].Name)
	}
	return out, signers, nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close() // read-only: ReadAll reports the error that matters
	return io.ReadAll(rc)
}

func verifyASiCS(entries map[string][]byte, data []ASiCFile, certs []*x509.Certificate) ([]ASiCFile, []Signer, error) {
	if len(data) != 1 {
		return nil, nil, fmt.Errorf("pki: ASiC-S holds %d files, want 1", len(data))
	}
	signature, ok := entries[asicSSignature]
	if !ok {
		return nil, nil, fmt.Errorf("pki: ASiC-S without %s", asicSSignature)
	}
	_, signers, err := VerifySignedData(signature, data[0].Data, certs)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: ASiC-S %s: %w", data[0].Name, err)
	}
	return data, signers, nil
}

// asicManifest is the ASiCManifest element of ETSI EN 319 162-1.
type asicManifest struct {
	XMLName      xml.Name `xml:"http://uri.etsi.org/02918/v1.2.1# ASiCManifest"`
	SigReference struct {
		URI string `xml:"URI,attr"`
	} `xml:"http://uri.etsi.org/02918/v1.2.1# SigReference"`
	References []struct {
		URI          string `xml:"URI,attr"`
		DigestMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
		DigestValue string `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
	} `xml:"http://uri.etsi.org/02918/v1.2.1# DataObjectReference"`
}

func verifyASiCE(entries map[string][]byte, data []ASiCFile, certs []*x509.Certificate) ([]ASiCFile, []Signer, error) {
	var signers []Signer
	signed := make(map[string]bool)     // data objects a verified manifest lists
	referenced := make(map[string]bool) // signatures a manifest references
	for name, manifest := range entries {
		if !strings.HasPrefix(name, "META-INF/ASiCManifest") || !strings.HasSuffix(name, ".xml") {
			continue
		}
		var m asicManifest
		if err := xml.Unmarshal(manifest, &m); err != nil {
			return nil, nil, fmt.Errorf("pki: ASiC-E %s: %w", name, err)
		}
		sigName := m.SigReference.URI
		signature, ok := entries[sigName]
		if !ok || referenced[sigName] {
			return nil, nil, fmt.Errorf("pki: ASiC-E %s references signature %q, which is missing or referenced twice", name, sigName)
		}
		referenced[sigName] = true
		_, s, err := VerifySignedData(signature, manifest, certs)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: ASiC-E %s: %w", sigName, err)
		}
		for _, ref := range m.References {
			file := ref.URI
			content, ok := entries[file]
			if !ok { // a URI may percent-encode the name
				if unescaped, err := url.PathUnescape(file); err == nil {
					file = unescaped
					content, ok = entries[file]
				}
			}
			if !ok || file == "mimetype" || strings.HasPrefix(file, "META-INF/") {
				return nil, nil, fmt.Errorf("pki: ASiC-E %s lists %q, which is not a file of the container", name, ref.URI)
			}
			digest, err := asicDigest(ref.DigestMethod.Algorithm, content)
			if err != nil {
				return nil, nil, fmt.Errorf("pki: ASiC-E %s: %w", name, err)
			}
			want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ref.DigestValue))
			if err != nil || !bytes.Equal(digest, want) {
				return nil, nil, fmt.Errorf("pki: ASiC-E %s: digest of %s: %w", name, file, ErrInvalidSignature)
			}
			signed[file] = true
		}
		signers = append(signers, s...)
	}
	for name := range entries {
		if strings.HasPrefix(name, "META-INF/signature") && strings.HasSuffix(name, ".p7s") && !referenced[name] {
			return nil, nil, fmt.Errorf("pki: ASiC-E signature %s is not referenced by a manifest", name)
		}
	}
	if len(signers) == 0 {
		return nil, nil, errors.New("pki: ASiC-E without a signed manifest")
	}

	var files []ASiCFile
	for _, f := range data {
		if signed[f.Name] {
			files = append(files, f)
		}
	}
	return files, signers, nil
}

// asicDigest hashes data with the algorithm an ASiC manifest names by URI.
func asicDigest(algorithm string, data []byte) ([]byte, error) {
	switch algorithm {
	case digestGOST34311:
		sum := gost34311.Sum(data)
		return sum[:], nil
	case digestKupyna256:
		sum := kupyna.Sum256(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("pki: ASiC digest algorithm %q: %w", algorithm, errors.ErrUnsupported)
	}
}
