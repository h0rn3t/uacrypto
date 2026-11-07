package pki_test

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/pki"
)

// The czo-test-asic* files are the ЦЗО test examples of IIT containers: the
// file test.txt, "Test\r\n", with a detached CAdES signature over it (ASiC-S)
// or over META-INF/ASiCManifest001.xml (ASiC-E).
func TestVerifyASiCCZO(t *testing.T) {
	tsa := readCert(t, "czo-test-tsa.der")
	bundle := []*x509.Certificate{tsa, readCert(t, "czo-test-ocsp-ca.der"), readCert(t, "czo-test-ocsp-root.der")}
	tests := []struct {
		file      string
		wantTS    bool
		wantChain int
	}{
		{file: "czo-test-asics-bes-gost.asics"},
		{file: "czo-test-asice-t-kupyna.asice", wantTS: true},
		{file: "czo-test-asice-xlong-gost.asice", wantTS: true, wantChain: 3},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			files, signers, err := pki.VerifyASiC(readTestdata(t, tt.file), bundle)
			if err != nil {
				t.Fatalf("VerifyASiC(%s) error = %v", tt.file, err)
			}
			if len(files) != 1 || files[0].Name != "test.txt" || string(files[0].Data) != "Test\r\n" {
				t.Errorf("VerifyASiC(%s) files = %+v, want test.txt with \"Test\\r\\n\"", tt.file, files)
			}
			if len(signers) != 1 {
				t.Fatalf("VerifyASiC(%s) = %d signers, want 1", tt.file, len(signers))
			}
			s := signers[0]
			if cn := s.Certificate.Subject.CommonName; cn != "ТЕСТ Тестовий Тест Тестович" {
				t.Errorf("VerifyASiC(%s) signer = %q, want ТЕСТ Тестовий Тест Тестович", tt.file, cn)
			}
			if got := s.TimeStamp != nil && s.TimeStamp.Certificate.Equal(tsa); got != tt.wantTS {
				t.Errorf("VerifyASiC(%s) time-stamp by the ЦЗО test TSA = %v, want %v", tt.file, got, tt.wantTS)
			}
			if len(s.Chain) != tt.wantChain {
				t.Errorf("VerifyASiC(%s) chain = %d certificates, want %d", tt.file, len(s.Chain), tt.wantChain)
			}
		})
	}
}

func TestVerifyASiCXAdES(t *testing.T) {
	bundle := []*x509.Certificate{readCert(t, "czo-test-tsa.der")}
	tests := []struct {
		file   string
		wantTS bool
	}{
		{file: "czo-test-asics-xades-gost.asics"},
		{file: "czo-test-asice-xades-bt-kupyna.asice", wantTS: true},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			files, signers, err := pki.VerifyASiC(readTestdata(t, tt.file), bundle)
			if err != nil {
				t.Fatalf("VerifyASiC(%s) error = %v", tt.file, err)
			}
			if len(files) != 1 || files[0].Name != "test.txt" || string(files[0].Data) != "Test\r\n" {
				t.Errorf("VerifyASiC(%s) files = %+v, want test.txt with \"Test\\r\\n\"", tt.file, files)
			}
			if len(signers) != 1 || signers[0].Certificate.Subject.CommonName != "ТЕСТ Тестовий Тест Тестович" || (signers[0].TimeStamp != nil) != tt.wantTS {
				t.Errorf("VerifyASiC(%s) signers = %+v, want ТЕСТ Тестовий Тест Тестович, time-stamped %v", tt.file, signers, tt.wantTS)
			}
		})
	}

	asics := readTestdata(t, "czo-test-asics-xades-gost.asics")
	asice := readTestdata(t, "czo-test-asice-xades-bt-kupyna.asice")
	changed := rezip(t, asice, func(name string, data []byte) []byte {
		if name == "test.txt" {
			return []byte("Test\n")
		}
		return data
	})
	invalid := []struct {
		name      string
		container []byte
		wantErr   error // nil: any
	}{
		{"file changed", changed, pki.ErrInvalidSignature},
		{"CAdES beside XAdES", addEntry(t, asice, "META-INF/signature001.p7s", []byte{0x30, 0}), errors.ErrUnsupported},
		{"ASiC-S with two files", addEntry(t, asics, "b.txt", []byte("y")), nil},
		{"ASiC-S signing an unlisted file", addEntry(t, dropEntry(t, asics, "test.txt"), "other.txt", []byte("Test\r\n")), nil},
	}
	for _, tt := range invalid {
		_, _, err := pki.VerifyASiC(tt.container, bundle)
		if err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("VerifyASiC(%s) error = %v, want an error matching %v (nil: any)", tt.name, err, tt.wantErr)
		}
	}
}

// signDetached returns the sign function of CreateASiCS and CreateASiCE for
// a test signer.
func signDetached(s *testSigner, gost bool) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		return pki.SignData(rand.Reader, data, s.key, s.cert, pki.SignOptions{Detached: true, GOST34311: gost})
	}
}

func TestCreateASiCS(t *testing.T) {
	s := newTestSigner(t)
	file := pki.ASiCFile{Name: "звіт.txt", Data: []byte("report")}
	container, err := pki.CreateASiCS(file, signDetached(s, true))
	if err != nil {
		t.Fatal(err)
	}

	// ETSI EN 319 162-1, A.1: the first local file header holds "mimetype",
	// stored, with no extra field, so the media type is at offset 38.
	const mediaType = "application/vnd.etsi.asic-s+zip"
	if !bytes.HasPrefix(container, []byte("PK\x03\x04")) ||
		container[8] != 0 || container[9] != 0 || // compression method: stored
		container[28] != 0 || container[29] != 0 || // extra field length
		string(container[30:38]) != "mimetype" ||
		string(container[38:38+len(mediaType)]) != mediaType {
		t.Errorf("CreateASiCS first header = %q, want mimetype stored without extra field, then %s", container[:80], mediaType)
	}
	names := entryNames(t, container)
	if want := []string{"mimetype", "звіт.txt", "META-INF/signature.p7s"}; strings.Join(names, " ") != strings.Join(want, " ") {
		t.Errorf("CreateASiCS entries = %q, want %q", names, want)
	}

	files, signers, err := pki.VerifyASiC(container, nil)
	if err != nil {
		t.Fatalf("VerifyASiC(CreateASiCS) error = %v", err)
	}
	if len(files) != 1 || files[0].Name != file.Name || string(files[0].Data) != "report" {
		t.Errorf("VerifyASiC(CreateASiCS) files = %+v, want %+v", files, file)
	}
	if len(signers) != 1 || !signers[0].Certificate.Equal(s.cert) {
		t.Errorf("VerifyASiC(CreateASiCS) signers = %+v, want the test signer", signers)
	}

	tampered := rezip(t, container, func(name string, data []byte) []byte {
		if name == file.Name {
			return []byte("REPORT")
		}
		return data
	})
	if _, _, err := pki.VerifyASiC(tampered, nil); !errors.Is(err, pki.ErrInvalidSignature) {
		t.Errorf("VerifyASiC(ASiC-S with the file changed) error = %v, want ErrInvalidSignature", err)
	}
}

func TestCreateASiCE(t *testing.T) {
	s := newTestSigner(t)
	in := []pki.ASiCFile{{Name: "a.txt", Data: []byte("first")}, {Name: "docs/b.bin", Data: []byte{0, 1, 2}}}
	for _, gost := range []bool{false, true} {
		container, err := pki.CreateASiCE(in, gost, signDetached(s, gost))
		if err != nil {
			t.Fatalf("CreateASiCE(GOST34311 %v) error = %v", gost, err)
		}
		names := entryNames(t, container)
		want := []string{"mimetype", "a.txt", "docs/b.bin", "META-INF/ASiCManifest001.xml", "META-INF/signature001.p7s"}
		if strings.Join(names, " ") != strings.Join(want, " ") {
			t.Errorf("CreateASiCE entries = %q, want %q", names, want)
		}
		if string(container[38:38+31]) != "application/vnd.etsi.asic-e+zip" {
			t.Errorf("CreateASiCE media type = %q, want application/vnd.etsi.asic-e+zip", container[38:69])
		}
		manifest := entry(t, container, "META-INF/ASiCManifest001.xml")
		uri := "http://www.w3.org/2001/04/xmlenc#dstu7564-256"
		if gost {
			uri = "http://www.w3.org/2001/04/xmlenc#gost34311"
		}
		if !bytes.Contains(manifest, []byte(`Algorithm="`+uri+`"`)) {
			t.Errorf("CreateASiCE(GOST34311 %v) manifest = %s, want digests by %s", gost, manifest, uri)
		}

		files, signers, err := pki.VerifyASiC(container, nil)
		if err != nil {
			t.Fatalf("VerifyASiC(CreateASiCE) error = %v", err)
		}
		if len(files) != 2 || files[0].Name != "a.txt" || string(files[0].Data) != "first" ||
			files[1].Name != "docs/b.bin" || !bytes.Equal(files[1].Data, []byte{0, 1, 2}) {
			t.Errorf("VerifyASiC(CreateASiCE) files = %+v, want %+v", files, in)
		}
		if len(signers) != 1 || !signers[0].Certificate.Equal(s.cert) {
			t.Errorf("VerifyASiC(CreateASiCE) signers = %+v, want the test signer", signers)
		}

		changed := rezip(t, container, func(name string, data []byte) []byte {
			if name == "docs/b.bin" {
				return []byte{9}
			}
			return data
		})
		if _, _, err := pki.VerifyASiC(changed, nil); !errors.Is(err, pki.ErrInvalidSignature) {
			t.Errorf("VerifyASiC(ASiC-E with a file changed) error = %v, want ErrInvalidSignature", err)
		}
	}
}

// The manifest CreateASiCE writes for test.txt is byte for byte the one IIT
// wrote in the ЦЗО example.
func TestCreateASiCEManifestCZO(t *testing.T) {
	want := entry(t, readTestdata(t, "czo-test-asice-t-kupyna.asice"), "META-INF/ASiCManifest001.xml")
	s := newTestSigner(t)
	container, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "test.txt", Data: []byte("Test\r\n")}}, false, signDetached(s, false))
	if err != nil {
		t.Fatal(err)
	}
	if got := entry(t, container, "META-INF/ASiCManifest001.xml"); !bytes.Equal(got, want) {
		t.Errorf("CreateASiCE(test.txt) manifest =\n%s\nwant\n%s", got, want)
	}
}

// A file the manifest does not name is not signed and is not returned.
func TestVerifyASiCEUnsignedFile(t *testing.T) {
	s := newTestSigner(t)
	container, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "a.txt", Data: []byte("signed")}}, false, signDetached(s, false))
	if err != nil {
		t.Fatal(err)
	}
	added := addEntry(t, container, "extra.txt", []byte("not signed"))
	files, _, err := pki.VerifyASiC(added, nil)
	if err != nil {
		t.Fatalf("VerifyASiC(ASiC-E with an extra file) error = %v", err)
	}
	if len(files) != 1 || files[0].Name != "a.txt" {
		t.Errorf("VerifyASiC(ASiC-E with an extra file) files = %+v, want a.txt only", files)
	}
}

func TestVerifyASiCMalformed(t *testing.T) {
	s := newTestSigner(t)
	asics, err := pki.CreateASiCS(pki.ASiCFile{Name: "a.txt", Data: []byte("x")}, signDetached(s, false))
	if err != nil {
		t.Fatal(err)
	}
	asice, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "a.txt", Data: []byte("x")}}, false, signDetached(s, false))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		container []byte
	}{
		{"not a zip", []byte("not a zip")},
		{"nil", nil},
		{"wrong media type", rezip(t, asics, func(name string, data []byte) []byte {
			if name == "mimetype" {
				return []byte("application/zip")
			}
			return data
		})},
		{"ASiC-S with two files", addEntry(t, asics, "b.txt", []byte("y"))},
		{"no signature", dropEntry(t, asics, "META-INF/signature.p7s")},
		{"duplicate entry", addEntry(t, asics, "a.txt", []byte("x"))},
		{"ASiC-E signature without a manifest", addEntry(t, asice, "META-INF/signature002.p7s", entry(t, asice, "META-INF/signature001.p7s"))},
		{"ASiC-E without a manifest", dropEntry(t, dropEntry(t, asice, "META-INF/ASiCManifest001.xml"), "META-INF/signature001.p7s")},
	}
	for _, tt := range tests {
		if _, _, err := pki.VerifyASiC(tt.container, nil); err == nil {
			t.Errorf("VerifyASiC(%s) error = nil, want an error", tt.name)
		}
	}
}

func TestCreateASiCErrors(t *testing.T) {
	s := newTestSigner(t)
	sign := signDetached(s, false)
	failed := errors.New("no key")
	fail := func([]byte) ([]byte, error) { return nil, failed }
	for _, name := range []string{"", "mimetype", "META-INF/x.txt", "/abs.txt", "../up.txt", "dir/"} {
		if _, err := pki.CreateASiCS(pki.ASiCFile{Name: name, Data: []byte("x")}, sign); err == nil {
			t.Errorf("CreateASiCS(name %q) error = nil, want an error", name)
		}
	}
	if _, err := pki.CreateASiCS(pki.ASiCFile{Name: "a.txt"}, fail); !errors.Is(err, failed) {
		t.Errorf("CreateASiCS(failing sign) error = %v, want %v", err, failed)
	}
	if _, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "../up.txt"}}, false, sign); err == nil {
		t.Error("CreateASiCE(name ../up.txt) error = nil, want an error")
	}
	if _, err := pki.CreateASiCE(nil, false, sign); err == nil {
		t.Error("CreateASiCE(no files) error = nil, want an error")
	}
	two := []pki.ASiCFile{{Name: "a.txt"}, {Name: "a.txt"}}
	if _, err := pki.CreateASiCE(two, false, sign); err == nil {
		t.Error("CreateASiCE(a.txt twice) error = nil, want an error")
	}
	if _, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "a.txt"}}, false, fail); !errors.Is(err, failed) {
		t.Errorf("CreateASiCE(failing sign) error = %v, want %v", err, failed)
	}
}

func entryNames(t *testing.T, container []byte) []string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

func entry(t *testing.T, container []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(zr, name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// rezip copies container entry by entry, with each entry's data passed
// through edit; a nil result drops the entry.
func rezip(t *testing.T, container []byte, edit func(name string, data []byte) []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		data := edit(f.Name, entry(t, container, f.Name))
		if data == nil {
			continue
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dropEntry(t *testing.T, container []byte, drop string) []byte {
	t.Helper()
	return rezip(t, container, func(name string, data []byte) []byte {
		if name == drop {
			return nil
		}
		return data
	})
}

func addEntry(t *testing.T, container []byte, name string, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		if err := zw.Copy(f); err != nil {
			t.Fatal(err)
		}
	}
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// handASiCE returns an ASiC-E container with name holding data and a manifest,
// signed by s, that lists uri with the digest algorithm alg and the
// Kupyna-256 digest of data.
func handASiCE(t *testing.T, s *testSigner, name string, data []byte, uri, alg string) []byte {
	t.Helper()
	sum := kupyna.Sum256(data)
	manifest := []byte(`<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<asic:SigReference URI="META-INF/signature001.p7s"/>` +
		`<asic:DataObjectReference URI="` + uri + `">` +
		`<ds:DigestMethod Algorithm="` + alg + `"/>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(sum[:]) + `</ds:DigestValue>` +
		`</asic:DataObjectReference></asic:ASiCManifest>`)
	signature, err := signDetached(s, false)(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []pki.ASiCFile{
		{Name: "mimetype", Data: []byte("application/vnd.etsi.asic-e+zip")},
		{Name: name, Data: data},
		{Name: "META-INF/ASiCManifest001.xml", Data: manifest},
		{Name: "META-INF/signature001.p7s", Data: signature},
	} {
		w, err := zw.Create(e.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.Data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const kupyna256URI = "http://www.w3.org/2001/04/xmlenc#dstu7564-256"

// A manifest may percent-encode the file name in its URI.
func TestVerifyASiCEEncodedURI(t *testing.T) {
	name := "звіт 1.txt"
	container := handASiCE(t, newTestSigner(t), name, []byte("report"), "%D0%B7%D0%B2%D1%96%D1%82%201.txt", kupyna256URI)
	files, _, err := pki.VerifyASiC(container, nil)
	if err != nil {
		t.Fatalf("VerifyASiC(manifest URI percent-encoded) error = %v", err)
	}
	if len(files) != 1 || files[0].Name != name {
		t.Errorf("VerifyASiC(manifest URI percent-encoded) files = %+v, want %q", files, name)
	}
}

// addRawEntry returns container with an entry whose header claims hdr's
// method and sizes, holding data as it is.
func addRawEntry(t *testing.T, container []byte, hdr *zip.FileHeader, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		if err := zw.Copy(f); err != nil {
			t.Fatal(err)
		}
	}
	w, err := zw.CreateRaw(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestVerifyASiCEntries(t *testing.T) {
	s := newTestSigner(t)
	asice, err := pki.CreateASiCE([]pki.ASiCFile{{Name: "a.txt", Data: []byte("x")}}, false, signDetached(s, false))
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := pki.VerifyASiC(addEntry(t, asice, "docs/", nil), nil)
	if err != nil || len(files) != 1 {
		t.Errorf("VerifyASiC(with a directory entry) = %+v, %v, want a.txt", files, err)
	}

	editManifest := func(old, replacement string) []byte {
		return rezip(t, asice, func(name string, data []byte) []byte {
			if name == "META-INF/ASiCManifest001.xml" {
				return bytes.Replace(data, []byte(old), []byte(replacement), 1)
			}
			return data
		})
	}
	tests := []struct {
		name      string
		container []byte
		wantErr   error // nil: any
	}{
		{"entry over the size limit", addRawEntry(t, asice, &zip.FileHeader{Name: "big.bin", Method: zip.Store,
			CompressedSize64: 1, UncompressedSize64: 1<<30 + 1}, []byte{0}), nil},
		{"entry in an unknown compression method", addRawEntry(t, asice, &zip.FileHeader{Name: "b.bin", Method: 99,
			CompressedSize64: 1, UncompressedSize64: 1}, []byte{0}), nil},
		{"manifest not XML", editManifest("<asic:SigReference", "<<"), nil},
		{"manifest on a missing signature", editManifest("signature001.p7s", "signature009.p7s"), nil},
		{"manifest changed after signing", editManifest(`standalone="no"`, `standalone="yes"`), pki.ErrInvalidSignature},
		{"manifest listing the signature", handASiCE(t, s, "a.txt", []byte("x"), "META-INF/signature001.p7s", kupyna256URI), nil},
		{"manifest listing a missing file", handASiCE(t, s, "a.txt", []byte("x"), "b.txt", kupyna256URI), nil},
		{"digest on SHA-256", handASiCE(t, s, "a.txt", []byte("x"), "a.txt", "http://www.w3.org/2001/04/xmlenc#sha256"), errors.ErrUnsupported},
	}
	for _, tt := range tests {
		_, _, err := pki.VerifyASiC(tt.container, nil)
		if err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("VerifyASiC(%s) error = %v, want an error matching %v (nil: any)", tt.name, err, tt.wantErr)
		}
	}
}

// signXAdES returns the sign function of CreateASiCSXAdES and
// CreateASiCEXAdES for a test signer, with a time-stamp by tsa unless it is
// nil.
func signXAdES(t *testing.T, s *testSigner, gost bool, tsa *pki.TSAClient) func([]pki.ASiCFile) ([]byte, error) {
	return func(files []pki.ASiCFile) ([]byte, error) {
		sig, err := pki.SignXAdESDetached(rand.Reader, files, s.key, s.cert, pki.SignOptions{GOST34311: gost})
		if err != nil || tsa == nil {
			return sig, err
		}
		return pki.AddXAdESSignatureTimeStamp(t.Context(), sig, tsa)
	}
}

// The ЦЗО XAdES containers are the layout: the entries, the OpenDocument
// manifest byte for byte, and the markup of the signatures document; the
// ASiC-S one holds XAdES-B-B with GOST 34.311, the ASiC-E one B-T with
// Kupyna.
func TestCreateASiCXAdESCZO(t *testing.T) {
	s := newTestSigner(t)
	_, tsa := newFakeTSA(t, "")
	file := pki.ASiCFile{Name: "test.txt", Data: []byte("Test\r\n")}
	asics, err := pki.CreateASiCSXAdES(file, signXAdES(t, s, true, nil))
	if err != nil {
		t.Fatalf("CreateASiCSXAdES() error = %v", err)
	}
	asice, err := pki.CreateASiCEXAdES([]pki.ASiCFile{file}, signXAdES(t, s, false, tsa))
	if err != nil {
		t.Fatalf("CreateASiCEXAdES() error = %v", err)
	}
	tests := []struct {
		name, sample string
		container    []byte
		wantTS       bool
	}{
		{"ASiC-S", "czo-test-asics-xades-gost.asics", asics, false},
		{"ASiC-E", "czo-test-asice-xades-bt-kupyna.asice", asice, true},
	}
	for _, tt := range tests {
		sample := readTestdata(t, tt.sample)
		names := entryNames(t, tt.container)
		if want := entryNames(t, sample); !slices.Equal(names, want) {
			t.Errorf("%s entries = %q, want (%s) %q", tt.name, names, tt.sample, want)
		}
		if mt := entry(t, tt.container, "mimetype"); !bytes.Equal(mt, entry(t, sample, "mimetype")) || !bytes.Equal(tt.container[38:38+len(mt)], mt) {
			t.Errorf("%s mimetype = %q, want the first entry as in %s", tt.name, mt, tt.sample)
		}
		for _, name := range names {
			got, want := entry(t, tt.container, name), entry(t, sample, name)
			switch {
			case name == "META-INF/manifest.xml" && !bytes.Equal(got, want):
				t.Errorf("%s %s =\n%s\nwant (%s)\n%s", tt.name, name, got, tt.sample, want)
			case strings.HasPrefix(name, "META-INF/signatures") && xadesFullLayout(got) != xadesFullLayout(want):
				t.Errorf("%s %s layout =\n%s\nwant (%s)\n%s", tt.name, name, xadesFullLayout(got), tt.sample, xadesFullLayout(want))
			}
		}

		files, signers, err := pki.VerifyASiC(tt.container, nil)
		if err != nil {
			t.Fatalf("VerifyASiC(%s) error = %v", tt.name, err)
		}
		if len(files) != 1 || files[0].Name != file.Name || len(signers) != 1 || !signers[0].Certificate.Equal(s.cert) || (signers[0].TimeStamp != nil) != tt.wantTS {
			t.Errorf("VerifyASiC(%s) = %+v, %+v, want test.txt signed by the test signer, time-stamped %v", tt.name, files, signers, tt.wantTS)
		}
	}
}

func TestCreateASiCEXAdES(t *testing.T) {
	s := newTestSigner(t)
	in := []pki.ASiCFile{{Name: "a.xml", Data: []byte("<a/>")}, {Name: "docs/b & c.bin", Data: []byte{0, 1, 2}}}
	container, err := pki.CreateASiCEXAdES(in, signXAdES(t, s, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0" encoding="utf-8" standalone="no" ?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">` +
		`<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>` +
		`<manifest:file-entry manifest:full-path="a.xml" manifest:media-type="text/xml"/>` +
		`<manifest:file-entry manifest:full-path="docs/b &amp; c.bin" manifest:media-type="application/octet-stream"/></manifest:manifest>`
	if got := string(entry(t, container, "META-INF/manifest.xml")); got != want {
		t.Errorf("CreateASiCEXAdES manifest =\n%s\nwant\n%s", got, want)
	}
	files, _, err := pki.VerifyASiC(container, nil)
	if err != nil || len(files) != 2 {
		t.Fatalf("VerifyASiC(CreateASiCEXAdES) = %+v, %v, want both files", files, err)
	}
	changed := rezip(t, container, func(name string, data []byte) []byte {
		if name == "a.xml" {
			return []byte("<b/>")
		}
		return data
	})
	if _, _, err := pki.VerifyASiC(changed, nil); !errors.Is(err, pki.ErrInvalidSignature) {
		t.Errorf("VerifyASiC(ASiC-E XAdES with a file changed) error = %v, want ErrInvalidSignature", err)
	}
}

func TestCreateASiCXAdESErrors(t *testing.T) {
	s := newTestSigner(t)
	sign := signXAdES(t, s, false, nil)
	failed := errors.New("no key")
	tests := []struct {
		name    string
		create  func() ([]byte, error)
		wantErr error // nil: any
	}{
		{"ASiC-S name META-INF/x", func() ([]byte, error) { return pki.CreateASiCSXAdES(pki.ASiCFile{Name: "META-INF/x"}, sign) }, nil},
		{"ASiC-E no files", func() ([]byte, error) { return pki.CreateASiCEXAdES(nil, sign) }, nil},
		{"ASiC-E a.txt twice", func() ([]byte, error) {
			return pki.CreateASiCEXAdES([]pki.ASiCFile{{Name: "a.txt"}, {Name: "a.txt"}}, sign)
		}, nil},
		{"failing sign", func() ([]byte, error) {
			return pki.CreateASiCSXAdES(pki.ASiCFile{Name: "a.txt"}, func([]pki.ASiCFile) ([]byte, error) { return nil, failed })
		}, failed},
		{"not a signature", func() ([]byte, error) {
			return pki.CreateASiCEXAdES([]pki.ASiCFile{{Name: "a.txt"}}, func([]pki.ASiCFile) ([]byte, error) { return []byte("<a></a>"), nil })
		}, nil},
	}
	for _, tt := range tests {
		if _, err := tt.create(); err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: error = %v, want an error matching %v (nil: any)", tt.name, err, tt.wantErr)
		}
	}
}
