package pki_test

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/fs"
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

func TestVerifyASiCXAdESUnsupported(t *testing.T) {
	if _, _, err := pki.VerifyASiC(readTestdata(t, "czo-test-asics-xades-gost.asics"), nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("VerifyASiC(ASiC-S with XAdES) error = %v, want errors.ErrUnsupported", err)
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

// A manifest may percent-encode the file name in its URI.
func TestVerifyASiCEEncodedURI(t *testing.T) {
	s := newTestSigner(t)
	name, data := "звіт 1.txt", []byte("report")
	sum := kupyna.Sum256(data)
	manifest := []byte(`<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<asic:SigReference URI="META-INF/signature001.p7s"/>` +
		`<asic:DataObjectReference URI="%D0%B7%D0%B2%D1%96%D1%82%201.txt">` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#dstu7564-256"/>` +
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
	files, _, err := pki.VerifyASiC(buf.Bytes(), nil)
	if err != nil {
		t.Fatalf("VerifyASiC(manifest URI percent-encoded) error = %v", err)
	}
	if len(files) != 1 || files[0].Name != name {
		t.Errorf("VerifyASiC(manifest URI percent-encoded) files = %+v, want %q", files, name)
	}
}
