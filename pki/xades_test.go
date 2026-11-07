package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"maps"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/pki"
)

// The czo-test-xades-* files are the ЦЗО test examples of IIT XAdES: the
// document <ServiceStatusList>\n</ServiceStatusList> with the signature
// inside it (enveloped) or the signature of the file Test.xml with that
// document (detached). The 2026 example has another test signer and TSA,
// whose certificate it carries in the time-stamp. In the B-LTA example IIT
// wrote the OCSP response about the signer with a zero issuerKeyHash: it is
// matched by the issuer name and serial number alone.
func TestVerifyXAdESCZO(t *testing.T) {
	bundle := []*x509.Certificate{readCert(t, "czo-test-tsa.der"), readCert(t, "czo-test-ocsp-ca.der"), readCert(t, "czo-test-ocsp-root.der")}
	detached := map[string][]byte{"Test.xml": readTestdata(t, "czo-test-xades-data.xml")}
	tests := []struct {
		file        string
		files       map[string][]byte
		wantSigned  []string
		wantSigner  string
		wantTime    string
		wantTS      bool
		wantChain   int
		wantOCSP    bool
		wantArchive int
	}{
		{file: "czo-test-xades-bb-gost.xml", wantSigned: []string{""}, wantSigner: "ТЕСТ Тестовий Тест Тестович", wantTime: "2024-03-04T08:16:53Z"},
		{file: "czo-test-xades-bt-kupyna-detached.xml", files: detached, wantSigned: []string{"Test.xml"}, wantSigner: "TEST TEST Testov Test",
			wantTime: "2026-04-27T05:35:57Z", wantTS: true},
		{file: "czo-test-xades-blt-gost.xml", wantSigned: []string{""}, wantSigner: "ТЕСТ Тестовий Тест Тестович", wantTS: true, wantChain: 3, wantOCSP: true},
		{file: "czo-test-xades-blta-kupyna.xml", wantSigned: []string{""}, wantSigner: "ТЕСТ Тестовий Тест Тестович", wantTS: true, wantChain: 3, wantOCSP: true,
			wantArchive: 1},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			signed, signers, err := pki.VerifyXAdES(readTestdata(t, tt.file), tt.files, bundle)
			if err != nil {
				t.Fatalf("VerifyXAdES(%s) error = %v", tt.file, err)
			}
			if !slices.Equal(signed, tt.wantSigned) {
				t.Errorf("VerifyXAdES(%s) signed = %q, want %q", tt.file, signed, tt.wantSigned)
			}
			if len(signers) != 1 {
				t.Fatalf("VerifyXAdES(%s) = %d signers, want 1", tt.file, len(signers))
			}
			s := signers[0]
			if cn := s.Certificate.Subject.CommonName; cn != tt.wantSigner {
				t.Errorf("VerifyXAdES(%s) signer = %q, want %q", tt.file, cn, tt.wantSigner)
			}
			if tt.wantTime != "" {
				if want, _ := time.Parse(time.RFC3339, tt.wantTime); !s.SigningTime.Equal(want) {
					t.Errorf("VerifyXAdES(%s) signing time = %v, want %s", tt.file, s.SigningTime, tt.wantTime)
				}
			}
			const tsaName = "TSP-сервер Адміністратора ІТС ЦЗО (CA TEST)"
			if got := s.TimeStamp != nil && s.TimeStamp.Certificate.Subject.CommonName == tsaName; got != tt.wantTS {
				t.Errorf("VerifyXAdES(%s) time-stamp by the ЦЗО test TSA = %v, want %v", tt.file, got, tt.wantTS)
			}
			if len(s.Chain) != tt.wantChain {
				t.Errorf("VerifyXAdES(%s) chain = %d certificates, want %d", tt.file, len(s.Chain), tt.wantChain)
			}
			if got := len(s.OCSP) > 0 && s.OCSP[0] != nil; got != tt.wantOCSP {
				t.Errorf("VerifyXAdES(%s) OCSP response about the signer = %v, want %v", tt.file, got, tt.wantOCSP)
			}
			if len(s.ArchiveTimeStamps) != tt.wantArchive {
				t.Fatalf("VerifyXAdES(%s) = %d archive time-stamps, want %d", tt.file, len(s.ArchiveTimeStamps), tt.wantArchive)
			}
			for _, ts := range s.ArchiveTimeStamps {
				if ts.Certificate.Subject.CommonName != tsaName || ts.Time.Before(s.TimeStamp.Time) {
					t.Errorf("VerifyXAdES(%s) archive time-stamp by %q at %v, want the ЦЗО test TSA after the signature time-stamp %v",
						tt.file, ts.Certificate.Subject.CommonName, ts.Time, s.TimeStamp.Time)
				}
			}
		})
	}
}

// TestVerifyXAdESArchiveTimeStamp changes what the ArchiveTimeStamp of the
// ЦЗО B-LTA sample covers and nothing else the other checks see.
func TestVerifyXAdESArchiveTimeStamp(t *testing.T) {
	bundle := []*x509.Certificate{readCert(t, "czo-test-tsa.der"), readCert(t, "czo-test-ocsp-ca.der"), readCert(t, "czo-test-ocsp-root.der")}
	doc := readTestdata(t, "czo-test-xades-blta-kupyna.xml")
	replace := func(old, replacement string) []byte {
		t.Helper()
		if !bytes.Contains(doc, []byte(old)) {
			t.Fatalf("the document has no %q", old)
		}
		return bytes.Replace(doc, []byte(old), []byte(replacement), 1)
	}
	tests := []struct {
		name    string
		doc     []byte
		wantErr error // nil: any
	}{
		{"certificate values changed", replace("<xades:CertificateValues>", "<xades:CertificateValues>\n"), pki.ErrInvalidSignature},
		{"revocation values changed", replace("<xades:RevocationValues>", "<xades:RevocationValues>\n"), pki.ErrInvalidSignature},
		{"inclusive canonicalization", replace(`<xadesv141:ArchiveTimeStamp xmlns:xadesv141="http://uri.etsi.org/01903/v1.4.1#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`,
			`<xadesv141:ArchiveTimeStamp xmlns:xadesv141="http://uri.etsi.org/01903/v1.4.1#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>`), errors.ErrUnsupported},
		{"token missing", regexp.MustCompile(`(<xadesv141:ArchiveTimeStamp[^>]*><ds:CanonicalizationMethod[^>]*/><xades:EncapsulatedTimeStamp>)[^<]*`).ReplaceAll(doc, []byte("${1}")), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := pki.VerifyXAdES(tt.doc, nil, bundle)
			if err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyXAdES(%s) error = %v, want an error matching %v (nil: any)", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestVerifyXAdESRejects(t *testing.T) {
	bundle := []*x509.Certificate{readCert(t, "czo-test-tsa.der")}
	enveloped := readTestdata(t, "czo-test-xades-bb-gost.xml")
	detachedSig := readTestdata(t, "czo-test-xades-bt-kupyna-detached.xml")
	data := readTestdata(t, "czo-test-xades-data.xml")
	replace := func(doc []byte, old, replacement string) []byte {
		t.Helper()
		if !bytes.Contains(doc, []byte(old)) {
			t.Fatalf("the document has no %q", old)
		}
		return bytes.Replace(doc, []byte(old), []byte(replacement), 1)
	}
	tests := []struct {
		name    string
		doc     []byte
		files   map[string][]byte
		wantErr error // nil: any
	}{
		{"document changed", replace(enveloped, "<ServiceStatusList>\n", "<ServiceStatusList>\n "), nil, pki.ErrInvalidSignature},
		{"signing time changed", replace(enveloped, "08:16:53Z", "08:16:54Z"), nil, pki.ErrInvalidSignature},
		{"signature value changed", replace(enveloped, "<ds:SignatureValue>br9o", "<ds:SignatureValue>cr9o"), nil, pki.ErrInvalidSignature},
		{"signed file changed", detachedSig, map[string][]byte{"Test.xml": append(slices.Clone(data), ' ')}, pki.ErrInvalidSignature},
		{"signed file missing", detachedSig, nil, nil},
		{"not XML", []byte("not XML"), nil, nil},
		{"no signature", data, nil, nil},
		{"DOCTYPE", append([]byte(`<!DOCTYPE ServiceStatusList>`), enveloped[bytes.Index(enveloped, []byte("<ServiceStatusList>")):]...), nil, nil},
		{"Id twice", replace(enveloped, "<ServiceStatusList>", `<ServiceStatusList><x Id="xades-id-cf92f7a6441a360f6805ad1902e0d19a"/>`), nil, nil},
		{"unclosed element", enveloped[:len(enveloped)-len("</ServiceStatusList>")], nil, nil},
		{"inclusive canonicalization", replace(enveloped, `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod`,
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><ds:SignatureMethod`), nil, errors.ErrUnsupported},
		{"ECDSA", replace(enveloped, "xmldsig-more#dstu4145-gost34311", "xmldsig-more#ecdsa-sha256"), nil, errors.ErrUnsupported},
		{"XPath transform", replace(enveloped, "#enveloped-signature", "#xpath"), nil, errors.ErrUnsupported},
		{"enveloped signature without its transform", replace(enveloped, `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`, ""), nil, pki.ErrInvalidSignature},
		{"transform of a file", replace(detachedSig, `URI="Test.xml">`, `URI="Test.xml"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>`),
			map[string][]byte{"Test.xml": data}, errors.ErrUnsupported},
		{"reference to a missing Id", replace(enveloped, `URI="#xades-id-`, `URI="#none-`), nil, nil},
		{"no SignedProperties reference", replace(enveloped, `Type="http://uri.etsi.org/01903#SignedProperties"`, `Type=""`), nil, nil},
		{"SignedProperties type on the document", replace(enveloped, `Type="" URI=""`, `Type="http://uri.etsi.org/01903#SignedProperties" URI=""`), nil, nil},
		{"digest on SHA-256", replace(enveloped, "xmlenc#gost34311\"/><ds:DigestValue>5Z", "xmlenc#sha256\"/><ds:DigestValue>5Z"), nil, errors.ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := pki.VerifyXAdES(tt.doc, tt.files, bundle)
			if err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyXAdES(%s) error = %v, want an error matching %v (nil: any)", tt.name, err, tt.wantErr)
			}
		})
	}
}

// xadesLayout blanks the unsigned properties and what xadesFullLayout
// blanks, leaving the markup SignXAdES must write as IIT does.
func xadesLayout(doc []byte) string {
	return xadesFullLayout(regexp.MustCompile(`<xades:UnsignedProperties>.*</xades:UnsignedProperties>`).ReplaceAll(doc, nil))
}

// xadesFullLayout blanks what changes from one signature to the next (Ids,
// base64 values, times), leaving the markup.
func xadesFullLayout(doc []byte) string {
	for _, r := range []struct{ re, repl string }{
		{`id-[0-9a-f]{32}`, "ID"},
		{`TS-[0-9a-f]{32}`, "TSID"},
		{`>[A-Za-z0-9+/=]{20,}<`, ">B64<"},
		{`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`, "TIME"},
	} {
		doc = regexp.MustCompile(r.re).ReplaceAll(doc, []byte(r.repl))
	}
	return string(doc)
}

// The ЦЗО examples are the layout: the enveloped GOST 34.311 signature of
// the document with the XML declaration IIT keeps, the detached Kupyna one
// of Test.xml.
func TestSignXAdES(t *testing.T) {
	s := newTestSigner(t)
	data := readTestdata(t, "czo-test-xades-data.xml")
	doc := append([]byte(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`), data...)
	tests := []struct {
		name   string
		doc    []byte
		opts   pki.SignOptions
		layout string // a ЦЗО example, "" for none
	}{
		{"GOST", doc, pki.SignOptions{GOST34311: true}, "czo-test-xades-bb-gost.xml"},
		{"Kupyna", doc, pki.SignOptions{}, ""},
		{"empty element", []byte(`<a:doc xmlns:a="urn:a"/>`), pki.SignOptions{}, ""},
		{"default namespace", []byte(`<doc xmlns="urn:a" xml:lang="uk"><p>текст &amp; <b/></p></doc>`), pki.SignOptions{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := pki.SignXAdES(rand.Reader, tt.doc, s.key, s.cert, tt.opts)
			if err != nil {
				t.Fatalf("SignXAdES(%s) error = %v", tt.name, err)
			}
			uris, signers, err := pki.VerifyXAdES(signed, nil, nil)
			if err != nil {
				t.Fatalf("VerifyXAdES(SignXAdES(%s)) error = %v", tt.name, err)
			}
			if !slices.Equal(uris, []string{""}) || len(signers) != 1 || !signers[0].Certificate.Equal(s.cert) {
				t.Errorf("VerifyXAdES(SignXAdES(%s)) = %q, %v, want the document signed by the test certificate", tt.name, uris, signers)
			}
			if since := time.Since(signers[0].SigningTime); since < 0 || since > time.Minute {
				t.Errorf("VerifyXAdES(SignXAdES(%s)) signing time = %v, want now", tt.name, signers[0].SigningTime)
			}
			if tt.layout != "" {
				if got, want := xadesLayout(signed), xadesLayout(readTestdata(t, tt.layout)); got != want {
					t.Errorf("SignXAdES(%s) layout =\n%s\nwant (%s)\n%s", tt.name, got, tt.layout, want)
				}
			}
		})
	}
}

func TestSignXAdESDetached(t *testing.T) {
	s := newTestSigner(t)
	data := readTestdata(t, "czo-test-xades-data.xml")
	tests := []struct {
		name   string
		files  []pki.ASiCFile
		opts   pki.SignOptions
		layout string
	}{
		{"Kupyna", []pki.ASiCFile{{Name: "Test.xml", Data: data}}, pki.SignOptions{}, "czo-test-xades-bt-kupyna-detached.xml"},
		{"GOST, two files", []pki.ASiCFile{{Name: "dir/звіт 1.txt", Data: []byte("a")}, {Name: "b#&.bin"}}, pki.SignOptions{GOST34311: true}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := pki.SignXAdESDetached(rand.Reader, tt.files, s.key, s.cert, tt.opts)
			if err != nil {
				t.Fatalf("SignXAdESDetached(%s) error = %v", tt.name, err)
			}
			files := make(map[string][]byte)
			var names []string
			for _, f := range tt.files {
				files[f.Name] = f.Data
				names = append(names, f.Name)
			}
			uris, signers, err := pki.VerifyXAdES(sig, files, nil)
			if err != nil {
				t.Fatalf("VerifyXAdES(SignXAdESDetached(%s)) error = %v", tt.name, err)
			}
			if len(uris) != len(names) || len(signers) != 1 || !signers[0].Certificate.Equal(s.cert) {
				t.Errorf("VerifyXAdES(SignXAdESDetached(%s)) = %q, %v, want %q signed by the test certificate", tt.name, uris, signers, names)
			}
			changed := maps.Clone(files)
			changed[names[0]] = append(slices.Clone(files[names[0]]), 'x')
			if _, _, err := pki.VerifyXAdES(sig, changed, nil); !errors.Is(err, pki.ErrInvalidSignature) {
				t.Errorf("VerifyXAdES(SignXAdESDetached(%s), file changed) error = %v, want ErrInvalidSignature", tt.name, err)
			}
			if tt.layout != "" {
				if got, want := xadesLayout(sig), xadesLayout(readTestdata(t, tt.layout)); got != want {
					t.Errorf("SignXAdESDetached(%s) layout =\n%s\nwant (%s)\n%s", tt.name, got, tt.layout, want)
				}
			}
		})
	}
}

func TestSignXAdESRejects(t *testing.T) {
	s, other := newTestSigner(t), newTestSigner(t)
	if _, err := pki.SignXAdES(rand.Reader, []byte("<a/>"), other.key, s.cert, pki.SignOptions{}); err == nil {
		t.Error("SignXAdES(key of another certificate) error = nil, want an error")
	}
	if _, err := pki.SignXAdES(rand.Reader, []byte("<!DOCTYPE a><a/>"), s.key, s.cert, pki.SignOptions{}); err == nil {
		t.Error("SignXAdES(DOCTYPE) error = nil, want an error")
	}
	if _, err := pki.SignXAdES(rand.Reader, []byte("<a>"), s.key, s.cert, pki.SignOptions{}); err == nil {
		t.Error("SignXAdES(unclosed element) error = nil, want an error")
	}
	for _, files := range [][]pki.ASiCFile{nil, {{Name: "", Data: []byte("x")}}} {
		if _, err := pki.SignXAdESDetached(rand.Reader, files, s.key, s.cert, pki.SignOptions{}); err == nil {
			t.Errorf("SignXAdESDetached(%q) error = nil, want an error", files)
		}
	}
	if _, err := pki.SignXAdESDetached(rand.Reader, []pki.ASiCFile{{Name: "a"}}, other.key, s.cert, pki.SignOptions{}); err == nil {
		t.Error("SignXAdESDetached(key of another certificate) error = nil, want an error")
	}
}

// The ЦЗО B-T example is the layout of the time-stamp: the detached Kupyna
// signature of Test.xml.
func TestAddXAdESSignatureTimeStamp(t *testing.T) {
	s := newTestSigner(t)
	data := readTestdata(t, "czo-test-xades-data.xml")
	files := map[string][]byte{"Test.xml": data}
	for _, gost := range []bool{false, true} {
		sig, err := pki.SignXAdESDetached(rand.Reader, []pki.ASiCFile{{Name: "Test.xml", Data: data}}, s.key, s.cert, pki.SignOptions{GOST34311: gost})
		if err != nil {
			t.Fatal(err)
		}
		f, tsa := newFakeTSA(t, "")
		bt, err := pki.AddXAdESSignatureTimeStamp(t.Context(), sig, tsa)
		if err != nil {
			t.Fatalf("AddXAdESSignatureTimeStamp(GOST34311=%v) error = %v", gost, err)
		}
		wantAlg := oidKupyna256
		if gost {
			wantAlg = oidGOST34311
		}
		if !f.imprintAlg.Equal(wantAlg) {
			t.Errorf("AddXAdESSignatureTimeStamp(GOST34311=%v) stamped with %v, want the signature's %v", gost, f.imprintAlg, wantAlg)
		}
		_, signers, err := pki.VerifyXAdES(bt, files, nil)
		if err != nil {
			t.Fatalf("VerifyXAdES(B-T, GOST34311=%v) error = %v", gost, err)
		}
		if ts := signers[0].TimeStamp; ts == nil || !ts.Certificate.Equal(f.signer.cert) {
			t.Errorf("VerifyXAdES(B-T, GOST34311=%v) time-stamp = %+v, want the fake TSA's", gost, ts)
		}
		if !gost {
			if got, want := xadesFullLayout(bt), xadesFullLayout(readTestdata(t, "czo-test-xades-bt-kupyna-detached.xml")); got != want {
				t.Errorf("AddXAdESSignatureTimeStamp() layout =\n%s\nwant (czo-test-xades-bt-kupyna-detached.xml)\n%s", got, want)
			}
		}

		tampered := bytes.Replace(bt, []byte("<ds:SignatureValue>"), []byte("<ds:SignatureValue>AAAA"), 1)
		if _, _, err := pki.VerifyXAdES(tampered, files, nil); err == nil {
			t.Errorf("VerifyXAdES(B-T with another signature value, GOST34311=%v) error = nil, want error", gost)
		}
	}
}

// newXAdESPath is a signer under a CA under a root, the CA answering OCSP
// through a responder certificate of its own, as the ЦЗО CA does; mode is
// the fakeOCSP mode.
func newXAdESPath(t *testing.T, mode string) (leaf, ca, root, responder *testSigner) {
	t.Helper()
	root = issueTestSigner(t, nil, "test root", "")
	ca = issueTestSigner(t, root, "test CA", "")
	responder = issueTestSigner(t, ca, "test OCSP", "", oidOCSPSigning)
	_, srv := newFakeOCSP(t, mode, ca, responder)
	srv.Start() // OCSPClient dials the URL in the certificate with its own client
	return issueTestSigner(t, ca, "test signer", srv.URL), ca, root, responder
}

// The ЦЗО B-LT example is the layout of the validation data: the CA, the
// root and the OCSP responder, then the response about the signer.
func TestAddXAdESValidationData(t *testing.T) {
	leaf, ca, root, responder := newXAdESPath(t, "")
	doc := append([]byte(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`), readTestdata(t, "czo-test-xades-data.xml")...)
	bb, err := pki.SignXAdES(rand.Reader, doc, leaf.key, leaf.cert, pki.SignOptions{GOST34311: true})
	if err != nil {
		t.Fatal(err)
	}
	_, tsa := newFakeTSA(t, "")
	bt, err := pki.AddXAdESSignatureTimeStamp(t.Context(), bb, tsa)
	if err != nil {
		t.Fatal(err)
	}
	certs := []*x509.Certificate{ca.cert, root.cert}
	blt, err := pki.AddXAdESValidationData(t.Context(), bt, certs, &pki.OCSPClient{})
	if err != nil {
		t.Fatalf("AddXAdESValidationData() error = %v", err)
	}
	if got, want := xadesFullLayout(blt), xadesFullLayout(readTestdata(t, "czo-test-xades-blt-gost.xml")); got != want {
		t.Errorf("AddXAdESValidationData() layout =\n%s\nwant (czo-test-xades-blt-gost.xml)\n%s", got, want)
	}

	// the values make the signature self-contained: no certificates from the caller
	_, signers, err := pki.VerifyXAdES(blt, nil, nil)
	if err != nil {
		t.Fatalf("VerifyXAdES(B-LT) error = %v", err)
	}
	sg := signers[0]
	wantChain := []*x509.Certificate{leaf.cert, ca.cert, root.cert}
	if len(sg.Chain) != len(wantChain) || !slices.EqualFunc(sg.Chain, wantChain, (*x509.Certificate).Equal) {
		t.Errorf("VerifyXAdES(B-LT) chain = %d certificates, want signer, CA, root", len(sg.Chain))
	}
	if sg.TimeStamp == nil || len(sg.OCSP) != 2 || sg.OCSP[0] == nil || sg.OCSP[0].Status != pki.OCSPGood ||
		!sg.OCSP[0].Certificate.Equal(responder.cert) || sg.OCSP[1] != nil {
		t.Errorf("VerifyXAdES(B-LT) time-stamp %v, OCSP %+v, want a time-stamp and a good response about the signer only", sg.TimeStamp, sg.OCSP)
	}
}

func TestAddXAdESRejects(t *testing.T) {
	leaf, ca, root, _ := newXAdESPath(t, "")
	revokedLeaf, revokedCA, revokedRoot, _ := newXAdESPath(t, "revoked")
	_, tsa := newFakeTSA(t, "")
	bt := func(s *testSigner) []byte {
		t.Helper()
		bb, err := pki.SignXAdES(rand.Reader, []byte("<a/>"), s.key, s.cert, pki.SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bt, err := pki.AddXAdESSignatureTimeStamp(t.Context(), bb, tsa)
		if err != nil {
			t.Fatal(err)
		}
		return bt
	}
	good := bt(leaf)
	certs := []*x509.Certificate{ca.cert, root.cert}
	blt, err := pki.AddXAdESValidationData(t.Context(), good, certs, &pki.OCSPClient{})
	if err != nil {
		t.Fatal(err)
	}
	bb, err := pki.SignXAdES(rand.Reader, []byte("<a/>"), leaf.key, leaf.cert, pki.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pki.AddXAdESSignatureTimeStamp(t.Context(), good, tsa); err == nil {
		t.Error("AddXAdESSignatureTimeStamp(B-T) error = nil, want error")
	}
	if _, err := pki.AddXAdESSignatureTimeStamp(t.Context(), []byte("<a/>"), tsa); err == nil {
		t.Error("AddXAdESSignatureTimeStamp(no signature) error = nil, want error")
	}
	otherPrefix := bytes.ReplaceAll(bb, []byte("xades:"), []byte("xa:"))
	otherPrefix = bytes.ReplaceAll(otherPrefix, []byte("xmlns:xades="), []byte("xmlns:xa="))
	if _, err := pki.AddXAdESSignatureTimeStamp(t.Context(), otherPrefix, tsa); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("AddXAdESSignatureTimeStamp(prefix xa) error = %v, want errors.ErrUnsupported", err)
	}
	tests := []struct {
		name  string
		doc   []byte
		certs []*x509.Certificate
	}{
		{"B-B", bb, certs},
		{"B-LT", blt, certs},
		{"CA unknown", good, []*x509.Certificate{root.cert}},
		{"revoked", bt(revokedLeaf), []*x509.Certificate{revokedCA.cert, revokedRoot.cert}},
	}
	for _, tt := range tests {
		if got, err := pki.AddXAdESValidationData(t.Context(), tt.doc, tt.certs, &pki.OCSPClient{}); err == nil {
			t.Errorf("AddXAdESValidationData(%s) = %d bytes, want error", tt.name, len(got))
		}
	}
}

// The ЦЗО B-LTA example is the layout of the archive time-stamp: the
// enveloped Kupyna signature with the validation data about the signer.
func TestAddXAdESArchiveTimeStamp(t *testing.T) {
	leaf, ca, root, _ := newXAdESPath(t, "")
	certs := []*x509.Certificate{ca.cert, root.cert}
	f, tsa := newFakeTSA(t, "")
	data := readTestdata(t, "czo-test-xades-data.xml")
	blt := func(t *testing.T, bb []byte) []byte {
		t.Helper()
		bt, err := pki.AddXAdESSignatureTimeStamp(t.Context(), bb, tsa)
		if err != nil {
			t.Fatal(err)
		}
		blt, err := pki.AddXAdESValidationData(t.Context(), bt, certs, &pki.OCSPClient{})
		if err != nil {
			t.Fatal(err)
		}
		return blt
	}

	t.Run("enveloped", func(t *testing.T) {
		doc := append([]byte(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`), data...)
		bb, err := pki.SignXAdES(rand.Reader, doc, leaf.key, leaf.cert, pki.SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		lta, err := pki.AddXAdESArchiveTimeStamp(t.Context(), blt(t, bb), nil, tsa)
		if err != nil {
			t.Fatalf("AddXAdESArchiveTimeStamp() error = %v", err)
		}
		if !f.imprintAlg.Equal(oidKupyna256) {
			t.Errorf("AddXAdESArchiveTimeStamp() stamped with %v, want the signature's %v", f.imprintAlg, oidKupyna256)
		}
		if got, want := xadesFullLayout(lta), xadesFullLayout(readTestdata(t, "czo-test-xades-blta-kupyna.xml")); got != want {
			t.Errorf("AddXAdESArchiveTimeStamp() layout =\n%s\nwant (czo-test-xades-blta-kupyna.xml)\n%s", got, want)
		}
		// a second archive time-stamp covers the first, as when renewing B-LTA
		lta2, err := pki.AddXAdESArchiveTimeStamp(t.Context(), lta, nil, tsa)
		if err != nil {
			t.Fatalf("AddXAdESArchiveTimeStamp(B-LTA) error = %v", err)
		}
		for _, tt := range []struct {
			name string
			doc  []byte
			want int
		}{{"B-LTA", lta, 1}, {"B-LTA twice", lta2, 2}} {
			_, signers, err := pki.VerifyXAdES(tt.doc, nil, nil)
			if err != nil {
				t.Fatalf("VerifyXAdES(%s) error = %v", tt.name, err)
			}
			if got := signers[0].ArchiveTimeStamps; len(got) != tt.want || !got[0].Certificate.Equal(f.signer.cert) {
				t.Errorf("VerifyXAdES(%s) archive time-stamps = %+v, want %d from the fake TSA", tt.name, got, tt.want)
			}
		}
	})

	t.Run("detached", func(t *testing.T) {
		bb, err := pki.SignXAdESDetached(rand.Reader, []pki.ASiCFile{{Name: "Test.xml", Data: data}}, leaf.key, leaf.cert, pki.SignOptions{GOST34311: true})
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{"Test.xml": data}
		lta, err := pki.AddXAdESArchiveTimeStamp(t.Context(), blt(t, bb), files, tsa)
		if err != nil {
			t.Fatalf("AddXAdESArchiveTimeStamp(detached) error = %v", err)
		}
		if !f.imprintAlg.Equal(oidGOST34311) {
			t.Errorf("AddXAdESArchiveTimeStamp(GOST34311) stamped with %v, want %v", f.imprintAlg, oidGOST34311)
		}
		if _, signers, err := pki.VerifyXAdES(lta, files, nil); err != nil || len(signers[0].ArchiveTimeStamps) != 1 {
			t.Errorf("VerifyXAdES(detached B-LTA) = %+v, %v, want one archive time-stamp", signers, err)
		}
	})

	t.Run("rejects", func(t *testing.T) {
		bb, err := pki.SignXAdESDetached(rand.Reader, []pki.ASiCFile{{Name: "Test.xml", Data: data}}, leaf.key, leaf.cert, pki.SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bt, err := pki.AddXAdESSignatureTimeStamp(t.Context(), bb, tsa)
		if err != nil {
			t.Fatal(err)
		}
		withValues := blt(t, bb)
		tests := []struct {
			name  string
			doc   []byte
			files map[string][]byte
		}{
			{"B-B", bb, map[string][]byte{"Test.xml": data}},
			{"B-T", bt, map[string][]byte{"Test.xml": data}},
			{"file missing", withValues, nil},
			{"file changed", withValues, map[string][]byte{"Test.xml": append(slices.Clone(data), ' ')}},
		}
		for _, tt := range tests {
			if got, err := pki.AddXAdESArchiveTimeStamp(t.Context(), tt.doc, tt.files, tsa); err == nil {
				t.Errorf("AddXAdESArchiveTimeStamp(%s) = %d bytes, want error", tt.name, len(got))
			}
		}
	})
}
