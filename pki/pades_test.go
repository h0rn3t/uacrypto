package pki_test

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/pki"
)

var oidKupyna256Hash = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1}

// czoTestPDF is the ЦЗО Test.pdf: the czo-test-pades-* examples are it, the
// first 28879 bytes Microsoft Word wrote (up to its last %%EOF), with the
// signatures IIT appended as incremental updates.
func czoTestPDF(t *testing.T) []byte {
	t.Helper()
	return readTestdata(t, "czo-test-pades-bb-gost.pdf")[:28879]
}

// The expected values were read from the examples by hand: /M and
// /ByteRange of the signature dictionaries, the genTime of the TSTInfo and
// the subject of the signer certificate. As in its XAdES-B-LTA example, IIT
// wrote the OCSP response of the PAdES-B-LTA DSS with a zero issuerKeyHash;
// it is matched by the issuer name and serial number alone.
func TestVerifyPAdESCZO(t *testing.T) {
	bundle := []*x509.Certificate{readCert(t, "czo-test-tsa.der"), readCert(t, "czo-test-ocsp-ca.der"), readCert(t, "czo-test-ocsp-root.der")}
	type want struct {
		subFilter string
		byteRange [4]int64
		covers    bool
		digest    asn1.ObjectIdentifier
		signed    string // /M, "" for a document time-stamp
		stamped   string // genTime, "" without a time-stamp
		chain     int
		ocsp      bool // an OCSP response about the signer
	}
	bes := [4]int64{0, 29494, 49976, 399}
	tests := []struct {
		file string
		want []want
	}{
		{"czo-test-pades-bb-gost.pdf", []want{{"ETSI.CAdES.detached", bes, true, oidGOST34311, "2024-03-04T08:20:05Z", "", 0, false}}},
		{"czo-test-pades-bb-kupyna.pdf", []want{{"ETSI.CAdES.detached", bes, true, oidKupyna256Hash, "2024-03-04T09:06:42Z", "", 0, false}}},
		{"czo-test-pades-bt-gost.pdf", []want{{"ETSI.CAdES.detached", bes, true, oidGOST34311, "2024-03-04T08:19:32Z", "2024-03-04T08:19:33Z", 0, false}}},
		{"czo-test-pades-bt-kupyna.pdf", []want{{"ETSI.CAdES.detached", bes, true, oidKupyna256Hash, "2024-03-04T09:06:18Z", "2024-03-04T09:06:19Z", 0, false}}},
		{"czo-test-pades-blt-gost.pdf", []want{{"ETSI.CAdES.detached", bes, false, oidGOST34311, "2024-03-04T08:18:56Z", "2024-03-04T08:18:57Z", 3, true}}},
		{"czo-test-pades-blta-kupyna.pdf", []want{
			{"ETSI.CAdES.detached", bes, false, oidKupyna256Hash, "2024-03-04T09:05:14Z", "2024-03-04T09:05:15Z", 3, true},
			{"ETSI.RFC3161", [4]int64{0, 66206, 86688, 374}, true, oidKupyna256Hash, "", "2024-03-04T09:05:16Z", 0, false},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			sigs, err := pki.VerifyPAdES(readTestdata(t, tt.file), bundle)
			if err != nil {
				t.Fatalf("VerifyPAdES(%s) error = %v", tt.file, err)
			}
			if len(sigs) != len(tt.want) {
				t.Fatalf("VerifyPAdES(%s) = %d signatures, want %d", tt.file, len(sigs), len(tt.want))
			}
			for i, w := range tt.want {
				s := sigs[i]
				if s.SubFilter != w.subFilter || s.ByteRange != w.byteRange || s.CoversDocument != w.covers || !s.DigestAlgorithm.Equal(w.digest) {
					t.Errorf("VerifyPAdES(%s)[%d] = %s %v covers %v digest %v, want %s %v covers %v digest %v", tt.file, i,
						s.SubFilter, s.ByteRange, s.CoversDocument, s.DigestAlgorithm, w.subFilter, w.byteRange, w.covers, w.digest)
				}
				if w.signed != "" {
					if cn := s.Signer.Certificate.Subject.CommonName; cn != "ТЕСТ Тестовий Тест Тестович" {
						t.Errorf("VerifyPAdES(%s)[%d] signer = %q, want the ЦЗО test signer", tt.file, i, cn)
					}
					if want, _ := time.Parse(time.RFC3339, w.signed); !s.Signer.SigningTime.Equal(want) {
						t.Errorf("VerifyPAdES(%s)[%d] signing time = %v, want %s", tt.file, i, s.Signer.SigningTime, w.signed)
					}
				}
				if w.stamped == "" {
					if s.Signer.TimeStamp != nil {
						t.Errorf("VerifyPAdES(%s)[%d] time-stamp = %v, want none", tt.file, i, s.Signer.TimeStamp.Time)
					}
				} else if want, _ := time.Parse(time.RFC3339, w.stamped); s.Signer.TimeStamp == nil || !s.Signer.TimeStamp.Time.Equal(want) {
					t.Errorf("VerifyPAdES(%s)[%d] time-stamp = %+v, want of %s", tt.file, i, s.Signer.TimeStamp, w.stamped)
				}
				if len(s.Signer.Chain) != w.chain {
					t.Errorf("VerifyPAdES(%s)[%d] chain = %d certificates, want %d", tt.file, i, len(s.Signer.Chain), w.chain)
				}
				if got := len(s.Signer.OCSP) > 0 && s.Signer.OCSP[0] != nil; got != w.ocsp {
					t.Errorf("VerifyPAdES(%s)[%d] OCSP response about the signer = %v, want %v", tt.file, i, got, w.ocsp)
				}
			}
		})
	}
}

func TestVerifyPAdESRejects(t *testing.T) {
	bundle := []*x509.Certificate{readCert(t, "czo-test-tsa.der")}
	sample := readTestdata(t, "czo-test-pades-bt-gost.pdf")
	edit := func(f func(b []byte) []byte) []byte { return f(slices.Clone(sample)) }
	replace := func(old, repl string) []byte {
		t.Helper()
		if !bytes.Contains(sample, []byte(old)) {
			t.Fatalf("the sample has no %q", old)
		}
		return bytes.Replace(slices.Clone(sample), []byte(old), []byte(repl), 1)
	}
	tests := []struct {
		name    string
		pdf     []byte
		invalid bool // the error is ErrInvalidSignature
		unsup   bool // the error is errors.ErrUnsupported
	}{
		{name: "first range", pdf: edit(func(b []byte) []byte { b[200] ^= 1; return b }), invalid: true},
		{name: "second range", pdf: replace("/M (D:20240304101932", "/M (D:20240304101933"), invalid: true},
		{name: "range into contents", pdf: replace("[ 0 29494 49976 399 ", "[ 0 29496 49976 399 ")},
		{name: "range short of contents", pdf: replace("[ 0 29494 49976 399 ", "[ 0 29494 49970 399 ")},
		{name: "range beyond the file", pdf: replace("[ 0 29494 49976 399 ", "[ 0 29494 49976 499 ")},
		{name: "other subfilter", pdf: replace("/SubFilter /ETSI.CAdES.detached", "/SubFilter /adbe.pkcs7.sha1     "), unsup: true},
		{name: "no signature", pdf: czoTestPDF(t)},
		{name: "xref stream without stream", pdf: []byte("%PDF-1.7\n1 0 obj\n<</Type/XRef>>\nendobj\nstartxref\n9\n%%EOF\n")},
		{name: "prev loop", pdf: []byte("%PDF-1.7\nxref\n0 0\ntrailer\n<</Prev 9>>\nstartxref\n9\n%%EOF\n")},
		{name: "deep nesting", pdf: []byte("%PDF-1.7\nxref\n0 0\ntrailer\n" + strings.Repeat("[", 10000) + "\nstartxref\n9\n%%EOF\n")},
		{name: "truncated", pdf: sample[:len(sample)-100]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs, err := pki.VerifyPAdES(tt.pdf, bundle)
			if err == nil {
				t.Fatalf("VerifyPAdES(%s) = %d signatures, want error", tt.name, len(sigs))
			}
			if got := errors.Is(err, pki.ErrInvalidSignature); got != tt.invalid {
				t.Errorf("VerifyPAdES(%s) error = %v, ErrInvalidSignature %v, want %v", tt.name, err, got, tt.invalid)
			}
			if got := errors.Is(err, errors.ErrUnsupported); got != tt.unsup {
				t.Errorf("VerifyPAdES(%s) error = %v, ErrUnsupported %v, want %v", tt.name, err, got, tt.unsup)
			}
		})
	}
}

// A revision appended after the signature leaves the signature valid, but
// not over the whole document.
func TestVerifyPAdESLaterUpdate(t *testing.T) {
	pdf := append(readTestdata(t, "czo-test-pades-bb-gost.pdf"), "\n% a later update\n"...)
	sigs, err := pki.VerifyPAdES(pdf, nil)
	if err != nil {
		t.Fatalf("VerifyPAdES(appended) error = %v", err)
	}
	if len(sigs) != 1 || sigs[0].CoversDocument {
		t.Errorf("VerifyPAdES(appended) = %+v, want one signature that does not cover the document", sigs)
	}
}

func TestSignPAdES(t *testing.T) {
	s := newTestSigner(t)
	doc := czoTestPDF(t)
	tests := []struct {
		name   string
		gost   bool
		tsa    bool
		digest asn1.ObjectIdentifier
		layout string // the ЦЗО example with the same signed attributes
	}{
		{"GOST", true, false, oidGOST34311, "czo-test-pades-bb-gost.pdf"},
		{"Kupyna", false, false, oidKupyna256Hash, "czo-test-pades-bb-kupyna.pdf"},
		{"GOST B-T", true, true, oidGOST34311, "czo-test-pades-bt-gost.pdf"},
		{"Kupyna B-T", false, true, oidKupyna256Hash, "czo-test-pades-bt-kupyna.pdf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tsa *pki.TSAClient
			var tsaCert *x509.Certificate
			if tt.tsa {
				var fake *fakeTSA
				fake, tsa = newFakeTSA(t, "")
				tsaCert = fake.signer.cert
			}
			signed, err := pki.SignPAdES(t.Context(), rand.Reader, doc, s.key, s.cert, pki.SignOptions{GOST34311: tt.gost}, tsa)
			if err != nil {
				t.Fatalf("SignPAdES(%s) error = %v", tt.name, err)
			}
			if !bytes.HasPrefix(signed, doc) {
				t.Errorf("SignPAdES(%s) changed the document instead of appending an update", tt.name)
			}
			sigs, err := pki.VerifyPAdES(signed, nil)
			if err != nil {
				t.Fatalf("VerifyPAdES(SignPAdES(%s)) error = %v", tt.name, err)
			}
			if len(sigs) != 1 {
				t.Fatalf("VerifyPAdES(SignPAdES(%s)) = %d signatures, want 1", tt.name, len(sigs))
			}
			sig := sigs[0]
			if sig.SubFilter != "ETSI.CAdES.detached" || !sig.CoversDocument || !sig.DigestAlgorithm.Equal(tt.digest) || !sig.Signer.Certificate.Equal(s.cert) {
				t.Errorf("VerifyPAdES(SignPAdES(%s)) = %s covers %v digest %v, want ETSI.CAdES.detached over the document by the test signer with %v",
					tt.name, sig.SubFilter, sig.CoversDocument, sig.DigestAlgorithm, tt.digest)
			}
			if since := time.Since(sig.Signer.SigningTime); since < 0 || since > time.Minute {
				t.Errorf("VerifyPAdES(SignPAdES(%s)) signing time = %v, want now", tt.name, sig.Signer.SigningTime)
			}
			if got := sig.Signer.TimeStamp != nil && sig.Signer.TimeStamp.Certificate.Equal(tsaCert); got != tt.tsa {
				t.Errorf("VerifyPAdES(SignPAdES(%s)) time-stamp by the TSA = %v, want %v", tt.name, got, tt.tsa)
			}
			got, _ := signedAttrTypes(t, padesCMS(t, signed)[0])
			want, _ := signedAttrTypes(t, padesCMS(t, readTestdata(t, tt.layout))[0])
			if !slices.Equal(got, want) {
				t.Errorf("SignPAdES(%s) signed attributes = %v, want those of %s: %v", tt.name, got, tt.layout, want)
			}
		})
	}
}

// A second signature goes into the form of the first, in a later update.
func TestSignPAdESTwice(t *testing.T) {
	s := newTestSigner(t)
	once, err := pki.SignPAdES(t.Context(), rand.Reader, readTestdata(t, "czo-test-pades-bb-gost.pdf"), s.key, s.cert, pki.SignOptions{}, nil)
	if err != nil {
		t.Fatalf("SignPAdES(signed) error = %v", err)
	}
	sigs, err := pki.VerifyPAdES(once, nil)
	if err != nil {
		t.Fatalf("VerifyPAdES(SignPAdES(signed)) error = %v", err)
	}
	if len(sigs) != 2 || sigs[0].CoversDocument || !sigs[1].CoversDocument || !sigs[1].Signer.Certificate.Equal(s.cert) {
		t.Errorf("VerifyPAdES(SignPAdES(signed)) = %+v, want the ЦЗО signature and then the test one over the whole document", sigs)
	}
}

func TestSignPAdESRejects(t *testing.T) {
	s := newTestSigner(t)
	other := newTestSigner(t)
	tests := []struct {
		name  string
		pdf   []byte
		key   *testSigner
		unsup bool
	}{
		{name: "other key", pdf: czoTestPDF(t), key: other},
		{name: "xref stream without stream", pdf: []byte("%PDF-1.7\n1 0 obj\n<</Type/XRef>>\nendobj\nstartxref\n9\n%%EOF\n"), key: s},
		{name: "xref field wider than 8 bytes", pdf: editCairo(t, "/W [1 2 2]", "/W [1 9 2]"), key: s},
		{name: "xref entries beyond the stream", pdf: editCairo(t, "/Size 27", "/Size 99"), key: s},
		{name: "object stream index", pdf: editCairo(t, "/N 4", "/N 2"), key: s},
		{name: "TIFF predictor", pdf: bytes.Replace(hybridPDF(t), []byte("/Predictor 12"), []byte("/Predictor 02"), 1), key: s, unsup: true},
		{name: "encrypted", pdf: []byte("%PDF-1.7\nxref\n0 0\ntrailer\n<</Size 1/Root 1 0 R/Encrypt 2 0 R>>\nstartxref\n9\n%%EOF\n"), key: s, unsup: true},
		{name: "not a PDF", pdf: []byte("hello"), key: s},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pki.SignPAdES(t.Context(), rand.Reader, tt.pdf, tt.key.key, s.cert, pki.SignOptions{}, nil)
			if err == nil {
				t.Fatalf("SignPAdES(%s) error = nil, want error", tt.name)
			}
			if got := errors.Is(err, errors.ErrUnsupported); got != tt.unsup {
				t.Errorf("SignPAdES(%s) error = %v, ErrUnsupported %v, want %v", tt.name, err, got, tt.unsup)
			}
		})
	}
}

// FuzzVerifyPAdES checks that a damaged document is an error, not a panic or
// a hang.
func FuzzVerifyPAdES(f *testing.F) {
	sample, err := os.ReadFile(filepath.Join("testdata", "czo-test-pades-blta-kupyna.pdf"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sample)
	f.Add([]byte("xref\n0 1\n0000000000 65535 f\ntrailer\n<</Root 1 0 R>>\nstartxref\n0\n"))
	cairo, err := os.ReadFile(filepath.Join("testdata", "cairo-xref-stream.pdf"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(cairo)
	f.Fuzz(func(t *testing.T, pdf []byte) {
		_, _ = pki.VerifyPAdES(pdf, nil) // only the absence of a panic is checked
	})
}

var contentsHex = regexp.MustCompile(`/Contents ?<([0-9A-Fa-f]+)>`)

// padesCMS returns the CMS of every signature dictionary of pdf, without
// the zero padding.
func padesCMS(t *testing.T, pdf []byte) [][]byte {
	t.Helper()
	var cms [][]byte
	for _, m := range contentsHex.FindAllSubmatch(pdf, -1) {
		der, err := hex.DecodeString(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(der, &raw); err != nil {
			t.Fatalf("asn1.Unmarshal(/Contents) error = %v", err)
		}
		cms = append(cms, raw.FullBytes)
	}
	return cms
}

// TestAddPAdESLongTerm turns a PAdES-B-T signature into B-LT and then B-LTA
// and checks the result as the ЦЗО examples are laid out: a /DSS with /Certs
// and /OCSPs and no /VRI (the signer's CA path, the TSA certificate, the
// OCSP responders; a response about every certificate of the paths but the
// roots), then a document time-stamp with /SubFilter /ETSI.RFC3161.
func TestAddPAdESLongTerm(t *testing.T) {
	p := newTestPath(t, "")
	fake, tsa := newFakeTSA(t, "")
	bt, err := pki.SignPAdES(t.Context(), rand.Reader, czoTestPDF(t), p.leaf.key, p.leaf.cert, pki.SignOptions{}, tsa)
	if err != nil {
		t.Fatal(err)
	}
	certs := []*x509.Certificate{p.ca.cert, p.root.cert}
	blt, err := pki.AddPAdESValidationData(t.Context(), bt, certs, &pki.OCSPClient{})
	if err != nil {
		t.Fatalf("AddPAdESValidationData() error = %v", err)
	}
	if !bytes.HasPrefix(blt, bt) {
		t.Fatal("AddPAdESValidationData() changed the document instead of appending an update")
	}
	update := string(blt[len(bt):])
	dss := regexp.MustCompile(`<</Certs \[([0-9 R]*)\] /OCSPs \[([0-9 R]*)\] /Type /DSS >>`).FindStringSubmatch(update)
	if dss == nil || !regexp.MustCompile(`/DSS \d+ 0 R`).MatchString(update) {
		t.Fatalf("AddPAdESValidationData() update has no /DSS of the catalog with /Certs and /OCSPs only:\n%.600s", update)
	}
	// CA, root, TSA; the CAs answer OCSP themselves; the fake TSA is self-signed
	if certRefs, ocspRefs := strings.Count(dss[1], "R"), strings.Count(dss[2], "R"); certRefs != 3 || ocspRefs != 2 {
		t.Errorf("AddPAdESValidationData() DSS = %d certificates and %d OCSP responses, want 3 and 2", certRefs, ocspRefs)
	}
	if n := strings.Count(update, "/Filter /FlateDecode"); n != 5 {
		t.Errorf("AddPAdESValidationData() wrote %d FlateDecode streams, want 5", n)
	}

	// the DSS makes the signature self-contained: no certificates from the caller
	sigs, err := pki.VerifyPAdES(blt, nil)
	if err != nil {
		t.Fatalf("VerifyPAdES(B-LT) error = %v", err)
	}
	sg := sigs[0].Signer
	wantChain := []*x509.Certificate{p.leaf.cert, p.ca.cert, p.root.cert}
	if len(sigs) != 1 || !slices.EqualFunc(sg.Chain, wantChain, (*x509.Certificate).Equal) ||
		len(sg.OCSP) != 2 || sg.OCSP[0] == nil || sg.OCSP[0].Status != pki.OCSPGood || sg.OCSP[1] == nil || sg.OCSP[1].Status != pki.OCSPGood {
		t.Errorf("VerifyPAdES(B-LT) = %d signatures, chain of %d, OCSP %+v, want signer, CA, root, good responses about the signer and the CA",
			len(sigs), len(sg.Chain), sg.OCSP)
	}
	if _, err := pki.AddPAdESValidationData(t.Context(), blt, certs, &pki.OCSPClient{}); err == nil {
		t.Error("AddPAdESValidationData(B-LT) error = nil, want error: the document already has a DSS")
	}

	blta, err := pki.AddPAdESDocumentTimeStamp(t.Context(), blt, tsa)
	if err != nil {
		t.Fatalf("AddPAdESDocumentTimeStamp() error = %v", err)
	}
	if !bytes.HasPrefix(blta, blt) {
		t.Fatal("AddPAdESDocumentTimeStamp() changed the document instead of appending an update")
	}
	if !regexp.MustCompile(`<</Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /M <[0-9A-F]+> /ByteRange \[0 \d+ \d+ \d+\] +/Contents <[0-9A-F]+>>>`).Match(blta[len(blt):]) {
		t.Errorf("AddPAdESDocumentTimeStamp() update has no document time-stamp dictionary:\n%.400s", blta[len(blt):])
	}
	sigs, err = pki.VerifyPAdES(blta, nil)
	if err != nil {
		t.Fatalf("VerifyPAdES(B-LTA) error = %v", err)
	}
	if len(sigs) != 2 || sigs[0].CoversDocument || sigs[0].Signer.Chain == nil {
		t.Fatalf("VerifyPAdES(B-LTA) = %+v, want the B-LT signature, no longer covering the document", sigs)
	}
	ts := sigs[1]
	if ts.SubFilter != "ETSI.RFC3161" || !ts.CoversDocument || ts.Signer.TimeStamp == nil || !ts.Signer.TimeStamp.Certificate.Equal(fake.signer.cert) {
		t.Errorf("VerifyPAdES(B-LTA) document time-stamp = %+v, want ETSI.RFC3161 by the fake TSA over the whole document", ts)
	}
}

func TestAddPAdESValidationDataRejects(t *testing.T) {
	_, tsa := newFakeTSA(t, "")
	sign := func(p testPath, tsa *pki.TSAClient) []byte {
		t.Helper()
		pdf, err := pki.SignPAdES(t.Context(), rand.Reader, czoTestPDF(t), p.leaf.key, p.leaf.cert, pki.SignOptions{}, tsa)
		if err != nil {
			t.Fatal(err)
		}
		return pdf
	}
	good, revoked := newTestPath(t, ""), newTestPath(t, "revoked")
	tests := []struct {
		name  string
		pdf   []byte
		certs []*x509.Certificate
	}{
		{"no signature time-stamp", sign(good, nil), []*x509.Certificate{good.ca.cert, good.root.cert}},
		{"no path to a root", sign(good, tsa), []*x509.Certificate{good.ca.cert}},
		{"revoked signer", sign(revoked, tsa), []*x509.Certificate{revoked.ca.cert, revoked.root.cert}},
		{"not signed", czoTestPDF(t), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pki.AddPAdESValidationData(t.Context(), tt.pdf, tt.certs, &pki.OCSPClient{}); err == nil {
				t.Errorf("AddPAdESValidationData(%s) error = nil, want error", tt.name)
			}
		})
	}
}

// editCairo returns cairo-xref-stream.pdf with old replaced by repl.
func editCairo(t *testing.T, old, repl string) []byte {
	t.Helper()
	pdf := readTestdata(t, "cairo-xref-stream.pdf")
	if !bytes.Contains(pdf, []byte(old)) {
		t.Fatalf("cairo-xref-stream.pdf has no %q", old)
	}
	return bytes.Replace(pdf, []byte(old), []byte(repl), 1)
}

// TestPAdESXrefStream signs a document whose catalog, page tree and page sit
// in an object stream behind a cross-reference stream (cairo writes them so)
// up to PAdES-B-LTA. Each update is a cross-reference stream too, as the
// document's last section is.
func TestPAdESXrefStream(t *testing.T) {
	doc := readTestdata(t, "cairo-xref-stream.pdf")
	p := newTestPath(t, "")
	_, tsa := newFakeTSA(t, "")
	bt, err := pki.SignPAdES(t.Context(), rand.Reader, doc, p.leaf.key, p.leaf.cert, pki.SignOptions{}, tsa)
	if err != nil {
		t.Fatalf("SignPAdES(xref stream) error = %v", err)
	}
	blt, err := pki.AddPAdESValidationData(t.Context(), bt, []*x509.Certificate{p.ca.cert, p.root.cert}, &pki.OCSPClient{})
	if err != nil {
		t.Fatalf("AddPAdESValidationData(xref stream) error = %v", err)
	}
	blta, err := pki.AddPAdESDocumentTimeStamp(t.Context(), blt, tsa)
	if err != nil {
		t.Fatalf("AddPAdESDocumentTimeStamp(xref stream) error = %v", err)
	}
	for _, u := range []struct{ name, before, after string }{
		{"SignPAdES", string(doc), string(bt)},
		{"AddPAdESValidationData", string(bt), string(blt)},
		{"AddPAdESDocumentTimeStamp", string(blt), string(blta)},
	} {
		update, ok := strings.CutPrefix(u.after, u.before)
		if !ok {
			t.Fatalf("%s(xref stream) changed the document instead of appending an update", u.name)
		}
		if !strings.Contains(update, "/Type /XRef") || strings.Contains(update, "trailer") {
			t.Errorf("%s(xref stream) update ends without a cross-reference stream:\n%.300s", u.name, update[max(0, len(update)-300):])
		}
	}
	sigs, err := pki.VerifyPAdES(blta, nil)
	if err != nil {
		t.Fatalf("VerifyPAdES(xref stream B-LTA) error = %v", err)
	}
	if len(sigs) != 2 || sigs[0].SubFilter != "ETSI.CAdES.detached" || sigs[0].Signer.Chain == nil || sigs[0].Signer.TimeStamp == nil ||
		sigs[1].SubFilter != "ETSI.RFC3161" || !sigs[1].CoversDocument {
		t.Errorf("VerifyPAdES(xref stream B-LTA) = %+v, want the B-LT signature and a document time-stamp over the whole document", sigs)
	}
}

// hybridPDF is a hybrid-reference file (ISO 32000-1, 7.5.8.4) written by
// hand. Its table holds object stream 1 and cross-reference stream 7;
// stream 7, which /XRefStm names, gives objects 2 to 6, the catalog first,
// as the objects of stream 1. The rows of stream 7, W
// [1 2 1], are 02 0001 00 to 02 0001 04, encoded with the PNG filters Sub,
// Up, Average, Paeth and None (PNG 1.2, 6.3), worked out by hand.
func hybridPDF(t *testing.T) []byte {
	t.Helper()
	objs := []string{"<</Type/Catalog/Pages 3 0 R>>", "<</Type/Pages/Kids[6 0 R]/Count 1>>", "<</Producer(hand)>>", "<<>>", "<</Type/Page/Parent 3 0 R/MediaBox[0 0 100 100]>>"}
	var header, body strings.Builder
	for i, o := range objs {
		fmt.Fprintf(&header, "%d %d ", i+2, body.Len())
		body.WriteString(o + " ")
	}
	rows := []byte{
		1, 0x02, 0xfe, 0x01, 0xff, // Sub
		2, 0x00, 0x00, 0x00, 0x01, // Up
		3, 0x01, 0xff, 0x01, 0x01, // Average
		4, 0x00, 0x00, 0x00, 0x01, // Paeth
		0, 0x02, 0x00, 0x01, 0x04, // None
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(rows); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	off1 := b.Len()
	fmt.Fprintf(&b, "1 0 obj\n<</Type/ObjStm/N %d/First %d/Length %d>>\nstream\n%s%s\nendstream\nendobj\n", len(objs), header.Len(), header.Len()+body.Len(), header.String(), body.String())
	off7 := b.Len()
	fmt.Fprintf(&b, "7 0 obj\n<</Type/XRef/Size 8/W[1 2 1]/Index[2 5]/Filter/FlateDecode/DecodeParms<</Predictor 12/Columns 4>>/Length %d>>\nstream\n", z.Len())
	b.Write(z.Bytes())
	b.WriteString("\nendstream\nendobj\n")
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 2\n0000000000 65535 f\r\n%010d 00000 n\r\n7 1\n%010d 00000 n\r\n", off1, off7)
	fmt.Fprintf(&b, "trailer\n<</Size 8/Root 2 0 R/Info 4 0 R/XRefStm %d>>\nstartxref\n%d\n%%%%EOF\n", off7, xref)
	return b.Bytes()
}

// In a hybrid file the objects of the /XRefStm stream fill the gaps of the
// table of the same revision.
func TestSignPAdESHybrid(t *testing.T) {
	s := newTestSigner(t)
	doc := hybridPDF(t)
	// a free entry in the table wins over the stream, as in poppler and pdf.js
	freed := bytes.Replace(doc, []byte("xref\n0 2\n"), []byte("xref\n2 1\n0000000000 00000 f\r\n0 2\n"), 1)
	if _, err := pki.SignPAdES(t.Context(), rand.Reader, freed, s.key, s.cert, pki.SignOptions{}, nil); err == nil {
		t.Error("SignPAdES(hybrid, catalog free in the table) error = nil, want error")
	}
	signed, err := pki.SignPAdES(t.Context(), rand.Reader, doc, s.key, s.cert, pki.SignOptions{}, nil)
	if err != nil {
		t.Fatalf("SignPAdES(hybrid) error = %v", err)
	}
	update, ok := strings.CutPrefix(string(signed), string(doc))
	if !ok || !strings.Contains(update, "\nxref\n") || !strings.Contains(update, "/Info 4 0 R") || !strings.Contains(update, "/P 6 0 R") {
		t.Errorf("SignPAdES(hybrid) update = %q, want an appended update with a field on page 6 and a table that keeps /Info", update[:min(len(update), 300)])
	}
	sigs, err := pki.VerifyPAdES(signed, nil)
	if err != nil {
		t.Fatalf("VerifyPAdES(SignPAdES(hybrid)) error = %v", err)
	}
	if len(sigs) != 1 || !sigs[0].CoversDocument {
		t.Errorf("VerifyPAdES(SignPAdES(hybrid)) = %+v, want one signature over the whole document", sigs)
	}
}
