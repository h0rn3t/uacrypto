package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/pki"
)

var (
	oidCertificateRefs = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 21}
	oidRevocationRefs  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 22}
	oidCertValues      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}
)

// testPath is a signer under an intermediate CA under a root; each CA runs
// an OCSP responder that the certificates it issued name.
type testPath struct {
	root, ca, leaf *testSigner
}

// newTestPath starts the responders; leafMode is the fakeOCSP mode of the
// CA's responder, the one that answers about the signer.
func newTestPath(t *testing.T, leafMode string) testPath {
	t.Helper()
	root := issueTestSigner(t, nil, "test root", "")
	_, rootOCSP := newFakeOCSP(t, "", root, nil)
	rootOCSP.Start() // OCSPClient dials the URL in the certificate with its own client
	ca := issueTestSigner(t, root, "test CA", rootOCSP.URL)
	_, caOCSP := newFakeOCSP(t, leafMode, ca, nil)
	caOCSP.Start()
	return testPath{root: root, ca: ca, leaf: issueTestSigner(t, ca, "test signer", caOCSP.URL)}
}

// cadesT signs content as the signer and stamps the signature.
func (p testPath) cadesT(t *testing.T, content []byte, gost bool) []byte {
	t.Helper()
	bes, err := pki.SignData(rand.Reader, content, p.leaf.key, p.leaf.cert, pki.SignOptions{GOST34311: gost})
	if err != nil {
		t.Fatal(err)
	}
	_, tsa := newFakeTSA(t, "")
	cadesT, err := pki.AddSignatureTimeStamp(t.Context(), bes, tsa)
	if err != nil {
		t.Fatal(err)
	}
	return cadesT
}

func TestAddValidationData(t *testing.T) {
	content := []byte("договір")
	for _, gost := range []bool{false, true} {
		p := newTestPath(t, "")
		cadesT := p.cadesT(t, content, gost)
		long, err := pki.AddValidationData(t.Context(), cadesT, []*x509.Certificate{p.ca.cert, p.root.cert}, &pki.OCSPClient{})
		if err != nil {
			t.Fatalf("AddValidationData(GOST34311=%v) error = %v", gost, err)
		}

		// the values make the signature self-contained: no certificates from the caller
		got, signers, err := pki.VerifySignedData(long, nil, nil)
		if err != nil {
			t.Fatalf("VerifySignedData(CAdES-X Long, GOST34311=%v) error = %v", gost, err)
		}
		if !bytes.Equal(got, content) || len(signers) != 1 {
			t.Fatalf("VerifySignedData(CAdES-X Long) = %q, %v", got, signers)
		}
		s := signers[0]
		if s.TimeStamp == nil {
			t.Error("VerifySignedData(CAdES-X Long) time-stamp = nil, want the CAdES-T one")
		}
		wantChain := []*x509.Certificate{p.leaf.cert, p.ca.cert, p.root.cert}
		if len(s.Chain) != len(wantChain) {
			t.Fatalf("VerifySignedData(CAdES-X Long) chain of %d certificates, want signer, CA, root", len(s.Chain))
		}
		for i, c := range wantChain {
			if !s.Chain[i].Equal(c) {
				t.Errorf("VerifySignedData(CAdES-X Long) chain[%d] = %s, want %s", i, s.Chain[i].Subject, c.Subject)
			}
		}
		if len(s.OCSP) != 2 {
			t.Fatalf("VerifySignedData(CAdES-X Long) %d OCSP responses, want one for the signer and one for the CA", len(s.OCSP))
		}
		for i, resp := range s.OCSP {
			if resp.Status != pki.OCSPGood || !resp.Certificate.Equal(wantChain[i+1]) {
				t.Errorf("VerifySignedData(CAdES-X Long) OCSP[%d] = status %v by %s, want good by %s", i, resp.Status, resp.Certificate.Subject, wantChain[i+1].Subject)
			}
		}

		// the references hash with the signer's digest algorithm, and a
		// reference that no longer matches its value is refused
		ref := kupyna.Sum256(p.ca.cert.Raw)
		if gost {
			ref = gost34311.Sum(p.ca.cert.Raw)
		}
		i := bytes.Index(long, ref[:])
		if i < 0 {
			t.Fatalf("AddValidationData(GOST34311=%v) has no reference to the CA certificate with the signer's hash", gost)
		}
		tampered := bytes.Clone(long)
		tampered[i] ^= 1
		if _, _, err := pki.VerifySignedData(tampered, nil, nil); err == nil {
			t.Errorf("VerifySignedData(CAdES-X Long with a changed certificate reference, GOST34311=%v) error = nil, want error", gost)
		}

		_, signers, err = pki.VerifySignedData(cadesT, nil, nil)
		if err != nil || signers[0].Chain != nil || signers[0].OCSP != nil {
			t.Errorf("VerifySignedData(CAdES-T) = chain %v, OCSP %v, %v, want none", signers[0].Chain, signers[0].OCSP, err)
		}
	}
}

func TestAddValidationDataRejects(t *testing.T) {
	content := []byte("договір")
	good := newTestPath(t, "")
	revoked := newTestPath(t, "revoked")
	unknown := newTestPath(t, "unknown")
	long, err := pki.AddValidationData(t.Context(), good.cadesT(t, content, false), []*x509.Certificate{good.ca.cert, good.root.cert}, &pki.OCSPClient{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		signed []byte
		certs  []*x509.Certificate
	}{
		{"CAdES-BES", mustSign(t, good.leaf, content), []*x509.Certificate{good.ca.cert, good.root.cert}},
		{"CAdES-X Long", long, []*x509.Certificate{good.ca.cert, good.root.cert}},
		{"no CA certificate", good.cadesT(t, content, false), []*x509.Certificate{good.root.cert}},
		{"no root", good.cadesT(t, content, false), []*x509.Certificate{good.ca.cert}},
		{"revoked signer", revoked.cadesT(t, content, false), []*x509.Certificate{revoked.ca.cert, revoked.root.cert}},
		{"unknown signer", unknown.cadesT(t, content, false), []*x509.Certificate{unknown.ca.cert, unknown.root.cert}},
	}
	for _, tt := range tests {
		if got, err := pki.AddValidationData(t.Context(), tt.signed, tt.certs, &pki.OCSPClient{}); err == nil {
			t.Errorf("AddValidationData(%s) = %d bytes, want error", tt.name, len(got))
		}
	}
}

// The czo-test-*.p7s files are the ЦЗО test examples of IIT signatures: plain
// CAdES-X Long carries the signer's OCSP response without the responder
// certificate and a time-stamp token without the TSA certificate, as a
// verifier with the CA certificate bundle expects; -full carries both and the
// CA's OCSP response too.
func TestVerifySignedDataCZO(t *testing.T) {
	tsa := readCert(t, "czo-test-tsa.der")
	ocspCA := readCert(t, "czo-test-ocsp-ca.der")
	ocspRoot := readCert(t, "czo-test-ocsp-root.der")
	bundle := []*x509.Certificate{tsa, ocspCA, ocspRoot}
	tests := []struct {
		file      string
		certs     []*x509.Certificate
		wantChain []string // common names, signer first
		wantOCSP  []string // responder per chain link, "" for none
	}{
		{file: "czo-test-t-kupyna.p7s", certs: bundle},
		{file: "czo-test-c-gost.p7s", certs: bundle},
		{
			file: "czo-test-xlong-kupyna.p7s", certs: bundle,
			wantChain: []string{"ТЕСТ Тестовий Тест Тестович", "Адміністратор ІТС ЦЗО (CA TEST)", "Центральний засвідчувальний орган (ROOT TEST)"},
			wantOCSP:  []string{"OCSP-сервер Адміністратора ІТС ЦЗО (CA TEST)", ""},
		},
		{
			file: "czo-test-xlong-gost.p7s", certs: bundle,
			wantChain: []string{"ТЕСТ Тестовий Тест Тестович", "Адміністратор ІТС ЦЗО (CA TEST)", "Центральний засвідчувальний орган (ROOT TEST)"},
			wantOCSP:  []string{"OCSP-сервер Адміністратора ІТС ЦЗО (CA TEST)", ""},
		},
		{
			file:      "czo-test-xlong-full-kupyna.p7s",
			wantChain: []string{"ТЕСТ Тестовий Тест Тестович", "Адміністратор ІТС ЦЗО (CA TEST)", "Центральний засвідчувальний орган (ROOT TEST)"},
			wantOCSP:  []string{"OCSP-сервер Адміністратора ІТС ЦЗО (CA TEST)", "OCSP-сервер Центрального засвідчувального органу (ROOT TEST)"},
		},
		{
			file:      "czo-test-xlong-full-gost.p7s",
			wantChain: []string{"ТЕСТ Тестовий Тест Тестович", "Адміністратор ІТС ЦЗО (CA TEST)", "Центральний засвідчувальний орган (ROOT TEST)"},
			wantOCSP:  []string{"OCSP-сервер Адміністратора ІТС ЦЗО (CA TEST)", "OCSP-сервер Центрального засвідчувального органу (ROOT TEST)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, signers, err := pki.VerifySignedData(der, nil, tt.certs)
			if err != nil {
				t.Fatalf("VerifySignedData(%s) error = %v", tt.file, err)
			}
			if string(got) != "Test\r\n" || len(signers) != 1 {
				t.Fatalf("VerifySignedData(%s) = %q, %d signers, want \"Test\\r\\n\" and one", tt.file, got, len(signers))
			}
			s := signers[0]
			if s.TimeStamp == nil || !s.TimeStamp.Certificate.Equal(tsa) {
				t.Errorf("VerifySignedData(%s) time-stamp = %+v, want one by the ЦЗО test TSA", tt.file, s.TimeStamp)
			}
			var chain []string
			for _, c := range s.Chain {
				chain = append(chain, c.Subject.CommonName)
			}
			if !slices.Equal(chain, tt.wantChain) {
				t.Errorf("VerifySignedData(%s) chain = %q, want %q", tt.file, chain, tt.wantChain)
			}
			var responders []string
			for i, r := range s.OCSP {
				if r == nil {
					responders = append(responders, "")
					continue
				}
				responders = append(responders, r.Certificate.Subject.CommonName)
				if r.Status != pki.OCSPGood || r.SerialNumber.Cmp(s.Chain[i].SerialNumber) != 0 {
					t.Errorf("VerifySignedData(%s) OCSP[%d] = status %v about %x, want good about chain[%d]", tt.file, i, r.Status, r.SerialNumber, i)
				}
			}
			if !slices.Equal(responders, tt.wantOCSP) {
				t.Errorf("VerifySignedData(%s) OCSP responders = %q, want %q", tt.file, responders, tt.wantOCSP)
			}
		})
	}

	// without the bundle the TSA certificate of plain CAdES-X Long is unknown
	der, err := os.ReadFile(filepath.Join("testdata", "czo-test-xlong-kupyna.p7s"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pki.VerifySignedData(der, nil, nil); err == nil {
		t.Error("VerifySignedData(czo-test-xlong-kupyna.p7s, no certificates) error = nil, want the TSA certificate missing")
	}
}

// AddValidationData writes the attributes as IIT does: one CrlOcspRef per
// certificate of the path, the root's empty; certValues and
// completeCertificateRefs over the CAs only, each reference with issuerSerial.
func TestAddValidationDataLayout(t *testing.T) {
	p := newTestPath(t, "")
	long, err := pki.AddValidationData(t.Context(), p.cadesT(t, []byte("договір"), false), []*x509.Certificate{p.ca.cert, p.root.cert}, &pki.OCSPClient{})
	if err != nil {
		t.Fatal(err)
	}
	attrs := unsignedAttrs(t, long)

	var revocationRefs []struct {
		CRLs asn1.RawValue `asn1:"optional,tag:0"`
		OCSP struct {
			Responses []asn1.RawValue
		} `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(attrs[oidRevocationRefs.String()], &revocationRefs); err != nil {
		t.Fatalf("completeRevocationRefs: %v", err)
	}
	var ocspIDs []int
	for _, ref := range revocationRefs {
		ocspIDs = append(ocspIDs, len(ref.OCSP.Responses))
	}
	if want := []int{1, 1, 0}; !slices.Equal(ocspIDs, want) {
		t.Errorf("AddValidationData() completeRevocationRefs OCSP ids per certificate = %v, want %v (signer, CA, root)", ocspIDs, want)
	}

	var certValues []asn1.RawValue
	if _, err := asn1.Unmarshal(attrs[oidCertValues.String()], &certValues); err != nil {
		t.Fatalf("certValues: %v", err)
	}
	if len(certValues) != 2 || !bytes.Equal(certValues[0].FullBytes, p.ca.cert.Raw) || !bytes.Equal(certValues[1].FullBytes, p.root.cert.Raw) {
		t.Errorf("AddValidationData() certValues has %d certificates, want the CA and the root", len(certValues))
	}

	var certRefs []struct {
		Hash         asn1.RawValue
		IssuerSerial struct {
			Issuer []asn1.RawValue
			Serial *big.Int
		} `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(attrs[oidCertificateRefs.String()], &certRefs); err != nil {
		t.Fatalf("completeCertificateRefs: %v", err)
	}
	for i, ref := range certRefs {
		want := []*x509.Certificate{p.ca.cert, p.root.cert}[i]
		if len(ref.IssuerSerial.Issuer) != 1 || !bytes.Equal(ref.IssuerSerial.Issuer[0].Bytes, want.RawIssuer) || ref.IssuerSerial.Serial.Cmp(want.SerialNumber) != 0 {
			t.Errorf("AddValidationData() completeCertificateRefs[%d] issuerSerial = %+v, want the issuer and serial of %s", i, ref.IssuerSerial, want.Subject)
		}
	}
}

// unsignedAttrs returns the first value of each unsigned attribute of the
// first signer of der by attribute type.
func unsignedAttrs(t *testing.T, der []byte) map[string][]byte {
	t.Helper()
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		Encap            asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      []struct {
			Version            int
			SID                asn1.RawValue
			DigestAlgorithm    asn1.RawValue
			SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
			SignatureAlgorithm asn1.RawValue
			Signature          []byte
			UnsignedAttrs      []attribute `asn1:"optional,set,tag:1"`
		} `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	attrs := make(map[string][]byte)
	for _, a := range sd.SignerInfos[0].UnsignedAttrs {
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(a.Values.Bytes, &value); err != nil {
			t.Fatal(err)
		}
		attrs[a.Type.String()] = value.FullBytes
	}
	return attrs
}
