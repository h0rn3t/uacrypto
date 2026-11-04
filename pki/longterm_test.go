package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/pki"
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
