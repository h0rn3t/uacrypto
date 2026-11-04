package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/pki"
)

var (
	oidOCSPBasic   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

func serial(t *testing.T, hex string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		t.Fatalf("bad serial %q", hex)
	}
	return n
}

// The responses in testdata are what the OCSP responders of CZO and monobank
// answered on 2026-11-04 to requests with Kupyna-256 CertIDs.
func TestParseOCSPResponseReal(t *testing.T) {
	tests := []struct {
		file, issuer string
		serial       string
		wantStatus   pki.OCSPStatus
		wantRevoked  time.Time
		wantReason   int
	}{
		{file: "ocsp-czo-good.der", issuer: "czo-2601.der", serial: "572B26CBD46D664A0100000001000000E7010000", wantStatus: pki.OCSPGood},
		{
			file: "ocsp-czo-revoked.der", issuer: "czo-2020.der", serial: "05E19E2CD92EA299020000000100000006010000",
			wantStatus: pki.OCSPRevoked, wantRevoked: time.Date(2021, 10, 7, 15, 56, 54, 0, time.UTC), wantReason: 4, // superseded
		},
		{file: "ocsp-monobank-good.der", issuer: "monobank-ca.der", serial: "107D4BC9551300004F9C20000000000148F70463", wantStatus: pki.OCSPGood},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			issuer := readCert(t, tt.issuer)
			sn := serial(t, tt.serial)
			resp, err := pki.ParseOCSPResponse(der, sn, issuer)
			if err != nil {
				t.Fatalf("ParseOCSPResponse(%s) error = %v", tt.file, err)
			}
			if resp.Status != tt.wantStatus || !resp.RevokedAt.Equal(tt.wantRevoked) || resp.RevocationReason != tt.wantReason {
				t.Errorf("ParseOCSPResponse(%s) = status %v, revoked %v reason %d, want %v, %v, %d",
					tt.file, resp.Status, resp.RevokedAt, resp.RevocationReason, tt.wantStatus, tt.wantRevoked, tt.wantReason)
			}
			if resp.SerialNumber.Cmp(sn) != 0 || !bytes.Equal(resp.Raw, der) {
				t.Errorf("ParseOCSPResponse(%s) serial %x, raw %d bytes, want %x and the response", tt.file, resp.SerialNumber, len(resp.Raw), sn)
			}
			if from, to := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC); resp.ProducedAt.Before(from) || resp.ProducedAt.After(to) || resp.ThisUpdate.IsZero() {
				t.Errorf("ParseOCSPResponse(%s) produced at %v, this update %v, want 2026-11-03..05", tt.file, resp.ProducedAt, resp.ThisUpdate)
			}
			if resp.Certificate == nil || !strings.Contains(resp.Certificate.Subject.CommonName, "OCSP") {
				t.Errorf("ParseOCSPResponse(%s) responder = %v, want the OCSP server certificate", tt.file, resp.Certificate)
			}

			if _, err := pki.ParseOCSPResponse(der, new(big.Int).Add(sn, big.NewInt(1)), issuer); err == nil {
				t.Errorf("ParseOCSPResponse(%s, other serial) error = nil, want error", tt.file)
			}
			if _, err := pki.ParseOCSPResponse(der, sn, readCert(t, "nbu-root-kupyna.der")); err == nil {
				t.Errorf("ParseOCSPResponse(%s, other issuer) error = nil, want error", tt.file)
			}
			i := bytes.Index(der, []byte("uacrypto-test-nonce")) // in the signed response data
			if i < 0 {
				t.Fatal("the request nonce is not in the response")
			}
			tampered := bytes.Clone(der)
			tampered[i] ^= 1
			if _, err := pki.ParseOCSPResponse(tampered, sn, issuer); !errors.Is(err, pki.ErrInvalidSignature) {
				t.Errorf("ParseOCSPResponse(%s with a changed byte) error = %v, want ErrInvalidSignature", tt.file, err)
			}
		})
	}
}

// fakeOCSP answers OCSP requests about certificates of issuer, signing as
// responder; mode selects the answer or a misbehaviour.
type fakeOCSP struct {
	issuer, responder *testSigner
	mode              string

	mu      sync.Mutex
	hashAlg asn1.ObjectIdentifier // of the last request's CertID
}

func (f *fakeOCSP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	var req struct {
		TBS struct {
			Requests []struct {
				CertID asn1.RawValue
			}
			Extensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
		}
	}
	if _, err := asn1.Unmarshal(body, &req); err != nil || len(req.TBS.Requests) != 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var certID struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		NameHash      []byte
		KeyHash       []byte
		Serial        *big.Int
	}
	if _, err := asn1.Unmarshal(req.TBS.Requests[0].CertID.FullBytes, &certID); err != nil {
		http.Error(w, "bad CertID", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.hashAlg = certID.HashAlgorithm.Algorithm
	f.mu.Unlock()

	var marshalErr error
	marshal := func(v any, params string) []byte {
		b, err := asn1.MarshalWithParams(v, params)
		marshalErr = errors.Join(marshalErr, err)
		return b
	}
	extensions := req.TBS.Extensions
	status := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0} // good
	responderID := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: f.responder.cert.RawSubject}
	switch f.mode {
	case "http error":
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	case "try later":
		_, _ = w.Write(marshal(struct{ Status asn1.Enumerated }{3}, "")) // the client reads what arrives
		return
	case "revoked":
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: append(
			marshal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "generalized"),
			marshal(asn1.Enumerated(1), "explicit,tag:0")...)} // keyCompromise
	case "unknown":
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2}
	case "by key":
		responderID = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: marshal(f.responder.cert.SubjectKeyId, "")}
	case "other serial":
		certID.Serial.Add(certID.Serial, big.NewInt(1))
		req.TBS.Requests[0].CertID = asn1.RawValue{FullBytes: marshal(certID, "")}
	case "other nonce":
		extensions = []pkix.Extension{{Id: oidOCSPNonce, Value: marshal([]byte("not the request nonce"), "")}}
	case "no nonce":
		extensions = nil
	}

	now := time.Now().UTC().Truncate(time.Second)
	tbs := marshal(struct {
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []any
		Extensions  []pkix.Extension `asn1:"optional,explicit,tag:1"`
	}{responderID, now, []any{struct {
		CertID     asn1.RawValue
		Status     asn1.RawValue
		ThisUpdate time.Time `asn1:"generalized"`
	}{req.TBS.Requests[0].CertID, status, now}}, extensions}, "")
	digest := gost34311.Sum(tbs)
	rv, sv, err := dstu4145.Sign(rand.Reader, f.responder.key, digest[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sig := marshal(dstu4145.MarshalSignature(f.responder.key.Public().Curve(), rv, sv), "")
	if f.mode == "bad signature" {
		sig[len(sig)-1] ^= 1
	}
	basic := marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
		Certs     []asn1.RawValue `asn1:"explicit,tag:0"`
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: oidLE}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}, []asn1.RawValue{{FullBytes: f.responder.cert.Raw}}}, "")
	type responseBytes struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}
	resp := marshal(struct {
		Status asn1.Enumerated
		Bytes  responseBytes `asn1:"explicit,tag:0"`
	}{0, responseBytes{oidOCSPBasic, basic}}, "")
	if marshalErr != nil {
		http.Error(w, marshalErr.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(resp) // the client reads what arrives
}

// newFakeOCSP starts a responder for the test CA issuer; the responder is the
// CA itself unless one is given.
func newFakeOCSP(t *testing.T, mode string, issuer, responder *testSigner) (*fakeOCSP, *httptest.Server) {
	t.Helper()
	if responder == nil {
		responder = issuer
	}
	f := &fakeOCSP{issuer: issuer, responder: responder, mode: mode}
	return f, httptest.NewTestServer(t, f)
}

func TestOCSPClient(t *testing.T) {
	issuer := newTestSigner(t)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1234)}
	tests := []struct {
		mode        string
		gost        bool
		wantStatus  pki.OCSPStatus
		wantRevoked time.Time
		wantReason  int
	}{
		{mode: "", wantStatus: pki.OCSPGood},
		{mode: "", gost: true, wantStatus: pki.OCSPGood},
		{mode: "by key", wantStatus: pki.OCSPGood},
		{mode: "revoked", wantStatus: pki.OCSPRevoked, wantRevoked: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), wantReason: 1},
		{mode: "unknown", wantStatus: pki.OCSPUnknown},
	}
	for _, tt := range tests {
		f, srv := newFakeOCSP(t, tt.mode, issuer, nil)
		client := &pki.OCSPClient{URL: "", HTTPClient: srv.Client(), GOST34311: tt.gost}
		withAIA := *cert
		withAIA.OCSPServer = []string{srv.URL} // Check takes the URL from the certificate
		resp, err := client.Check(t.Context(), &withAIA, issuer.cert)
		if err != nil {
			t.Errorf("Check(%q, GOST34311=%v) error = %v", tt.mode, tt.gost, err)
			continue
		}
		if resp.Status != tt.wantStatus || !resp.RevokedAt.Equal(tt.wantRevoked) || resp.RevocationReason != tt.wantReason {
			t.Errorf("Check(%q) = status %v, revoked %v reason %d, want %v, %v, %d",
				tt.mode, resp.Status, resp.RevokedAt, resp.RevocationReason, tt.wantStatus, tt.wantRevoked, tt.wantReason)
		}
		if !resp.Certificate.Equal(issuer.cert) || time.Since(resp.ProducedAt) > time.Minute {
			t.Errorf("Check(%q) responder %v produced at %v, want the CA now", tt.mode, resp.Certificate.Subject, resp.ProducedAt)
		}
		if again, err := pki.ParseOCSPResponse(resp.Raw, cert.SerialNumber, issuer.cert); err != nil || again.Status != resp.Status {
			t.Errorf("ParseOCSPResponse(Check(%q).Raw) = %v, %v, want the same status", tt.mode, again, err)
		}
		wantAlg := oidKupyna256
		if tt.gost {
			wantAlg = oidGOST34311
		}
		if !f.hashAlg.Equal(wantAlg) {
			t.Errorf("Check(GOST34311=%v) CertID hash %v, want %v", tt.gost, f.hashAlg, wantAlg)
		}
	}
}

func TestOCSPClientRejects(t *testing.T) {
	issuer := newTestSigner(t)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1234)}
	tests := []struct {
		name, mode string
		responder  *testSigner
		invalid    bool // the error is ErrInvalidSignature
	}{
		{name: "http error", mode: "http error"},
		{name: "try later", mode: "try later"},
		{name: "other serial", mode: "other serial"},
		{name: "other nonce", mode: "other nonce"},
		{name: "no nonce", mode: "no nonce"},
		{name: "bad signature", mode: "bad signature", invalid: true},
		// a certificate for OCSP signing that the CA did not sign; test
		// certificates share one name, so it fails on the CA's signature
		{name: "unauthorized responder", responder: newTestSigner(t, oidOCSPSigning), invalid: true},
		{name: "responder without OCSP signing", responder: newTestSigner(t, oidTimeStamp)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, srv := newFakeOCSP(t, tt.mode, issuer, tt.responder)
			client := &pki.OCSPClient{URL: srv.URL, HTTPClient: srv.Client()}
			resp, err := client.Check(t.Context(), cert, issuer.cert)
			if err == nil {
				t.Fatalf("Check(%s) = %+v, want error", tt.name, resp)
			}
			if got := errors.Is(err, pki.ErrInvalidSignature); got != tt.invalid {
				t.Errorf("Check(%s) error = %v, ErrInvalidSignature %v, want %v", tt.name, err, got, tt.invalid)
			}
		})
	}

	if _, err := (&pki.OCSPClient{}).Check(t.Context(), cert, issuer.cert); err == nil {
		t.Error("Check(certificate without an OCSP server, no URL) error = nil, want error")
	}
}
