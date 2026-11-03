package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/pki"
)

var (
	oidTSTInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidKupyna256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1}
	oidTimeStamp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

func TestVerifyTimeStampTSA(t *testing.T) {
	for _, file := range []string{"tsa-tax-gost.p7s", "tsa-privatbank-gost.p7s", "tsa-diia-kupyna.p7s"} {
		t.Run(file, func(t *testing.T) {
			token, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			ts, err := pki.VerifyTimeStamp(token, []byte(tsaMessage))
			if err != nil {
				t.Fatalf("VerifyTimeStamp(%s) error = %v", file, err)
			}
			// the tokens were requested on 2026-11-04 Kyiv time
			if from, to := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC); ts.Time.Before(from) || ts.Time.After(to) {
				t.Errorf("VerifyTimeStamp(%s) time = %v, want 2026-11-03..05", file, ts.Time)
			}
			if ts.Certificate == nil || ts.SerialNumber == nil || len(ts.Policy) == 0 {
				t.Errorf("VerifyTimeStamp(%s) = %+v, want TSA certificate, serial number and policy", file, ts)
			}
			if _, err := pki.VerifyTimeStamp(token, []byte("other data")); !errors.Is(err, pki.ErrInvalidSignature) {
				t.Errorf("VerifyTimeStamp(%s, other data) error = %v, want ErrInvalidSignature", file, err)
			}
		})
	}
}

// fakeTSA answers RFC 3161 requests with tokens signed by its test key; mode
// selects a misbehaviour.
type fakeTSA struct {
	signer *testSigner
	mode   string

	mu         sync.Mutex
	imprintAlg asn1.ObjectIdentifier // of the last request
	lastToken  []byte
}

func (f *fakeTSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	var req struct {
		Version int
		Imprint struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		Nonce   *big.Int `asn1:"optional"`
		CertReq bool     `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch f.mode {
	case "http error":
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	case "rejected":
		resp, _ := asn1.Marshal(struct{ Status struct{ Status int } }{struct{ Status int }{2}})
		_, _ = w.Write(resp) // the client reads what arrives
		return
	case "other nonce":
		req.Nonce = new(big.Int).Add(req.Nonce, big.NewInt(1))
	case "no nonce":
		req.Nonce = nil
	case "other data":
		req.Imprint.Digest[0] ^= 1
	}

	tst, err := asn1.Marshal(struct {
		Version int
		Policy  asn1.ObjectIdentifier
		Imprint any
		Serial  *big.Int
		GenTime time.Time `asn1:"generalized"`
		Nonce   *big.Int  `asn1:"optional"`
	}{1, asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 2, 3, 1}, req.Imprint, big.NewInt(42), time.Now().UTC().Truncate(time.Second), req.Nonce})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, err := pki.SignContent(rand.Reader, oidTSTInfo, tst, f.signer.key, f.signer.cert, pki.SignOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := asn1.Marshal(struct {
		Status struct{ Status int }
		Token  asn1.RawValue
	}{struct{ Status int }{0}, asn1.RawValue{FullBytes: token}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.imprintAlg, f.lastToken = req.Imprint.Algorithm.Algorithm, token
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(resp) // the client reads what arrives
}

func newFakeTSA(t *testing.T, mode string, eku ...asn1.ObjectIdentifier) (*fakeTSA, *pki.TSAClient) {
	t.Helper()
	if eku == nil {
		eku = []asn1.ObjectIdentifier{oidTimeStamp}
	}
	f := &fakeTSA{signer: newTestSigner(t, eku...), mode: mode}
	srv := httptest.NewTestServer(t, f)
	return f, &pki.TSAClient{URL: srv.URL, HTTPClient: srv.Client()}
}

func TestTSAClient(t *testing.T) {
	data := []byte("що засвідчити")
	for _, gost := range []bool{false, true} {
		f, client := newFakeTSA(t, "")
		client.GOST34311 = gost
		token, ts, err := client.TimeStamp(t.Context(), data)
		if err != nil {
			t.Fatalf("TimeStamp(GOST34311=%v) error = %v", gost, err)
		}
		if time.Since(ts.Time) > time.Minute || ts.SerialNumber.Int64() != 42 || !ts.Certificate.Equal(f.signer.cert) {
			t.Errorf("TimeStamp(GOST34311=%v) = %+v, want the fake TSA's stamp of now", gost, ts)
		}
		if _, err := pki.VerifyTimeStamp(token, data); err != nil {
			t.Errorf("VerifyTimeStamp(TimeStamp token) error = %v", err)
		}
		wantAlg := oidKupyna256
		if gost {
			wantAlg = oidGOST34311
		}
		if !f.imprintAlg.Equal(wantAlg) {
			t.Errorf("TimeStamp(GOST34311=%v) requested %v, want %v", gost, f.imprintAlg, wantAlg)
		}
	}
}

func TestTSAClientRejects(t *testing.T) {
	tests := []struct {
		name, mode string
		eku        []asn1.ObjectIdentifier
		invalid    bool // the error is ErrInvalidSignature
	}{
		{name: "http error", mode: "http error"},
		{name: "rejected", mode: "rejected"},
		{name: "other nonce", mode: "other nonce"},
		{name: "no nonce", mode: "no nonce"},
		{name: "other data", mode: "other data", invalid: true},
		{name: "not a TSA certificate", eku: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 4}}}, // e-mail protection
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, client := newFakeTSA(t, tt.mode, tt.eku...)
			token, _, err := client.TimeStamp(t.Context(), []byte("data"))
			if err == nil {
				t.Fatalf("TimeStamp(%s) = %x, want error", tt.name, token)
			}
			if got := errors.Is(err, pki.ErrInvalidSignature); got != tt.invalid {
				t.Errorf("TimeStamp(%s) error = %v, ErrInvalidSignature %v, want %v", tt.name, err, got, tt.invalid)
			}
		})
	}
}

func TestAddSignatureTimeStamp(t *testing.T) {
	s := newTestSigner(t)
	content := []byte("договір")
	for _, gost := range []bool{false, true} {
		f, client := newFakeTSA(t, "")
		bes, err := pki.SignData(rand.Reader, content, s.key, s.cert, pki.SignOptions{GOST34311: gost})
		if err != nil {
			t.Fatal(err)
		}
		cadesT, err := pki.AddSignatureTimeStamp(t.Context(), bes, client)
		if err != nil {
			t.Fatalf("AddSignatureTimeStamp(GOST34311=%v) error = %v", gost, err)
		}
		got, signers, err := pki.VerifySignedData(cadesT, nil, nil)
		if err != nil {
			t.Fatalf("VerifySignedData(CAdES-T, GOST34311=%v) error = %v", gost, err)
		}
		if !bytes.Equal(got, content) || len(signers) != 1 {
			t.Fatalf("VerifySignedData(CAdES-T) = %q, %v", got, signers)
		}
		if signers[0].TimeStamp == nil || !signers[0].TimeStamp.Certificate.Equal(f.signer.cert) {
			t.Errorf("VerifySignedData(CAdES-T, GOST34311=%v) time-stamp = %+v, want the fake TSA's", gost, signers[0].TimeStamp)
		}
		if time.Since(signers[0].SigningTime) > time.Minute {
			t.Errorf("VerifySignedData(CAdES-T) signing time = %v, want now", signers[0].SigningTime)
		}
		wantAlg := oidKupyna256
		if gost {
			wantAlg = oidGOST34311
		}
		if !f.imprintAlg.Equal(wantAlg) {
			t.Errorf("AddSignatureTimeStamp(GOST34311=%v) stamped with %v, want the signer's %v", gost, f.imprintAlg, wantAlg)
		}

		// a changed byte in the embedded token breaks the CAdES-T signature
		i := bytes.Index(cadesT, f.lastToken)
		if i < 0 {
			t.Fatal("the TSA token is not in the CAdES-T signature")
		}
		tampered := bytes.Clone(cadesT)
		tampered[i+len(f.lastToken)-1] ^= 1
		if _, _, err := pki.VerifySignedData(tampered, nil, nil); err == nil {
			t.Errorf("VerifySignedData(CAdES-T with a changed token, GOST34311=%v) error = nil, want error", gost)
		}
	}

	_, signers, err := pki.VerifySignedData(mustSign(t, s, content), nil, nil)
	if err != nil || signers[0].TimeStamp != nil {
		t.Errorf("VerifySignedData(CAdES-BES) time-stamp = %+v, %v, want none", signers, err)
	}
}

func mustSign(t *testing.T, s *testSigner, content []byte) []byte {
	t.Helper()
	der, err := pki.SignData(rand.Reader, content, s.key, s.cert, pki.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return der
}
