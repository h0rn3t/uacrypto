package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/pki"
)

var (
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidTSAPolicy = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 2, 3, 1}
)

// newTestTSA issues a TSA certificate under a fresh root with CreateCertificate.
func newTestTSA(t *testing.T) (*x509.Certificate, *dstu4145.PrivateKey) {
	t.Helper()
	root, rootKey := newTestRoot(t)
	key := newKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	der, err := pki.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(20),
		Subject:      pkix.Name{CommonName: "TSP-сервер"},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}, root, marshalKey(t, key), rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(TSA) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// timeStampRequest builds a TimeStampReq over a SHA-256 hash of 32 zero bytes.
func timeStampRequest(t *testing.T, policy asn1.ObjectIdentifier, nonce *big.Int, certReq bool, extensions []pkix.Extension) []byte {
	t.Helper()
	return mustMarshal(t, struct {
		Version int
		Imprint struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		Policy     asn1.ObjectIdentifier `asn1:"optional"`
		Nonce      *big.Int              `asn1:"optional"`
		CertReq    bool                  `asn1:"optional"`
		Extensions []pkix.Extension      `asn1:"optional,tag:0"`
	}{1, struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}{pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, make([]byte, 32)}, policy, nonce, certReq, extensions})
}

func TestParseTimeStampRequest(t *testing.T) {
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 99}, Value: []byte{1, 2}}
	der := timeStampRequest(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}, big.NewInt(4242), true, []pkix.Extension{ext})
	for name, in := range map[string][]byte{"DER": der, "BER": toBER(t, der)} {
		req, err := pki.ParseTimeStampRequest(in)
		if err != nil {
			t.Fatalf("ParseTimeStampRequest(%s) error = %v", name, err)
		}
		if !req.HashAlgorithm.Algorithm.Equal(oidSHA256) || !bytes.Equal(req.HashedMessage, make([]byte, 32)) ||
			!req.Policy.Equal(asn1.ObjectIdentifier{1, 2, 3, 4, 5}) || req.Nonce.Int64() != 4242 || !req.CertReq ||
			len(req.Extensions) != 1 || !req.Extensions[0].Id.Equal(ext.Id) {
			t.Errorf("ParseTimeStampRequest(%s) = %+v, want every field of the request", name, req)
		}
	}
	req, err := pki.ParseTimeStampRequest(timeStampRequest(t, nil, nil, false, nil))
	if err != nil || req.Policy != nil || req.Nonce != nil || req.CertReq || req.Extensions != nil {
		t.Errorf("ParseTimeStampRequest(imprint only) = %+v, %v, want no policy, nonce, certReq or extensions", req, err)
	}
	for name, in := range map[string][]byte{"empty": nil, "garbage": {1, 2, 3}} {
		if req, err := pki.ParseTimeStampRequest(in); err == nil {
			t.Errorf("ParseTimeStampRequest(%s) = %+v, want error", name, req)
		}
	}
}

// tstInfo returns the TSTInfo fields of the token in a granted
// TimeStampResp, verified with the TSA certificate tsa, and whether the
// token carries the certificate.
func tstInfo(t *testing.T, resp []byte, tsa *x509.Certificate) (fields []asn1.RawValue, certificates bool) {
	t.Helper()
	var r struct {
		Status struct{ Status int }
		Token  asn1.RawValue
	}
	if _, err := asn1.Unmarshal(resp, &r); err != nil || r.Status.Status != 0 {
		t.Fatalf("TimeStampResp status %d: %v", r.Status.Status, err)
	}
	content, _, err := pki.VerifySignedData(r.Token.FullBytes, nil, []*x509.Certificate{tsa})
	if err != nil {
		t.Fatalf("VerifySignedData(token) error = %v", err)
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(content, &seq); err != nil {
		t.Fatal(err)
	}
	for rest := seq.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, f)
	}
	certs, err := pki.ParseCertificateBundle(r.Token.FullBytes)
	if err != nil {
		t.Fatal(err)
	}
	return fields, len(certs) > 0
}

func TestCreateTimeStampResponse(t *testing.T) {
	cert, key := newTestTSA(t)
	ts := &pki.TimeStamp{Time: time.Now(), SerialNumber: big.NewInt(99), Policy: oidTSAPolicy, Certificate: cert}
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 99}, Value: []byte{1, 2}}
	tests := []struct {
		name       string
		req        []byte
		wantPolicy asn1.ObjectIdentifier
		wantCert   bool
		wantLast   []byte // the last TSTInfo field
	}{
		{"default policy, no certReq", timeStampRequest(t, nil, nil, false, nil), oidTSAPolicy, false, nil},
		{"policy of the request", timeStampRequest(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}, nil, false, nil), asn1.ObjectIdentifier{1, 2, 3, 4, 5}, false, nil},
		{"certReq", timeStampRequest(t, nil, nil, true, nil), oidTSAPolicy, true, nil},
		{"nonce echoed", timeStampRequest(t, nil, big.NewInt(4242), false, nil), oidTSAPolicy, false, mustMarshal(t, big.NewInt(4242))},
		{"extensions copied", timeStampRequest(t, nil, nil, false, []pkix.Extension{ext}), oidTSAPolicy, false,
			append([]byte{0xa1, 0x0c}, mustMarshal(t, ext)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := pki.ParseTimeStampRequest(tt.req)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := pki.CreateTimeStampResponse(rand.Reader, req, ts, key)
			if err != nil {
				t.Fatalf("CreateTimeStampResponse(%s) error = %v", tt.name, err)
			}
			fields, withCert := tstInfo(t, resp, cert)
			var policy asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(fields[1].FullBytes, &policy); err != nil || !policy.Equal(tt.wantPolicy) {
				t.Errorf("CreateTimeStampResponse(%s) policy = %v, want %v", tt.name, policy, tt.wantPolicy)
			}
			if withCert != tt.wantCert {
				t.Errorf("CreateTimeStampResponse(%s) carries the TSA certificate: %v, want %v", tt.name, withCert, tt.wantCert)
			}
			if !bytes.Equal(fields[2].FullBytes, mustMarshal(t, struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}{req.HashAlgorithm, req.HashedMessage})) {
				t.Errorf("CreateTimeStampResponse(%s) imprint = %x, want the request's", tt.name, fields[2].FullBytes)
			}
			if last := fields[len(fields)-1].FullBytes; tt.wantLast != nil && !bytes.Equal(last, tt.wantLast) {
				t.Errorf("CreateTimeStampResponse(%s) last TSTInfo field = %x, want %x", tt.name, last, tt.wantLast)
			}
		})
	}

	// an unsupported digest is refused with badAlg, as Bouncy Castle refuses it
	req, err := pki.ParseTimeStampRequest(mustMarshal(t, struct {
		Version int
		Imprint struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
	}{1, struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, make([]byte, 20)}}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pki.CreateTimeStampResponse(rand.Reader, req, ts, key)
	if err != nil {
		t.Fatalf("CreateTimeStampResponse(SHA-1) error = %v, want a rejection", err)
	}
	var rejection struct {
		Status struct {
			Status   int
			Text     []asn1.RawValue `asn1:"optional"`
			FailInfo asn1.BitString  `asn1:"optional"`
		}
	}
	if _, err := asn1.Unmarshal(resp, &rejection); err != nil || rejection.Status.Status != 2 || rejection.Status.FailInfo.At(0) != 1 {
		t.Errorf("CreateTimeStampResponse(SHA-1) = %x, want rejection (2) with badAlg", resp)
	}

	sha256Req, err := pki.ParseTimeStampRequest(timeStampRequest(t, nil, nil, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.CreateTimeStampResponse(rand.Reader, sha256Req, ts, newKey(t)); err == nil {
		t.Error("CreateTimeStampResponse(key of another certificate) error = nil, want error")
	}
}

// The TSA client accepts what CreateTimeStampResponse issues: signature,
// time-stamping certificate, imprint and nonce.
func TestCreateTimeStampResponseTSAClient(t *testing.T) {
	cert, key := newTestTSA(t)
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := pki.ParseTimeStampRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := pki.CreateTimeStampResponse(rand.Reader, req, &pki.TimeStamp{Time: time.Now(), SerialNumber: big.NewInt(7), Policy: oidTSAPolicy, Certificate: cert}, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(resp) // the client reads what arrives
	}))
	for _, gost := range []bool{false, true} {
		client := &pki.TSAClient{URL: "http://tsa.example/", HTTPClient: srv.Client(), GOST34311: gost}
		token, ts, err := client.TimeStamp(t.Context(), []byte("договір"))
		if err != nil {
			t.Fatalf("TimeStamp(GOST34311=%v) error = %v", gost, err)
		}
		if !ts.Certificate.Equal(cert) || ts.SerialNumber.Int64() != 7 || !ts.Policy.Equal(oidTSAPolicy) || time.Since(ts.Time) > time.Minute {
			t.Errorf("TimeStamp(GOST34311=%v) = %+v, want the test TSA's stamp of now", gost, ts)
		}
		if _, err := pki.VerifyTimeStamp(token, []byte("договір")); err != nil {
			t.Errorf("VerifyTimeStamp(token) error = %v", err)
		}
	}
}
