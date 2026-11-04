package pki_test

import (
	"crypto/md5" //nolint:gosec // G501: CertID hashes of MD5 are identifiers that clients compute
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is the usual CertID hash of RFC 6960
	"crypto/sha256"
	"crypto/sha3"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/pki"
)

// issuerHashes returns the name and key hashes of a CertID of issuer under sum.
func issuerHashes(t *testing.T, issuer *x509.Certificate, sum func([]byte) []byte) (name, key []byte) {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	return sum(issuer.RawSubject), sum(spki.PublicKey.RightAlign())
}

// ocspRequest builds an OCSP request about serial of issuer with the CertID hashed by alg.
func ocspRequest(t *testing.T, alg asn1.ObjectIdentifier, nameHash, keyHash []byte, serial *big.Int, nonce []byte) []byte {
	t.Helper()
	type certID struct {
		Algorithm pkix.AlgorithmIdentifier
		NameHash  []byte
		KeyHash   []byte
		Serial    *big.Int
	}
	type request struct{ CertID certID }
	tbs := struct {
		Requests   []request
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
	}{Requests: []request{{certID{pkix.AlgorithmIdentifier{Algorithm: alg}, nameHash, keyHash, serial}}}}
	if nonce != nil {
		tbs.Extensions = []pkix.Extension{{Id: oidOCSPNonce, Value: mustMarshal(t, nonce)}}
	}
	return mustMarshal(t, struct{ TBS any }{tbs})
}

func TestOCSPCertIDIssuedBy(t *testing.T) {
	issuer := readCert(t, "czo-2601.der")
	other := readCert(t, "czo-2020.der")
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		sum  func([]byte) []byte
	}{
		{"GOST 34.311", oidGOST34311, func(b []byte) []byte { h := gost34311.Sum(b); return h[:] }},
		{"Kupyna-256", oidKupyna256, func(b []byte) []byte { h := kupyna.Sum256(b); return h[:] }},
		{"Kupyna-512", asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 3}, func(b []byte) []byte { h := kupyna.Sum512(b); return h[:] }},
		{"SHA-1", asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, func(b []byte) []byte { h := sha1.Sum(b); return h[:] }}, //nolint:gosec // G401: see the import
		{"SHA-224", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}, func(b []byte) []byte { h := sha256.Sum224(b); return h[:] }},
		{"SHA-256", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }},
		{"SHA3-256", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}, func(b []byte) []byte { h := sha3.Sum256(b); return h[:] }},
		{"MD5", asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}, func(b []byte) []byte { h := md5.Sum(b); return h[:] }}, //nolint:gosec // G401: see the import
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, key := issuerHashes(t, issuer, tt.sum)
			req, err := pki.ParseOCSPRequest(ocspRequest(t, tt.oid, name, key, big.NewInt(5), nil))
			if err != nil {
				t.Fatalf("ParseOCSPRequest(%s CertID) error = %v", tt.name, err)
			}
			id := req.CertIDs[0]
			if ok, err := id.IssuedBy(issuer); !ok || err != nil {
				t.Errorf("IssuedBy(the issuer) under %s = %v, %v, want true", tt.name, ok, err)
			}
			if ok, err := id.IssuedBy(other); ok || err != nil {
				t.Errorf("IssuedBy(another CA) under %s = %v, %v, want false", tt.name, ok, err)
			}
		})
	}

	req, err := pki.ParseOCSPRequest(ocspRequest(t, asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{1}, []byte{2}, big.NewInt(5), nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := req.CertIDs[0].IssuedBy(issuer); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		t.Errorf("IssuedBy(CertID hashed by 1.2.3.4) error = %v, want x509.ErrUnsupportedAlgorithm", err)
	}
}

func TestParseOCSPRequest(t *testing.T) {
	der := ocspRequest(t, oidKupyna256, []byte{1, 2}, []byte{3, 4}, big.NewInt(77), []byte("nonce"))
	for name, in := range map[string][]byte{"DER": der, "BER": toBER(t, der)} {
		req, err := pki.ParseOCSPRequest(in)
		if err != nil {
			t.Fatalf("ParseOCSPRequest(%s) error = %v", name, err)
		}
		if len(req.CertIDs) != 1 || req.CertIDs[0].SerialNumber.Int64() != 77 || !req.CertIDs[0].HashAlgorithm.Equal(oidKupyna256) ||
			string(req.CertIDs[0].IssuerNameHash) != "\x01\x02" || string(req.CertIDs[0].IssuerKeyHash) != "\x03\x04" {
			t.Errorf("ParseOCSPRequest(%s) CertIDs = %+v, want serial 77 under Kupyna-256", name, req.CertIDs)
		}
		if len(req.Extensions) != 1 || !req.Extensions[0].Id.Equal(oidOCSPNonce) {
			t.Errorf("ParseOCSPRequest(%s) extensions = %+v, want the nonce", name, req.Extensions)
		}
		if want := "\x04\x05nonce"; string(req.Nonce) != want { // the extension value: an OCTET STRING
			t.Errorf("ParseOCSPRequest(%s) nonce = %x, want %x", name, req.Nonce, want)
		}
	}
	if req, err := pki.ParseOCSPRequest(ocspRequest(t, oidKupyna256, []byte{1}, []byte{2}, big.NewInt(77), nil)); err != nil || req.Nonce != nil {
		t.Errorf("ParseOCSPRequest(no nonce) nonce = %x, %v, want nil", req.Nonce, err)
	}

	// version, requestorName and a signature, which a responder may ignore;
	// encoding/asn1 does not wrap a RawValue in an explicit tag, so the tags are written here
	explicit := func(tag int, inner []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
	}
	directoryName := mustMarshal(t, explicit(4, mustMarshal(t, pkix.Name{CommonName: "client"}.ToRDNSequence())))
	certID := mustMarshal(t, struct {
		Algorithm pkix.AlgorithmIdentifier
		NameHash  []byte
		KeyHash   []byte
		Serial    *big.Int
	}{pkix.AlgorithmIdentifier{Algorithm: oidGOST34311}, []byte{1}, []byte{2}, big.NewInt(9)})
	tbs := mustMarshal(t, struct {
		Version   asn1.RawValue
		Requestor asn1.RawValue
		Requests  []struct{ CertID asn1.RawValue }
	}{explicit(0, mustMarshal(t, 0)), explicit(1, directoryName), []struct{ CertID asn1.RawValue }{{asn1.RawValue{FullBytes: certID}}}})
	signature := mustMarshal(t, struct{ Algorithm pkix.AlgorithmIdentifier }{pkix.AlgorithmIdentifier{Algorithm: oidDSTULE}})
	signed := mustMarshal(t, struct{ TBS, Signature asn1.RawValue }{asn1.RawValue{FullBytes: tbs}, explicit(0, signature)})
	if req, err := pki.ParseOCSPRequest(signed); err != nil || len(req.CertIDs) != 1 || req.CertIDs[0].SerialNumber.Int64() != 9 {
		t.Errorf("ParseOCSPRequest(signed, with version and requestor) = %+v, %v, want serial 9", req, err)
	}

	for name, in := range map[string][]byte{"empty": nil, "garbage": {1, 2, 3}, "no requests": mustMarshal(t, struct {
		TBS struct{ Requests []asn1.RawValue }
	}{})} {
		if req, err := pki.ParseOCSPRequest(in); err == nil {
			t.Errorf("ParseOCSPRequest(%s) = %+v, want error", name, req)
		}
	}
}

// ocspResponder answers OCSP requests for the certificates of ca with
// ParseOCSPRequest and CreateOCSPResponse, signing as responder; revoked
// serials are revoked at revokedAt for keyCompromise.
type ocspResponder struct {
	ca, responder *x509.Certificate
	key           *dstu4145.PrivateKey
	good, revoked *big.Int
	revokedAt     time.Time
}

func (o *ocspResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := pki.ParseOCSPRequest(body)
	if err != nil {
		_, _ = w.Write([]byte{0x30, 0x03, 0x0a, 0x01, 0x01}) // malformedRequest; the client reads what arrives
		return
	}
	now := time.Now()
	tmpl := &pki.OCSPResponseTemplate{ProducedAt: now, Nonce: req.Nonce}
	for _, id := range req.CertIDs {
		single := pki.OCSPSingleResponse{CertID: id, Status: pki.OCSPUnknown, ThisUpdate: now, NextUpdate: now.Add(time.Hour)}
		if ok, err := id.IssuedBy(o.ca); err == nil && ok {
			switch {
			case id.SerialNumber.Cmp(o.good) == 0:
				single.Status = pki.OCSPGood
			case id.SerialNumber.Cmp(o.revoked) == 0:
				single.Status, single.RevokedAt, single.RevocationReason = pki.OCSPRevoked, o.revokedAt, 1
			}
		}
		tmpl.Responses = append(tmpl.Responses, single)
	}
	resp, err := pki.CreateOCSPResponse(rand.Reader, tmpl, o.responder, o.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(resp) // the client reads what arrives
}

func TestCreateOCSPResponse(t *testing.T) {
	ca, caKey := newTestRoot(t)
	o := &ocspResponder{ca: ca, responder: ca, key: caKey, good: big.NewInt(10), revoked: big.NewInt(11), revokedAt: time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)}
	srv := httptest.NewTestServer(t, o)
	client := &pki.OCSPClient{URL: "http://ocsp.example/", HTTPClient: srv.Client()}

	tests := []struct {
		serial      int64
		gost        bool
		wantStatus  pki.OCSPStatus
		wantRevoked time.Time
		wantReason  int
	}{
		{serial: 10, wantStatus: pki.OCSPGood},
		{serial: 10, gost: true, wantStatus: pki.OCSPGood},
		{serial: 11, wantStatus: pki.OCSPRevoked, wantRevoked: o.revokedAt, wantReason: 1},
		{serial: 12, wantStatus: pki.OCSPUnknown},
	}
	for _, tt := range tests {
		client.GOST34311 = tt.gost
		// Check verifies the signature, the responder, the CertID and the echoed nonce
		resp, err := client.Check(t.Context(), &x509.Certificate{SerialNumber: big.NewInt(tt.serial)}, ca)
		if err != nil {
			t.Errorf("Check(serial %d, GOST34311=%v) error = %v", tt.serial, tt.gost, err)
			continue
		}
		if resp.Status != tt.wantStatus || !resp.RevokedAt.Equal(tt.wantRevoked) || resp.RevocationReason != tt.wantReason {
			t.Errorf("Check(serial %d) = status %v revoked %v reason %d, want %v %v %d", tt.serial, resp.Status, resp.RevokedAt, resp.RevocationReason, tt.wantStatus, tt.wantRevoked, tt.wantReason)
		}
		if !resp.Certificate.Equal(ca) || time.Since(resp.ProducedAt) > time.Minute || resp.NextUpdate.Sub(resp.ThisUpdate) != time.Hour {
			t.Errorf("Check(serial %d) = responder %s produced %v, update %v–%v, want the CA now for an hour", tt.serial, resp.Certificate.Subject, resp.ProducedAt, resp.ThisUpdate, resp.NextUpdate)
		}
	}

	// a key that is not the responder's is refused
	tmpl := &pki.OCSPResponseTemplate{ProducedAt: time.Now()}
	if _, err := pki.CreateOCSPResponse(rand.Reader, tmpl, ca, newKey(t)); err == nil {
		t.Error("CreateOCSPResponse(key of another certificate) error = nil, want error")
	}

	// a nonce in Extensions too would be written twice
	nonce := mustMarshal(t, []byte("nonce"))
	twice := &pki.OCSPResponseTemplate{ProducedAt: time.Now(), Nonce: nonce, Extensions: []pkix.Extension{{Id: oidOCSPNonce, Value: nonce}}}
	if _, err := pki.CreateOCSPResponse(rand.Reader, twice, ca, caKey); err == nil {
		t.Error("CreateOCSPResponse(nonce in Nonce and Extensions) error = nil, want error")
	}
}
