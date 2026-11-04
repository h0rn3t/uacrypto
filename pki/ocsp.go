package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"time"
)

var (
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
)

// errNoStatus reports an OCSP response about other certificates.
var errNoStatus = errors.New("pki: the OCSP response has no status for the certificate")

// An OCSPStatus is the status of a certificate in an OCSP response.
type OCSPStatus int

// The certificate statuses of RFC 6960.
const (
	OCSPGood OCSPStatus = iota
	OCSPRevoked
	OCSPUnknown // the responder knows nothing about the certificate
)

// An OCSPResponse is a verified OCSP response (RFC 6960) about one certificate.
type OCSPResponse struct {
	Status       OCSPStatus
	SerialNumber *big.Int
	ProducedAt   time.Time
	ThisUpdate   time.Time
	NextUpdate   time.Time // zero when the responder gives none

	// RevokedAt and RevocationReason, a CRLReason code, are set only for
	// OCSPRevoked; the reason is 0 (unspecified) when the responder gives none.
	RevokedAt        time.Time
	RevocationReason int

	Certificate *x509.Certificate // of the responder
	Raw         []byte            // the DER OCSPResponse

	basic       []byte // the DER BasicOCSPResponse inside Raw
	responderID []byte // the DER ResponderID
}

type singleResponse struct {
	CertID     certID
	Status     asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"optional,explicit,generalized,tag:0"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	Serial        *big.Int
}

// newCertID returns the CertID of the certificate with serial issued by
// issuer: hashes of the issuer name and of its public key BIT STRING, made
// with alg and, for GOST 34.311, ДКЕ №1.
func newCertID(alg asn1.ObjectIdentifier, serial *big.Int, issuer *x509.Certificate) (certID, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if err := unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return certID{}, fmt.Errorf("pki: issuer SubjectPublicKeyInfo: %w", err)
	}
	id := certID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: alg}, Serial: serial}
	for _, f := range []struct {
		data []byte
		sum  *[]byte
	}{{issuer.RawSubject, &id.NameHash}, {spki.PublicKey.RightAlign(), &id.KeyHash}} {
		h, err := certIDHash(alg)
		if err != nil {
			return certID{}, err
		}
		h.Write(f.data)
		*f.sum = h.Sum(nil)
	}
	return id, nil
}

// ParseOCSPResponse parses and verifies a DER OCSP response about the
// certificate with serial issued by issuer. The response must be successful
// and carry a status for that certificate, with a DSTU 4145 signature by
// issuer itself or by a certificate that issuer issued for OCSP signing
// (RFC 6960, 4.2.2.2) and that was valid when the response was produced. The
// CertID may be hashed with Kupyna or GOST 34.311.
//
// ParseOCSPResponse does not check how fresh the response is: compare
// ThisUpdate and NextUpdate with the time that matters to you. A signature
// that does not verify is ErrInvalidSignature.
func ParseOCSPResponse(der []byte, serial *big.Int, issuer *x509.Certificate) (*OCSPResponse, error) {
	resp, _, err := parseOCSPResponse(der, serial, issuer, nil)
	return resp, err
}

// parseOCSPResponse is ParseOCSPResponse that also looks the responder up in
// certs and returns the value of the nonce extension, nil when there is
// none. A response about other certificates is errNoStatus.
func parseOCSPResponse(der []byte, serial *big.Int, issuer *x509.Certificate, certs []*x509.Certificate) (*OCSPResponse, []byte, error) {
	var outer struct {
		Status asn1.Enumerated
		Bytes  struct {
			Type     asn1.ObjectIdentifier
			Response []byte
		} `asn1:"optional,explicit,tag:0"`
	}
	if err := unmarshal(der, &outer); err != nil {
		return nil, nil, fmt.Errorf("pki: OCSPResponse: %w", err)
	}
	if outer.Status != 0 {
		return nil, nil, fmt.Errorf("pki: the OCSP responder refused the request: status %d", outer.Status)
	}
	if !outer.Bytes.Type.Equal(oidOCSPBasic) {
		return nil, nil, fmt.Errorf("pki: OCSP response type %v is not basic", outer.Bytes.Type)
	}
	var basic struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
		Certs     []asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	if err := unmarshal(outer.Bytes.Response, &basic); err != nil {
		return nil, nil, fmt.Errorf("pki: BasicOCSPResponse: %w", err)
	}
	var data struct {
		Version     int `asn1:"optional,explicit,default:0,tag:0"`
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []singleResponse
		Extensions  []pkix.Extension `asn1:"optional,explicit,tag:1"`
	}
	if err := unmarshal(basic.TBS.FullBytes, &data); err != nil {
		return nil, nil, fmt.Errorf("pki: OCSP ResponseData: %w", err)
	}

	match := slices.IndexFunc(data.Responses, func(r singleResponse) bool {
		want, err := newCertID(r.CertID.HashAlgorithm.Algorithm, serial, issuer)
		return err == nil && r.CertID.Serial.Cmp(serial) == 0 &&
			bytes.Equal(r.CertID.NameHash, want.NameHash) && bytes.Equal(r.CertID.KeyHash, want.KeyHash)
	})
	if match < 0 {
		return nil, nil, fmt.Errorf("%w %x of %s", errNoStatus, serial, issuer.Subject)
	}
	r := data.Responses[match]

	pool := []*x509.Certificate{issuer}
	for _, raw := range basic.Certs {
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: OCSP response certificate: %w", err)
		}
		pool = append(pool, c)
	}
	pool = append(pool, certs...)
	responder, err := findResponder(data.ResponderID, pool, func(c *x509.Certificate) error {
		key, err := ParsePublicKey(c.RawSubjectPublicKeyInfo)
		if err != nil {
			return err
		}
		return key.CheckSignature(basic.Algorithm.Algorithm, basic.TBS.FullBytes, basic.Signature.RightAlign())
	})
	if err != nil {
		return nil, nil, err
	}
	if err := checkResponder(responder, issuer, data.ProducedAt); err != nil {
		return nil, nil, err
	}

	resp := &OCSPResponse{
		SerialNumber: serial,
		ProducedAt:   data.ProducedAt,
		ThisUpdate:   r.ThisUpdate,
		NextUpdate:   r.NextUpdate,
		Certificate:  responder,
		Raw:          der,
		basic:        outer.Bytes.Response,
		responderID:  data.ResponderID.FullBytes,
	}
	switch s := r.Status; {
	case s.Class == asn1.ClassContextSpecific && s.Tag == 0:
		resp.Status = OCSPGood
	case s.Class == asn1.ClassContextSpecific && s.Tag == 1:
		var revoked struct {
			Time   time.Time       `asn1:"generalized"`
			Reason asn1.Enumerated `asn1:"optional,explicit,tag:0"`
		}
		if _, err := asn1.UnmarshalWithParams(s.FullBytes, &revoked, "tag:1"); err != nil {
			return nil, nil, fmt.Errorf("pki: OCSP RevokedInfo: %w", err)
		}
		resp.Status, resp.RevokedAt, resp.RevocationReason = OCSPRevoked, revoked.Time, int(revoked.Reason)
	case s.Class == asn1.ClassContextSpecific && s.Tag == 2:
		resp.Status = OCSPUnknown
	default:
		return nil, nil, fmt.Errorf("pki: OCSP certificate status with tag %d", s.Tag)
	}
	var nonce []byte
	if i := slices.IndexFunc(data.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidOCSPNonce) }); i >= 0 {
		nonce = data.Extensions[i].Value
	}
	return resp, nonce, nil
}

// findResponder returns the certificate in pool that id names and whose key
// verify accepts. Responders name themselves by subject or, as monobank
// does, by a key hash equal to the subjectKeyIdentifier.
func findResponder(id asn1.RawValue, pool []*x509.Certificate, verify func(*x509.Certificate) error) (*x509.Certificate, error) {
	var match func(*x509.Certificate) bool
	switch {
	case id.Class == asn1.ClassContextSpecific && id.Tag == 1:
		match = func(c *x509.Certificate) bool { return bytes.Equal(c.RawSubject, id.Bytes) }
	case id.Class == asn1.ClassContextSpecific && id.Tag == 2:
		var keyHash []byte
		if err := unmarshal(id.Bytes, &keyHash); err != nil {
			return nil, fmt.Errorf("pki: OCSP responder key hash: %w", err)
		}
		match = func(c *x509.Certificate) bool { return bytes.Equal(c.SubjectKeyId, keyHash) }
	default:
		return nil, fmt.Errorf("pki: OCSP responder identifier with tag %d", id.Tag)
	}
	var errs error
	for _, c := range pool {
		if !match(c) {
			continue
		}
		err := verify(c)
		if err == nil {
			return c, nil
		}
		errs = errors.Join(errs, err)
	}
	if errs == nil {
		return nil, errors.New("pki: the OCSP responder certificate is not in the response")
	}
	return nil, fmt.Errorf("pki: OCSP response signature: %w", errs)
}

// checkResponder checks that responder may answer for the certificates of
// issuer at producedAt.
func checkResponder(responder, issuer *x509.Certificate, producedAt time.Time) error {
	if responder.Equal(issuer) {
		return nil
	}
	if !bytes.Equal(responder.RawIssuer, issuer.RawSubject) || !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return fmt.Errorf("pki: %s is not an OCSP responder of %s", responder.Subject, issuer.Subject)
	}
	if err := CheckCertificateSignature(responder, issuer); err != nil {
		return fmt.Errorf("pki: OCSP responder certificate %s: %w", responder.Subject, err)
	}
	if producedAt.Before(responder.NotBefore) || producedAt.After(responder.NotAfter) {
		return fmt.Errorf("pki: OCSP responder certificate %s was not valid at %v", responder.Subject, producedAt)
	}
	return nil
}

// An OCSPClient asks OCSP responders (RFC 6960) about certificates over
// HTTP, as Ukrainian CAs serve them.
type OCSPClient struct {
	URL        string       // "": the first OCSP server named in the certificate
	HTTPClient *http.Client // nil: a client with a 30-second timeout
	GOST34311  bool         // hash the CertID with GOST 34.311 instead of Kupyna-256
}

// Check asks about cert, issued by issuer, with a random nonce, and returns
// the response after ParseOCSPResponse and a check that the responder echoed
// the nonce, which makes the response fresh. With no URL, Check connects to
// the address the certificate names; set URL for a certificate you do not
// trust to name it.
func (c *OCSPClient) Check(ctx context.Context, cert, issuer *x509.Certificate) (*OCSPResponse, error) {
	url := c.URL
	if url == "" {
		if len(cert.OCSPServer) == 0 {
			return nil, fmt.Errorf("pki: certificate %s names no OCSP server", cert.Subject)
		}
		url = cert.OCSPServer[0]
	}
	alg := oidKupyna256
	if c.GOST34311 {
		alg = oidGOST34311
	}
	id, err := newCertID(alg, cert.SerialNumber, issuer)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce) // never fails since Go 1.24
	nonceExt, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("pki: OCSP nonce: %w", err)
	}

	type request struct{ CertID certID }
	type tbsRequest struct {
		Requests   []request
		Extensions []pkix.Extension `asn1:"explicit,tag:2"`
	}
	req, err := asn1.Marshal(struct{ TBS tbsRequest }{tbsRequest{
		Requests:   []request{{id}},
		Extensions: []pkix.Extension{{Id: oidOCSPNonce, Value: nonceExt}},
	}})
	if err != nil {
		return nil, fmt.Errorf("pki: OCSPRequest: %w", err)
	}
	body, err := post(ctx, c.HTTPClient, "OCSP responder", url, "application/ocsp-request", req)
	if err != nil {
		return nil, err
	}
	resp, echoed, err := parseOCSPResponse(body, cert.SerialNumber, issuer, nil)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(echoed, nonceExt) {
		return nil, errors.New("pki: the OCSP response does not carry the request nonce")
	}
	return resp, nil
}
