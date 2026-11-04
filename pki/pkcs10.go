package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
)

// A CertificateRequest is a PKCS#10 certificate request (RFC 2986) as a CA
// reads it.
type CertificateRequest struct {
	Raw                      []byte // DER; a request in BER is re-encoded
	RawTBSCertificateRequest []byte
	RawSubject               []byte
	RawSubjectPublicKeyInfo  []byte
	Subject                  pkix.Name

	PublicKeyAlgorithm asn1.ObjectIdentifier
	// PublicKey is the key of the request, nil when PublicKeyAlgorithm is
	// not DSTU 4145.
	PublicKey *PublicKey

	SignatureAlgorithm asn1.ObjectIdentifier
	Signature          []byte // the content of the signature BIT STRING
}

// ParseCertificateRequest parses a PKCS#10 request in DER or BER. A request
// for a key of another algorithm than DSTU 4145 parses with a nil PublicKey,
// so that a CA can name the algorithm it refuses; CheckSignature checks the
// proof of possession.
func ParseCertificateRequest(der []byte) (*CertificateRequest, error) {
	der, err := toDER(der)
	if err != nil {
		return nil, err
	}
	var csr struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if err := unmarshal(der, &csr); err != nil {
		return nil, fmt.Errorf("pki: CertificationRequest: %w", err)
	}
	var info struct {
		Version    int
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
	}
	if err := unmarshal(csr.Info.FullBytes, &info); err != nil {
		return nil, fmt.Errorf("pki: CertificationRequestInfo: %w", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if err := unmarshal(info.SPKI.FullBytes, &spki); err != nil {
		return nil, fmt.Errorf("pki: SubjectPublicKeyInfo: %w", err)
	}
	var subject pkix.RDNSequence
	if err := unmarshal(info.Subject.FullBytes, &subject); err != nil {
		return nil, fmt.Errorf("pki: request subject: %w", err)
	}
	cr := &CertificateRequest{
		Raw:                      der,
		RawTBSCertificateRequest: csr.Info.FullBytes,
		RawSubject:               info.Subject.FullBytes,
		RawSubjectPublicKeyInfo:  info.SPKI.FullBytes,
		PublicKeyAlgorithm:       spki.Algorithm.Algorithm,
		SignatureAlgorithm:       csr.Algorithm.Algorithm,
		Signature:                csr.Signature.RightAlign(),
	}
	cr.Subject.FillFromRDNSequence(&subject)
	if cr.PublicKeyAlgorithm.Equal(oidDSTU4145LE) || cr.PublicKeyAlgorithm.Equal(oidDSTU4145BE) {
		if cr.PublicKey, err = ParsePublicKey(cr.RawSubjectPublicKeyInfo); err != nil {
			return nil, err
		}
	}
	return cr, nil
}

// CheckSignature checks the signature of cr with its own key, which proves
// that the requester holds the private key. Signatures are DSTU 4145 with
// GOST 34.311 or Kupyna, little- or big-endian as the signature algorithm
// says, whatever the encoding of the key. A signature that does not verify
// is ErrInvalidSignature; a key or signature algorithm other than DSTU 4145
// wraps x509.ErrUnsupportedAlgorithm.
func (cr *CertificateRequest) CheckSignature() error {
	if cr.PublicKey == nil {
		return fmt.Errorf("pki: public key algorithm %v: %w", cr.PublicKeyAlgorithm, x509.ErrUnsupportedAlgorithm)
	}
	return cr.PublicKey.CheckSignature(cr.SignatureAlgorithm, cr.RawTBSCertificateRequest, cr.Signature)
}

// CertificatePublicKey returns the SubjectPublicKeyInfo of the certificate
// issued on cr, the pub of CreateCertificate, as Ukrainian CAs write keys:
// a dstu4145le key, as IIT requests carry it, as it is, and a dstu4145be key,
// as Bouncy Castle requests carry it, in the little-endian form of
// MarshalPublicKey. A key of another algorithm wraps
// x509.ErrUnsupportedAlgorithm.
func (cr *CertificateRequest) CertificatePublicKey() ([]byte, error) {
	switch {
	case cr.PublicKey == nil:
		return nil, fmt.Errorf("pki: public key algorithm %v: %w", cr.PublicKeyAlgorithm, x509.ErrUnsupportedAlgorithm)
	case cr.PublicKeyAlgorithm.Equal(oidDSTU4145LE):
		return cr.RawSubjectPublicKeyInfo, nil
	}
	return MarshalPublicKey(cr.PublicKey)
}

// CreateCertificateRequest creates a PKCS#10 request as
// crypto/x509.CreateCertificateRequest does, for the public key of key in
// the form of MarshalPublicKey, signed by key with DSTU 4145 and GOST 34.311
// (dstu4145le), as the IIT library writes requests. The template fields are
// those of crypto/x509 except SignatureAlgorithm.
func CreateCertificateRequest(random io.Reader, template *x509.CertificateRequest, key *dstu4145.PrivateKey) ([]byte, error) {
	pub, err := MarshalPublicKey(&PublicKey{Key: key.Public(), DKE: gost28147.DKE1()})
	if err != nil {
		return nil, err
	}
	// as in CreateCertificate, crypto/x509 builds the request for a stand-in key
	standIn, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	tmpl := *template
	tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, standIn)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	var csr struct {
		Info      asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.RawValue
	}
	if err := unmarshal(der, &csr); err != nil {
		return nil, fmt.Errorf("pki: CertificationRequest: %w", err)
	}
	// CertificationRequestInfo: version, subject, subjectPKInfo, attributes
	info, err := replaceFields(csr.Info.Bytes, map[int][]byte{2: pub})
	if err != nil {
		return nil, fmt.Errorf("pki: CertificationRequestInfo: %w", err)
	}
	signatureAlg, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE})
	if err != nil {
		return nil, fmt.Errorf("pki: signature algorithm: %w", err)
	}
	signature, err := signDSTU(random, key, gost28147.DKE1(), info)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Info      asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: info}, asn1.RawValue{FullBytes: signatureAlg}, asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}})
}
