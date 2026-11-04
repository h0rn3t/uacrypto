package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
)

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

// MarshalPublicKey returns the DER SubjectPublicKeyInfo of k in the form of
// the keys of a Ukrainian CA: the algorithm dstu4145le, DSTU4145Params with
// the OID of the curve and, unless it is ДКЕ №1, the DKE, and the
// compressed point little-endian in an OCTET STRING.
func MarshalPublicKey(k *PublicKey) ([]byte, error) {
	curve, err := curveOID(k.Key.Curve())
	if err != nil {
		return nil, err
	}
	params := struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte `asn1:"optional"`
	}{Curve: curve}
	if k.DKE != gost28147.DKE1() {
		params.DKE = gost28147.PackDKE(k.DKE)
	}
	rawParams, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("pki: DSTU4145Params: %w", err)
	}
	point := k.Key.Bytes()
	slices.Reverse(point)
	bits, err := asn1.Marshal(point)
	if err != nil {
		return nil, fmt.Errorf("pki: public key: %w", err)
	}
	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE, Parameters: asn1.RawValue{FullBytes: rawParams}},
		asn1.BitString{Bytes: bits, BitLength: 8 * len(bits)},
	})
}

// curveOID returns the OID of the named curve c.
func curveOID(c *dstu4145.Curve) (asn1.ObjectIdentifier, error) {
	for n := range 10 {
		if named, err := dstu4145.NamedCurve(n); err == nil && named == c {
			return append(slices.Clone(oidNamedCurves), n), nil
		}
	}
	return nil, errors.New("pki: the key is not on a named curve")
}

// belongsTo reports whether key is the private key of k.
func (k *PublicKey) belongsTo(key *dstu4145.PrivateKey) bool {
	return k.Key.Curve() == key.Public().Curve() && bytes.Equal(k.Key.Bytes(), key.Public().Bytes())
}

// CreateCertificate issues a certificate as crypto/x509.CreateCertificate
// does, signed by key with DSTU 4145 and GOST 34.311 (dstu4145le), hashed
// with the DKE of the issuer's key. pub is the DER SubjectPublicKeyInfo of
// the subject's DSTU 4145 key and goes into the certificate as it is:
// CertificateRequest.RawSubjectPublicKeyInfo of a request, or
// MarshalPublicKey of a key of your own. parent is the issuer certificate, or
// template itself for a self-signed certificate; key must belong to it.
//
// The template fields are those of crypto/x509.CreateCertificate except
// PublicKey, PublicKeyAlgorithm and SignatureAlgorithm, with the defaults of
// Ukrainian CAs:
//   - SubjectKeyId is the GOST 34.311 hash (ДКЕ №1) of the subject public
//     key bits;
//   - AuthorityKeyId of a self-signed certificate is its SubjectKeyId;
//   - ExtKeyUsage of TimeStamping alone is critical, as RFC 3161 requires.
//
// ExtraExtensions replace the extensions built from the other fields, as in
// crypto/x509.
func CreateCertificate(random io.Reader, template, parent *x509.Certificate, pub []byte, key *dstu4145.PrivateKey) ([]byte, error) {
	subjectKey, err := ParsePublicKey(pub)
	if err != nil {
		return nil, err
	}
	selfSigned := parent == template
	issuerKey := subjectKey
	if !selfSigned {
		if issuerKey, err = ParsePublicKey(parent.RawSubjectPublicKeyInfo); err != nil {
			return nil, err
		}
	}
	if !issuerKey.belongsTo(key) {
		return nil, errors.New("pki: the private key does not belong to the issuer")
	}

	tmpl := *template
	if tmpl.SubjectKeyId == nil {
		var spki struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if err := unmarshal(pub, &spki); err != nil {
			return nil, fmt.Errorf("pki: SubjectPublicKeyInfo: %w", err)
		}
		ski, err := hashOf(oidGOST34311, spki.PublicKey.Bytes)
		if err != nil {
			return nil, err
		}
		tmpl.SubjectKeyId = ski.Value
	}
	if selfSigned && tmpl.AuthorityKeyId == nil {
		tmpl.AuthorityKeyId = tmpl.SubjectKeyId
	}
	if slices.Equal(tmpl.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}) && tmpl.UnknownExtKeyUsage == nil {
		eku, err := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping})
		if err != nil {
			return nil, fmt.Errorf("pki: extended key usage: %w", err)
		}
		// the template's own extension of the same OID comes later and wins
		tmpl.ExtraExtensions = slices.Concat([]pkix.Extension{{Id: oidExtKeyUsage, Critical: true, Value: eku}}, tmpl.ExtraExtensions)
	}

	// crypto/x509 builds the TBSCertificate for a stand-in ECDSA key; the key
	// and the signature algorithm are then replaced and the TBSCertificate
	// signed with DSTU 4145
	standIn, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	issuer := parent
	if selfSigned {
		issuer = &tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, issuer, standIn.Public(), standIn)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	var cert struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.RawValue
	}
	if err := unmarshal(der, &cert); err != nil {
		return nil, fmt.Errorf("pki: certificate: %w", err)
	}
	signatureAlg, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE})
	if err != nil {
		return nil, fmt.Errorf("pki: signature algorithm: %w", err)
	}
	// TBSCertificate: version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, …
	tbs, err := replaceFields(cert.TBS.Bytes, map[int][]byte{2: signatureAlg, 6: pub})
	if err != nil {
		return nil, fmt.Errorf("pki: TBSCertificate: %w", err)
	}
	signature, err := signDSTU(random, key, issuerKey.DKE, tbs)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, asn1.RawValue{FullBytes: signatureAlg}, asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}})
}

// replaceFields returns the SEQUENCE of the DER values in body with the
// values at the given positions replaced.
func replaceFields(body []byte, with map[int][]byte) ([]byte, error) {
	var fields []byte
	for i := 0; len(body) > 0; i++ {
		var field asn1.RawValue
		var err error
		if body, err = asn1.Unmarshal(body, &field); err != nil {
			return nil, err
		}
		if v, ok := with[i]; ok {
			field.FullBytes = v
		}
		fields = append(fields, field.FullBytes...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: fields})
}

// signDSTU signs the GOST 34.311 hash of data under dke with key and returns
// the signature as certificates, requests and OCSP responses carry it: r||s
// little-endian in a DER OCTET STRING.
func signDSTU(random io.Reader, key *dstu4145.PrivateKey, dke gost28147.Sbox, data []byte) ([]byte, error) {
	h, err := newHash(oidGOST34311, dke)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	r, s, err := dstu4145.Sign(random, key, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return asn1.Marshal(dstu4145.MarshalSignature(key.Public().Curve(), r, s))
}

// MarshalPKCS8PrivateKey returns key in PKCS#8 as Bouncy Castle writes a
// DSTU 4145 key: the algorithm dstu4145be with the OID of the curve as its
// parameters, and an ECPrivateKey with d big-endian, the curve and the
// compressed point big-endian.
func MarshalPKCS8PrivateKey(key *dstu4145.PrivateKey) ([]byte, error) {
	oid, err := curveOID(key.Public().Curve())
	if err != nil {
		return nil, err
	}
	point, err := asn1.Marshal(key.Public().Bytes())
	if err != nil {
		return nil, fmt.Errorf("pki: public key: %w", err)
	}
	ecKey, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: key.Bytes(),
		Curve:      oid,
		PublicKey:  asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
	if err != nil {
		return nil, fmt.Errorf("pki: ECPrivateKey: %w", err)
	}
	curve, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("pki: curve: %w", err)
	}
	return asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145BE, Parameters: asn1.RawValue{FullBytes: curve}}, ecKey})
}

type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	Curve      asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParsePKCS8PrivateKey parses a DSTU 4145 private key in PKCS#8 as
// MarshalPKCS8PrivateKey and Bouncy Castle write it: the algorithm
// dstu4145be or dstu4145le with the curve as an OID or in DSTU4145Params,
// and an ECPrivateKey with d big-endian. A public key in the ECPrivateKey
// must be the one of d.
func ParsePKCS8PrivateKey(der []byte) (*dstu4145.PrivateKey, error) {
	var pkcs8 struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
	}
	if err := unmarshal(der, &pkcs8); err != nil {
		return nil, fmt.Errorf("pki: PKCS#8: %w", err)
	}
	alg := pkcs8.Algorithm.Algorithm
	littleEndian := alg.Equal(oidDSTU4145LE)
	if !littleEndian && !alg.Equal(oidDSTU4145BE) {
		return nil, fmt.Errorf("pki: private key algorithm %v: %w", alg, x509.ErrUnsupportedAlgorithm)
	}
	curveDER := pkcs8.Algorithm.Parameters.FullBytes
	if pkcs8.Algorithm.Parameters.Tag == asn1.TagSequence { // DSTU4145Params
		var params struct {
			Curve asn1.RawValue
			DKE   []byte `asn1:"optional"`
		}
		if err := unmarshal(curveDER, &params); err != nil {
			return nil, fmt.Errorf("pki: DSTU 4145 parameters: %w", err)
		}
		curveDER = params.Curve.FullBytes
	}
	curve, err := parseCurve(curveDER, littleEndian)
	if err != nil {
		return nil, err
	}
	var ec ecPrivateKey
	if err := unmarshal(pkcs8.PrivateKey, &ec); err != nil {
		return nil, fmt.Errorf("pki: ECPrivateKey: %w", err)
	}
	key, err := dstu4145.NewPrivateKey(curve, ec.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	if ec.PublicKey.Bytes != nil {
		var point []byte
		if err := unmarshal(ec.PublicKey.RightAlign(), &point); err != nil {
			return nil, fmt.Errorf("pki: ECPrivateKey public key: %w", err)
		}
		own := key.Public().Bytes()
		reversed := slices.Clone(own)
		slices.Reverse(reversed)
		if !bytes.Equal(point, own) && !bytes.Equal(point, reversed) {
			return nil, errors.New("pki: the public key in the PKCS#8 key is not the one of its private key")
		}
	}
	return key, nil
}

// MarshalCertificateBundle returns certs as a SignedData without content
// and signers, the .p7b form of CACertificates.p7b and of openssl
// crl2pkcs7 -nocrl.
func MarshalCertificateBundle(certs []*x509.Certificate) ([]byte, error) {
	encap, err := asn1.Marshal(struct{ Type asn1.ObjectIdentifier }{oidData})
	if err != nil {
		return nil, fmt.Errorf("pki: EncapsulatedContentInfo: %w", err)
	}
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: []byte{0x31, 0x00}},
		Encap:            asn1.RawValue{FullBytes: encap},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
	}
	return sd.marshal()
}

// ParseCertificateBundle returns the X.509 certificates of a SignedData in
// DER or BER: a .p7b bundle such as CACertificates.p7b of the ЦЗО and of IIT,
// or a signed .p7s. Certificates in other formats are skipped.
func ParseCertificateBundle(der []byte) ([]*x509.Certificate, error) {
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	return sd.certificates()
}
