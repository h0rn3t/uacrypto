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
	"maps"
	"math/big"
	"slices"
	"strings"
	"unicode"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
)

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	oidSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	oidDRFO                       = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 1, 1}
	oidEDRPOU                     = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 2, 1}

	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSubjectInfoAccess      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	oidADTimeStamping         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 3}
	oidOCSPNoCheck            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
)

// policyQualified is the certificate policy that every certificate of a
// Ukrainian CA names (1.2.804.2.1.1.1.2.2).
var policyQualified = []uint64{1, 2, 804, 2, 1, 1, 1, 2, 2}

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
//   - Policies is 1.2.804.2.1.1.1.2.2, the policy every certificate of a
//     Ukrainian CA names, when neither Policies nor PolicyIdentifiers is set;
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
	if tmpl.Policies == nil && tmpl.PolicyIdentifiers == nil {
		policy, err := x509.OIDFromInts(policyQualified)
		if err != nil {
			return nil, fmt.Errorf("pki: certificate policy: %w", err)
		}
		tmpl.Policies = []x509.OID{policy}
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
	// TBSCertificate: version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, …
	return resignDSTU(random, der, 2, map[int][]byte{6: pub}, key, issuerKey.DKE)
}

// resignDSTU signs again with DSTU 4145 der, a certificate or CRL that
// crypto/x509 signed for a stand-in key: the signature algorithm, field alg
// of the TBS, becomes dstu4145le, the fields of with replace theirs, and key
// signs the GOST 34.311 hash of the TBS under dke.
func resignDSTU(random io.Reader, der []byte, alg int, with map[int][]byte, key *dstu4145.PrivateKey, dke gost28147.Sbox) ([]byte, error) {
	var signed struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.RawValue
	}
	if err := unmarshal(der, &signed); err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	signatureAlg, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE})
	if err != nil {
		return nil, fmt.Errorf("pki: signature algorithm: %w", err)
	}
	fields := maps.Clone(with)
	if fields == nil {
		fields = map[int][]byte{}
	}
	fields[alg] = signatureAlg
	tbs, err := replaceFields(signed.TBS.Bytes, fields)
	if err != nil {
		return nil, fmt.Errorf("pki: TBS: %w", err)
	}
	signature, err := signDSTU(random, key, dke, tbs)
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
// must be the one of d. It also parses the key as IIT and cryptonite write
// it, with d itself little-endian in place of the ECPrivateKey; the key
// agreement key IIT adds to it is ParsePKCS8KeyAgreementKey's.
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
	if unmarshal(pkcs8.PrivateKey, &ec) != nil {
		d := slices.Clone(pkcs8.PrivateKey) // IIT: d little-endian
		slices.Reverse(d)
		key, err := dstu4145.NewPrivateKey(curve, d)
		clear(d)
		if err != nil {
			return nil, fmt.Errorf("pki: %w", err)
		}
		return key, nil
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

// SubjectAttributes are the registration codes of a certificate subject that
// Ukrainian CAs write in the subjectDirectoryAttributes extension
// (RFC 5280, 4.2.1.8), each as a PrintableString. An empty code is absent.
type SubjectAttributes struct {
	DRFO   string // РНОКПП, the taxpayer number of a person in the ДРФО register
	EDRPOU string // the ЄДРПОУ code of a legal entity
}

// ParseSubjectAttributes returns the DRFO and EDRPOU codes in the
// subjectDirectoryAttributes extension of cert, the zero value when it has
// none. Other attributes are skipped; of several values the first is taken.
func ParseSubjectAttributes(cert *x509.Certificate) (SubjectAttributes, error) {
	var a SubjectAttributes
	i := slices.IndexFunc(cert.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidSubjectDirectoryAttributes) })
	if i < 0 {
		return a, nil
	}
	var attrs []attribute
	if err := unmarshal(cert.Extensions[i].Value, &attrs); err != nil {
		return a, fmt.Errorf("pki: subjectDirectoryAttributes: %w", err)
	}
	for _, attr := range attrs {
		var code *string
		switch {
		case attr.Type.Equal(oidDRFO):
			code = &a.DRFO
		case attr.Type.Equal(oidEDRPOU):
			code = &a.EDRPOU
		default:
			continue
		}
		if _, err := asn1.Unmarshal(attr.Values.Bytes, code); err != nil {
			return SubjectAttributes{}, fmt.Errorf("pki: subject attribute %v: %w", attr.Type, err)
		}
	}
	return a, nil
}

// MarshalSubjectAttributes returns the non-critical subjectDirectoryAttributes
// extension with the codes of a, DRFO first, as Ukrainian CAs write it, for
// x509.Certificate.ExtraExtensions. A code must be a valid PrintableString,
// and at least one must be set.
func MarshalSubjectAttributes(a SubjectAttributes) (pkix.Extension, error) {
	var attrs []attribute
	for _, code := range []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{{oidDRFO, a.DRFO}, {oidEDRPOU, a.EDRPOU}} {
		if code.value == "" {
			continue
		}
		v, err := asn1.MarshalWithParams(code.value, "printable")
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("pki: subject attribute %v: %w", code.oid, err)
		}
		attrs = append(attrs, attribute{Type: code.oid, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}})
	}
	if len(attrs) == 0 {
		return pkix.Extension{}, errors.New("pki: no subject attributes")
	}
	value, err := asn1.Marshal(attrs)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("pki: subjectDirectoryAttributes: %w", err)
	}
	return pkix.Extension{Id: oidSubjectDirectoryAttributes, Value: value}, nil
}

// MarshalName returns name as the DER Name of a certificate subject in the
// form of Ukrainian CAs, for x509.Certificate.RawSubject: one attribute per
// RDN in the order O, OU, CN, serialNumber, C, L, serialNumber and C as
// PrintableString and the others as UTF8String; empty values are left out.
// crypto/x509 would write another order and a PrintableString wherever the
// value allows it. Province, StreetAddress, PostalCode and ExtraNames are not
// supported; Names, which only parsing fills, is ignored.
func MarshalName(name pkix.Name) ([]byte, error) {
	if name.Province != nil || name.StreetAddress != nil || name.PostalCode != nil || name.ExtraNames != nil {
		return nil, errors.New("pki: the name has attributes other than O, OU, CN, serialNumber, C and L")
	}
	var rdns pkix.RDNSequence
	for _, attr := range []struct {
		oid    asn1.ObjectIdentifier
		params string
		values []string
	}{
		{oidOrganization, "utf8", name.Organization},
		{oidOrganizationalUnit, "utf8", name.OrganizationalUnit},
		{oidCommonName, "utf8", []string{name.CommonName}},
		{oidSerialNumber, "printable", []string{name.SerialNumber}},
		{oidCountry, "printable", name.Country},
		{oidLocality, "utf8", name.Locality},
	} {
		for _, v := range attr.values {
			if v == "" {
				continue
			}
			der, err := asn1.MarshalWithParams(v, attr.params)
			if err != nil {
				return nil, fmt.Errorf("pki: name attribute %v: %w", attr.oid, err)
			}
			rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: attr.oid, Value: asn1.RawValue{FullBytes: der}}})
		}
	}
	return asn1.Marshal(rdns)
}

// MarshalAuthorityKeyIdentifier returns the non-critical
// authorityKeyIdentifier extension (RFC 5280, 4.2.1.1) that names issuer by
// its key identifier and also by the name of its own issuer and its serial
// number, as Bouncy Castle's JcaX509ExtensionUtils writes it from the issuer
// certificate, for x509.Certificate.ExtraExtensions. Without it,
// CreateCertificate writes the key identifier alone, as Ukrainian CAs do.
func MarshalAuthorityKeyIdentifier(issuer *x509.Certificate) (pkix.Extension, error) {
	if len(issuer.SubjectKeyId) == 0 {
		return pkix.Extension{}, errors.New("pki: the issuer has no subject key identifier")
	}
	value, err := asn1.Marshal(struct {
		KeyID  []byte          `asn1:"tag:0"`
		Issuer []asn1.RawValue `asn1:"tag:1"` // GeneralNames
		Serial *big.Int        `asn1:"tag:2"`
	}{
		issuer.SubjectKeyId,
		[]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: issuer.RawIssuer}}, // directoryName
		issuer.SerialNumber,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("pki: authorityKeyIdentifier: %w", err)
	}
	return pkix.Extension{Id: oidAuthorityKeyIdentifier, Value: value}, nil
}

// MarshalSubjectInfoAccess returns the non-critical subjectInfoAccess
// extension (RFC 5280, 4.2.2.2) with the address of the time-stamping
// service the subject uses (id-ad-timeStamping), for
// x509.Certificate.ExtraExtensions. The address must be non-empty ASCII.
func MarshalSubjectInfoAccess(timeStampingURL string) (pkix.Extension, error) {
	if timeStampingURL == "" || strings.ContainsFunc(timeStampingURL, func(r rune) bool { return r > unicode.MaxASCII }) {
		return pkix.Extension{}, fmt.Errorf("pki: time-stamping address %q is not a non-empty ASCII URI", timeStampingURL)
	}
	type accessDescription struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}
	value, err := asn1.Marshal([]accessDescription{{
		oidADTimeStamping,
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(timeStampingURL)}, // uniformResourceIdentifier
	}})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("pki: subjectInfoAccess: %w", err)
	}
	return pkix.Extension{Id: oidSubjectInfoAccess, Value: value}, nil
}

// OCSPResponderExtensions returns the extensions that CAs on Bouncy Castle
// write in the certificate of their OCSP responder, for
// x509.Certificate.ExtraExtensions in place of ExtKeyUsage: the extended key
// usage OCSPSigning alone and critical, which crypto/x509 writes
// non-critical, and id-pkix-ocsp-nocheck (RFC 6960, 4.2.2.2.1), which tells
// clients not to check the status of the responder certificate itself.
func OCSPResponderExtensions() []pkix.Extension {
	return []pkix.Extension{
		{Id: oidExtKeyUsage, Critical: true, Value: []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09}}, // SEQUENCE { id-kp-OCSPSigning }
		{Id: oidOCSPNoCheck, Value: []byte{0x05, 0x00}}, // NULL
	}
}
