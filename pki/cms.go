package pki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

// A Signer is a signer of a SignedData whose signature VerifySignedData verified.
type Signer struct {
	Certificate *x509.Certificate
	// SigningTime is the signingTime attribute, zero when absent. It is what
	// the signer claims; only TimeStamp proves a time.
	SigningTime time.Time
	// TimeStamp is the verified signatureTimeStampToken of a CAdES-T
	// signature, nil when the signature has none.
	TimeStamp *TimeStamp
	// Chain and OCSP are the validation data of a CAdES-X Long signature,
	// nil when the signature has none: the path from Certificate to a
	// self-signed root, and for every certificate in it but the root the
	// verified OCSP response about it, OCSP[i] about Chain[i], nil when the
	// signature holds none. IIT stores the response about the signer
	// certificate only, or with "full CA data" about the CAs too. The
	// statuses and times of the responses are for the caller to judge.
	Chain []*x509.Certificate
	OCSP  []*OCSPResponse
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue // IssuerAndSerialNumber or [0] SubjectKeyIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// signedData keeps the parts it does not change as raw DER, so that a parsed
// SignedData marshals back to the same bytes.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	Encap            asn1.RawValue // EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// parseSignedData reads a ContentInfo holding a SignedData in DER or BER.
func parseSignedData(der []byte) (*signedData, error) {
	der, err := toDER(der)
	if err != nil {
		return nil, err
	}
	// encoding/asn1 keeps the [0] EXPLICIT wrapper in a RawValue: Bytes is the inner value
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if err := unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("pki: ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pki: content type %v is not SignedData", ci.ContentType)
	}
	sd := new(signedData)
	if err := unmarshal(ci.Content.Bytes, sd); err != nil {
		return nil, fmt.Errorf("pki: SignedData: %w", err)
	}
	return sd, nil
}

// marshal returns sd in a ContentInfo.
func (sd *signedData) marshal() ([]byte, error) {
	inner, err := asn1.Marshal(*sd)
	if err != nil {
		return nil, fmt.Errorf("pki: SignedData: %w", err)
	}
	return asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}

// VerifySignedData verifies a CMS SignedData (RFC 5652) in DER or BER whose
// signers use DSTU 4145, as IIT-compatible software, Ukrainian TSAs and
// Bouncy Castle write it; BER comes from streaming signers, with indefinite
// lengths and the content in chunks. Every SignerInfo must verify, and so must the signature
// time-stamp of a CAdES-T signer and the validation data of a CAdES-X Long
// one. When the SignedData carries no content, detached is the signed
// content; otherwise detached must be nil. The signer, TSA and OCSP responder
// certificates are looked up in the SignedData, the time-stamp token or OCSP
// response, the certValues attribute, and then in certs: IIT leaves the TSA
// and responder certificates out, so pass the CA certificates
// (CACertificates.p7b of the ЦЗО) to verify its CAdES-T and CAdES-X Long.
//
// VerifySignedData returns the content and the signers in SignerInfo order. It
// checks signatures only: the signer certificates are not checked against any
// trust anchor. A signature or message digest that does not match is
// ErrInvalidSignature.
func VerifySignedData(der, detached []byte, certs []*x509.Certificate) (content []byte, signers []Signer, err error) {
	_, content, signers, err = verifySignedData(der, detached, certs)
	return content, signers, err
}

// verifySignedData is VerifySignedData that also returns the content type.
func verifySignedData(der, detached []byte, certs []*x509.Certificate) (asn1.ObjectIdentifier, []byte, []Signer, error) {
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, nil, nil, err
	}
	var encap struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	if err := unmarshal(sd.Encap.FullBytes, &encap); err != nil {
		return nil, nil, nil, fmt.Errorf("pki: EncapsulatedContentInfo: %w", err)
	}

	var content []byte
	attached := encap.Content.FullBytes != nil
	switch {
	case attached && detached != nil:
		return nil, nil, nil, errors.New("pki: SignedData carries its content, but detached content was given")
	case !attached && detached == nil:
		return nil, nil, nil, errors.New("pki: SignedData carries no content and no detached content was given")
	case attached:
		if err := unmarshal(encap.Content.Bytes, &content); err != nil {
			return nil, nil, nil, fmt.Errorf("pki: eContent: %w", err)
		}
	default:
		content = detached
	}

	pool, err := sd.certificates()
	if err != nil {
		return nil, nil, nil, err
	}
	pool = append(pool, certs...)

	if len(sd.SignerInfos) == 0 {
		return nil, nil, nil, errors.New("pki: SignedData has no signers")
	}
	signers := make([]Signer, 0, len(sd.SignerInfos))
	for i, si := range sd.SignerInfos {
		cert, err := findCertificate(si.SID, pool)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pki: signer %d: %w", i, err)
		}
		signer, err := verifySignerInfo(si, encap.Type, content, cert, pool)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pki: signer %d (%s): %w", i, cert.Subject, err)
		}
		signers = append(signers, signer)
	}
	return encap.Type, content, signers, nil
}

// certificates returns the X.509 certificates of sd.
func (sd *signedData) certificates() ([]*x509.Certificate, error) {
	return certificateSet(sd.Certificates.Bytes)
}

// certificateSet returns the X.509 certificates in the content of a
// CertificateSet, of SignedData or of the OriginatorInfo of EnvelopedData.
func certificateSet(set []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := set; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil, fmt.Errorf("pki: certificates: %w", err)
		}
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			continue // attribute and other certificate formats
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("pki: certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// findCertificate returns the certificate of pool that id names: an
// IssuerAndSerialNumber or a [0] SubjectKeyIdentifier, as in a SignerInfo and
// the originator of a KeyAgreeRecipientInfo.
func findCertificate(id asn1.RawValue, pool []*x509.Certificate) (*x509.Certificate, error) {
	var match func(*x509.Certificate) bool
	if id.Class == asn1.ClassContextSpecific && id.Tag == 0 {
		match = func(c *x509.Certificate) bool { return bytes.Equal(c.SubjectKeyId, id.Bytes) }
	} else {
		var ias struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
		if err := unmarshal(id.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("certificate identifier: %w", err)
		}
		match = func(c *x509.Certificate) bool {
			return bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0
		}
	}
	if i := slices.IndexFunc(pool, match); i >= 0 {
		return pool[i], nil
	}
	return nil, errors.New("certificate not found")
}

// verifySignerInfo checks one signer: the signed attributes against the
// content, the signature over the attributes, or over the content when there
// are none, the signature time-stamp and the CAdES-X Long validation data
// when there are, with the issuers taken from pool.
func verifySignerInfo(si signerInfo, contentType asn1.ObjectIdentifier, content []byte, cert *x509.Certificate, pool []*x509.Certificate) (Signer, error) {
	signer := Signer{Certificate: cert}
	key, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return signer, err
	}
	_, littleEndian, err := signatureScheme(si.SignatureAlgorithm.Algorithm)
	if err != nil {
		return signer, err
	}
	h, err := newHash(si.DigestAlgorithm.Algorithm, key.DKE)
	if err != nil {
		return signer, err
	}

	signed := content
	if si.SignedAttrs.FullBytes != nil {
		// the signature covers the attributes with their universal SET tag (RFC 5652, 5.4)
		signed = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
		h.Write(content)
		if signer.SigningTime, err = checkSignedAttrs(signed, contentType, h.Sum(nil)); err != nil {
			return signer, err
		}
		h.Reset()
	}
	h.Write(signed)
	digest := h.Sum(nil)

	// IIT writes r||s itself; the Bouncy Castle JCA wraps it in a DER OCTET STRING
	var inner []byte
	if unmarshal(si.Signature, &inner) != nil || key.verify(digest, inner, littleEndian) != nil {
		if err := key.verify(digest, si.Signature, littleEndian); err != nil {
			return signer, err
		}
	}

	attrs, err := parseAttributes(si.UnsignedAttrs)
	if err != nil {
		return signer, fmt.Errorf("unsigned attributes: %w", err)
	}
	long, err := parseLongTermData(attrs)
	if err != nil {
		return signer, fmt.Errorf("validation data: %w", err)
	}
	// IIT leaves the TSA and OCSP responder certificates out of CAdES-X Long
	// for the verifier's CA certificate bundle
	pool = append(slices.Clone(pool), long.certs...)
	if i := slices.IndexFunc(attrs, func(a attribute) bool { return a.Type.Equal(oidSignatureTimeStamp) }); i >= 0 {
		var token asn1.RawValue // the first of the attribute's tokens
		if _, err := asn1.Unmarshal(attrs[i].Values.Bytes, &token); err != nil {
			return signer, fmt.Errorf("signature time-stamp: %w", err)
		}
		if signer.TimeStamp, _, err = verifyTimeStamp(token.FullBytes, si.Signature, pool); err != nil {
			return signer, fmt.Errorf("signature time-stamp: %w", err)
		}
	}
	if signer.Chain, signer.OCSP, err = long.verify(cert, pool); err != nil {
		return signer, fmt.Errorf("validation data: %w", err)
	}
	return signer, nil
}

// setUnsignedAttrs replaces the unsigned attributes of si with attrs.
func (si *signerInfo) setUnsignedAttrs(attrs []attribute) error {
	set, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return fmt.Errorf("pki: unsigned attributes: %w", err)
	}
	si.UnsignedAttrs = asn1.RawValue{FullBytes: append([]byte{0xa1}, set[1:]...)} // [1] IMPLICIT SET
	return nil
}

// parseAttributes reads a SET OF Attribute under any tag; an empty value has none.
func parseAttributes(set asn1.RawValue) ([]attribute, error) {
	if set.FullBytes == nil {
		return nil, nil
	}
	var attrs []attribute
	rest, err := asn1.UnmarshalWithParams(append([]byte{0x31}, set.FullBytes[1:]...), &attrs, "set")
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data")
	}
	return attrs, nil
}

// checkSignedAttrs checks that the signed attributes name the content type
// and carry the message digest of the content, each exactly once, and returns
// the signing time when there is one.
func checkSignedAttrs(set []byte, contentType asn1.ObjectIdentifier, digest []byte) (time.Time, error) {
	attrs, err := parseAttributes(asn1.RawValue{FullBytes: set})
	if err != nil {
		return time.Time{}, fmt.Errorf("signed attributes: %w", err)
	}
	value := func(oid asn1.ObjectIdentifier, v any) (bool, error) {
		i := slices.IndexFunc(attrs, func(a attribute) bool { return a.Type.Equal(oid) })
		if i < 0 {
			return false, nil
		}
		if err := unmarshal(attrs[i].Values.Bytes, v); err != nil {
			return true, fmt.Errorf("signed attribute %v: %w", oid, err)
		}
		return true, nil
	}

	var ct asn1.ObjectIdentifier
	if ok, err := value(oidContentType, &ct); err != nil || !ok {
		return time.Time{}, errors.Join(err, errors.New("signed attribute contentType is missing"))
	}
	if !ct.Equal(contentType) {
		return time.Time{}, fmt.Errorf("signed content type %v, but the content is %v", ct, contentType)
	}
	var md []byte
	if ok, err := value(oidMessageDigest, &md); err != nil || !ok {
		return time.Time{}, errors.Join(err, errors.New("signed attribute messageDigest is missing"))
	}
	if !bytes.Equal(md, digest) {
		return time.Time{}, fmt.Errorf("message digest: %w", ErrInvalidSignature)
	}
	var signingTime time.Time
	if _, err := value(oidSigningTime, &signingTime); err != nil {
		return time.Time{}, err
	}
	return signingTime, nil
}

// issuerSerial is the IssuerSerial of RFC 5035 that names a certificate.
type issuerSerial struct {
	Issuer []asn1.RawValue // GeneralNames with one directoryName
	Serial *big.Int
}

func newIssuerSerial(cert *x509.Certificate) issuerSerial {
	return issuerSerial{
		Issuer: []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: cert.RawIssuer}},
		Serial: cert.SerialNumber,
	}
}

// SignOptions select how SignData signs.
type SignOptions struct {
	Detached  bool // leave the content out of the SignedData, as in a .p7s next to the file
	GOST34311 bool // hash with GOST 34.311-95 instead of Kupyna-256
}

// SignData signs content with key and returns a DER CMS SignedData in the
// CAdES-BES form of Ukrainian qualified tools: the content type data, the
// certificate cert of key, and a signer identified by issuer and serial
// number with the signed attributes contentType, signingTime (now),
// messageDigest and signingCertificateV2. The hash is Kupyna-256 unless
// opts.GOST34311 is set; GOST 34.311 hashes the content and the attributes
// with the DKE of cert. The signature value is r||s little-endian. random,
// normally crypto/rand.Reader, provides the per-signature secret.
// AddSignatureTimeStamp turns the result into CAdES-T.
//
// SignData fails if key does not belong to cert.
func SignData(random io.Reader, content []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	sd, err := signContent(random, oidData, content, key, cert, opts, true)
	if err != nil {
		return nil, err
	}
	return sd.marshal()
}

// signContent is SignData for any content type, before marshalling; without
// signingTime the signed attributes leave it out, as PAdES requires.
func signContent(random io.Reader, contentType asn1.ObjectIdentifier, content []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions, signingTime bool) (*signedData, error) {
	pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	if !pub.belongsTo(key) {
		return nil, errors.New("pki: the private key does not belong to the certificate")
	}
	digestAlg, signatureAlg := oidKupyna256, oidDSTU4145Kupyna256
	if opts.GOST34311 {
		digestAlg, signatureAlg = oidGOST34311, oidDSTU4145LE
	}
	digest := func(data []byte, dke gost28147.Sbox) ([]byte, error) {
		h, err := newHash(digestAlg, dke)
		if err != nil {
			return nil, err
		}
		h.Write(data)
		return h.Sum(nil), nil
	}

	contentDigest, err := digest(content, pub.DKE)
	if err != nil {
		return nil, err
	}
	// Ukrainian tools hash the certificate with ДКЕ №1 whatever the key's DKE
	certHash, err := digest(cert.Raw, gost28147.DKE1())
	if err != nil {
		return nil, err
	}
	type essCertIDv2 struct {
		Hash         pkix.AlgorithmIdentifier
		CertHash     []byte
		IssuerSerial issuerSerial
	}
	signingCert := struct{ Certs []essCertIDv2 }{[]essCertIDv2{{
		Hash:         pkix.AlgorithmIdentifier{Algorithm: digestAlg},
		CertHash:     certHash,
		IssuerSerial: newIssuerSerial(cert),
	}}}

	var attrs []attribute
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value any
	}{
		{oidContentType, contentType},
		{oidSigningTime, time.Now().UTC().Truncate(time.Second)},
		{oidMessageDigest, contentDigest},
		{oidSigningCertV2, signingCert},
	} {
		if a.oid.Equal(oidSigningTime) && !signingTime {
			continue
		}
		v, err := asn1.Marshal(a.value)
		if err != nil {
			return nil, fmt.Errorf("pki: signed attribute %v: %w", a.oid, err)
		}
		attrs = append(attrs, attribute{Type: a.oid, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}})
	}
	signedAttrs, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, fmt.Errorf("pki: signed attributes: %w", err)
	}

	attrsDigest, err := digest(signedAttrs, pub.DKE)
	if err != nil {
		return nil, err
	}
	r, sv, err := dstu4145.Sign(random, key, attrsDigest)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	sid, err := asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: cert.RawIssuer}, cert.SerialNumber})
	if err != nil {
		return nil, fmt.Errorf("pki: certificate identifier: %w", err)
	}

	encap := struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"optional,explicit,tag:0"`
	}{Type: contentType}
	if !opts.Detached {
		encap.Content = content
	}
	rawEncap, err := asn1.Marshal(encap)
	if err != nil {
		return nil, fmt.Errorf("pki: EncapsulatedContentInfo: %w", err)
	}
	rawDigestAlgs, err := asn1.MarshalWithParams([]pkix.AlgorithmIdentifier{{Algorithm: digestAlg}}, "set")
	if err != nil {
		return nil, fmt.Errorf("pki: digest algorithms: %w", err)
	}
	version := 1
	if !contentType.Equal(oidData) {
		version = 3 // RFC 5652, 5.1
	}
	sd := signedData{
		Version:          version,
		DigestAlgorithms: asn1.RawValue{FullBytes: rawDigestAlgs},
		Encap:            asn1.RawValue{FullBytes: rawEncap},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos: []signerInfo{{
			Version:            1,
			SID:                asn1.RawValue{FullBytes: sid},
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestAlg},
			SignedAttrs:        asn1.RawValue{FullBytes: append([]byte{0xa0}, signedAttrs[1:]...)}, // [0] IMPLICIT SET
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureAlg},
			Signature:          dstu4145.MarshalSignature(key.Public().Curve(), r, sv),
		}},
	}
	return &sd, nil
}
