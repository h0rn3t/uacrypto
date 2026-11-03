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

// VerifySignedData verifies a DER CMS SignedData (RFC 5652) whose signers use
// DSTU 4145, as IIT-compatible software, Ukrainian TSAs and Bouncy Castle
// write it. Every SignerInfo must verify. When the SignedData carries no
// content, detached is the signed content; otherwise detached must be nil.
// The signer certificates are looked up in the SignedData and then in certs.
//
// VerifySignedData returns the content and the certificate of each signer in
// SignerInfo order. It checks signatures only: the signer certificates are
// not checked against any trust anchor. A signature or message digest that
// does not match is ErrInvalidSignature.
func VerifySignedData(der, detached []byte, certs []*x509.Certificate) (content []byte, signers []*x509.Certificate, err error) {
	// encoding/asn1 keeps the [0] EXPLICIT wrapper in a RawValue: Bytes is the inner value
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if err := unmarshal(der, &ci); err != nil {
		return nil, nil, fmt.Errorf("pki: ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, nil, fmt.Errorf("pki: content type %v is not SignedData", ci.ContentType)
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		Encap            struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		Certificates asn1.RawValue `asn1:"optional,tag:0"`
		CRLs         asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos  []signerInfo  `asn1:"set"`
	}
	if err := unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, nil, fmt.Errorf("pki: SignedData: %w", err)
	}

	attached := sd.Encap.Content.FullBytes != nil
	switch {
	case attached && detached != nil:
		return nil, nil, errors.New("pki: SignedData carries its content, but detached content was given")
	case !attached && detached == nil:
		return nil, nil, errors.New("pki: SignedData carries no content and no detached content was given")
	case attached:
		if err := unmarshal(sd.Encap.Content.Bytes, &content); err != nil {
			return nil, nil, fmt.Errorf("pki: eContent: %w", err)
		}
	default:
		content = detached
	}

	pool := slices.Clone(certs)
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil, nil, fmt.Errorf("pki: SignedData certificates: %w", err)
		}
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			continue // attribute and other certificate formats
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: SignedData certificate: %w", err)
		}
		pool = append(pool, c)
	}

	if len(sd.SignerInfos) == 0 {
		return nil, nil, errors.New("pki: SignedData has no signers")
	}
	for i, si := range sd.SignerInfos {
		cert, err := findSigner(si.SID, pool)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: signer %d: %w", i, err)
		}
		if err := verifySignerInfo(si, sd.Encap.Type, content, cert); err != nil {
			return nil, nil, fmt.Errorf("pki: signer %d (%s): %w", i, cert.Subject, err)
		}
		signers = append(signers, cert)
	}
	return content, signers, nil
}

// findSigner returns the certificate that sid names.
func findSigner(sid asn1.RawValue, pool []*x509.Certificate) (*x509.Certificate, error) {
	var match func(*x509.Certificate) bool
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		match = func(c *x509.Certificate) bool { return bytes.Equal(c.SubjectKeyId, sid.Bytes) }
	} else {
		var ias struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
		if err := unmarshal(sid.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("signer identifier: %w", err)
		}
		match = func(c *x509.Certificate) bool {
			return bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0
		}
	}
	if i := slices.IndexFunc(pool, match); i >= 0 {
		return pool[i], nil
	}
	return nil, errors.New("signer certificate not found")
}

// verifySignerInfo checks one signer: the signed attributes against the
// content, then the signature over the attributes, or over the content when
// there are none.
func verifySignerInfo(si signerInfo, contentType asn1.ObjectIdentifier, content []byte, cert *x509.Certificate) error {
	key, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	_, littleEndian, err := signatureScheme(si.SignatureAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	h, err := newHash(si.DigestAlgorithm.Algorithm, key.DKE)
	if err != nil {
		return err
	}

	signed := content
	if si.SignedAttrs.FullBytes != nil {
		// the signature covers the attributes with their universal SET tag (RFC 5652, 5.4)
		signed = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
		h.Write(content)
		if err := checkSignedAttrs(signed, contentType, h.Sum(nil)); err != nil {
			return err
		}
		h.Reset()
	}
	h.Write(signed)
	digest := h.Sum(nil)

	// IIT writes r||s itself; the Bouncy Castle JCA wraps it in a DER OCTET STRING
	var inner []byte
	if unmarshal(si.Signature, &inner) == nil {
		if err := key.verify(digest, inner, littleEndian); err == nil {
			return nil
		}
	}
	return key.verify(digest, si.Signature, littleEndian)
}

// checkSignedAttrs checks that the signed attributes name the content type
// and carry the message digest of the content, each exactly once.
func checkSignedAttrs(set []byte, contentType asn1.ObjectIdentifier, digest []byte) error {
	var attrs []attribute
	rest, err := asn1.UnmarshalWithParams(set, &attrs, "set")
	if err != nil {
		return fmt.Errorf("signed attributes: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("signed attributes: trailing data")
	}
	single := func(oid asn1.ObjectIdentifier, v any) error {
		i := slices.IndexFunc(attrs, func(a attribute) bool { return a.Type.Equal(oid) })
		if i < 0 {
			return fmt.Errorf("signed attribute %v is missing", oid)
		}
		if err := unmarshal(attrs[i].Values.Bytes, v); err != nil {
			return fmt.Errorf("signed attribute %v: %w", oid, err)
		}
		return nil
	}

	var ct asn1.ObjectIdentifier
	if err := single(oidContentType, &ct); err != nil {
		return err
	}
	if !ct.Equal(contentType) {
		return fmt.Errorf("signed content type %v, but the content is %v", ct, contentType)
	}
	var md []byte
	if err := single(oidMessageDigest, &md); err != nil {
		return err
	}
	if !bytes.Equal(md, digest) {
		return fmt.Errorf("message digest: %w", ErrInvalidSignature)
	}
	return nil
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
//
// SignData fails if key does not belong to cert.
func SignData(random io.Reader, content []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	if pub.Key.Curve() != key.Public().Curve() || !bytes.Equal(pub.Key.Bytes(), key.Public().Bytes()) {
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
	type issuerSerial struct {
		Issuer []asn1.RawValue // GeneralNames with one directoryName
		Serial *big.Int
	}
	type essCertIDv2 struct {
		Hash         pkix.AlgorithmIdentifier
		CertHash     []byte
		IssuerSerial issuerSerial
	}
	signingCert := struct{ Certs []essCertIDv2 }{[]essCertIDv2{{
		Hash:     pkix.AlgorithmIdentifier{Algorithm: digestAlg},
		CertHash: certHash,
		IssuerSerial: issuerSerial{
			Issuer: []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: cert.RawIssuer}},
			Serial: cert.SerialNumber,
		},
	}}}

	var attrs []attribute
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value any
	}{
		{oidContentType, oidData},
		{oidSigningTime, time.Now().UTC().Truncate(time.Second)},
		{oidMessageDigest, contentDigest},
		{oidSigningCertV2, signingCert},
	} {
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
		return nil, fmt.Errorf("pki: signer identifier: %w", err)
	}
	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestAlg},
		SignedAttrs:        asn1.RawValue{FullBytes: append([]byte{0xa0}, signedAttrs[1:]...)}, // [0] IMPLICIT SET
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureAlg},
		Signature:          dstu4145.MarshalSignature(key.Public().Curve(), r, sv),
	}

	encap := struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"optional,explicit,tag:0"`
	}{Type: oidData}
	if !opts.Detached {
		encap.Content = content
	}
	sd, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		Encap            any
		Certificates     asn1.RawValue
		SignerInfos      []signerInfo `asn1:"set"`
	}{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestAlg}},
		Encap:            encap,
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos:      []signerInfo{si},
	})
	if err != nil {
		return nil, fmt.Errorf("pki: SignedData: %w", err)
	}
	return asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}
