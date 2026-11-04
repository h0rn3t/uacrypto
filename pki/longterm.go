package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/h0rn3t/uacrypto/gost28147"
)

// The CAdES-C and CAdES-X Long attributes of RFC 5126.
var (
	oidCertificateRefs  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 21}
	oidRevocationRefs   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 22}
	oidCertValues       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}
	oidRevocationValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}
)

// otherHash is the OtherHashAlgAndValue form of OtherHash; the bare SHA-1
// form is not read.
type otherHash struct {
	Algorithm pkix.AlgorithmIdentifier
	Value     []byte
}

type otherCertID struct {
	Hash         otherHash
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type ocspResponsesID struct {
	Identifier struct {
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
	}
	Hash otherHash `asn1:"optional"`
}

type crlOcspRef struct {
	CRLs  asn1.RawValue                         `asn1:"optional,tag:0"`
	OCSP  struct{ Responses []ocspResponsesID } `asn1:"optional,explicit,tag:1"`
	Other asn1.RawValue                         `asn1:"optional,tag:2"`
}

type revocationValues struct {
	CRLs  asn1.RawValue   `asn1:"optional,tag:0"`
	OCSP  []asn1.RawValue `asn1:"optional,explicit,tag:1"` // BasicOCSPResponse
	Other asn1.RawValue   `asn1:"optional,tag:2"`
}

// hashOf returns the OtherHash of data under the digest algorithm alg; GOST
// 34.311 uses ДКЕ №1, as Ukrainian tools do.
func hashOf(alg asn1.ObjectIdentifier, data []byte) (otherHash, error) {
	h, err := newHash(alg, gost28147.DKE1())
	if err != nil {
		return otherHash{}, err
	}
	h.Write(data)
	return otherHash{pkix.AlgorithmIdentifier{Algorithm: alg}, h.Sum(nil)}, nil
}

// AddValidationData turns CAdES-T into CAdES-X Long (RFC 5126, 6.3.4), the
// long-term validation data that Ukrainian qualified tools write. For every
// signer it builds the path from the signer certificate to a self-signed
// root out of the certificates in signed and certs, asks ocsp about every
// certificate in the path but the root, and adds the unsigned attributes
// completeCertificateRefs and certValues over the CA and OCSP responder
// certificates, and completeRevocationRefs and revocationValues over the
// responses. The references hash with the signer's digest algorithm.
//
// Every signer must have a signature time-stamp and no validation data yet,
// and every certificate must be good. With ocsp.URL empty, each certificate
// is checked at the OCSP server it names.
func AddValidationData(ctx context.Context, signed []byte, certs []*x509.Certificate, ocsp *OCSPClient) ([]byte, error) {
	sd, err := parseSignedData(signed)
	if err != nil {
		return nil, err
	}
	pool, err := sd.certificates()
	if err != nil {
		return nil, err
	}
	pool = append(pool, certs...)
	for i := range sd.SignerInfos {
		si := &sd.SignerInfos[i]
		attrs, err := parseAttributes(si.UnsignedAttrs)
		if err != nil {
			return nil, fmt.Errorf("pki: signer %d unsigned attributes: %w", i, err)
		}
		has := func(oid asn1.ObjectIdentifier) bool {
			return slices.ContainsFunc(attrs, func(a attribute) bool { return a.Type.Equal(oid) })
		}
		if !has(oidSignatureTimeStamp) {
			return nil, fmt.Errorf("pki: signer %d has no signature time-stamp: add it with AddSignatureTimeStamp", i)
		}
		if has(oidCertValues) || has(oidRevocationValues) {
			return nil, fmt.Errorf("pki: signer %d already has validation data", i)
		}
		cert, err := findSigner(si.SID, pool)
		if err != nil {
			return nil, fmt.Errorf("pki: signer %d: %w", i, err)
		}
		path, err := certificatePath(cert, pool)
		if err != nil {
			return nil, err
		}
		long, err := validationData(ctx, path, ocsp, si.DigestAlgorithm.Algorithm)
		if err != nil {
			return nil, err
		}
		if err := si.setUnsignedAttrs(append(attrs, long...)); err != nil {
			return nil, err
		}
	}
	return sd.marshal()
}

// validationData asks ocsp about every certificate of path but the root and
// returns the CAdES-X Long attributes with references hashed by alg.
func validationData(ctx context.Context, path []*x509.Certificate, ocsp *OCSPClient, alg asn1.ObjectIdentifier) ([]attribute, error) {
	certs := slices.Clone(path[1:])
	var ocspIDs []ocspResponsesID
	var ocspValues []asn1.RawValue
	for i, cert := range path[:len(path)-1] {
		resp, err := ocsp.Check(ctx, cert, path[i+1])
		if err != nil {
			return nil, err
		}
		switch resp.Status {
		case OCSPGood:
		case OCSPRevoked:
			return nil, fmt.Errorf("pki: certificate %s was revoked at %v", cert.Subject, resp.RevokedAt)
		case OCSPUnknown:
			return nil, fmt.Errorf("pki: the OCSP responder does not know certificate %s", cert.Subject)
		}
		if !resp.Certificate.Equal(path[0]) && !slices.ContainsFunc(certs, resp.Certificate.Equal) {
			certs = append(certs, resp.Certificate)
		}
		var id ocspResponsesID
		id.Identifier.ResponderID = asn1.RawValue{FullBytes: resp.responderID}
		id.Identifier.ProducedAt = resp.ProducedAt
		if id.Hash, err = hashOf(alg, resp.basic); err != nil {
			return nil, err
		}
		ocspIDs = append(ocspIDs, id)
		ocspValues = append(ocspValues, asn1.RawValue{FullBytes: resp.basic})
	}
	certRefs := make([]otherCertID, 0, len(certs))
	certValues := make([]asn1.RawValue, 0, len(certs))
	for _, c := range certs {
		hash, err := hashOf(alg, c.Raw)
		if err != nil {
			return nil, err
		}
		certRefs = append(certRefs, otherCertID{Hash: hash})
		certValues = append(certValues, asn1.RawValue{FullBytes: c.Raw})
	}
	var revocationRef crlOcspRef
	revocationRef.OCSP.Responses = ocspIDs

	var attrs []attribute
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value any
	}{
		{oidCertificateRefs, certRefs},
		{oidRevocationRefs, []crlOcspRef{revocationRef}},
		{oidCertValues, certValues},
		{oidRevocationValues, revocationValues{OCSP: ocspValues}},
	} {
		v, err := asn1.Marshal(a.value)
		if err != nil {
			return nil, fmt.Errorf("pki: unsigned attribute %v: %w", a.oid, err)
		}
		attrs = append(attrs, attribute{Type: a.oid, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}})
	}
	return attrs, nil
}

// certificatePath returns the path from cert to a self-signed certificate,
// each certificate signed by the next, with the issuers taken from pool.
func certificatePath(cert *x509.Certificate, pool []*x509.Certificate) ([]*x509.Certificate, error) {
	path := []*x509.Certificate{cert}
	for c := cert; !bytes.Equal(c.RawIssuer, c.RawSubject) || CheckCertificateSignature(c, c) != nil; {
		i := slices.IndexFunc(pool, func(p *x509.Certificate) bool {
			return bytes.Equal(p.RawSubject, c.RawIssuer) && !slices.ContainsFunc(path, p.Equal) && CheckCertificateSignature(c, p) == nil
		})
		if i < 0 {
			return nil, fmt.Errorf("pki: the issuer of %s is not known", c.Subject)
		}
		c = pool[i]
		path = append(path, c)
	}
	return path, nil
}

// verifyValidationData checks the CAdES-X Long values in the unsigned
// attributes attrs of the signer with cert: every reference names a value,
// the certificates make a path to a self-signed root, and every certificate
// in it but the root has a verified OCSP response. A signer without values
// has nil path and responses.
func verifyValidationData(attrs []attribute, cert *x509.Certificate, pool []*x509.Certificate) ([]*x509.Certificate, []*OCSPResponse, error) {
	var certRefs []otherCertID
	var revocationRefs []crlOcspRef
	var certValues []asn1.RawValue
	var revocations revocationValues
	for _, a := range attrs {
		var v any
		switch {
		case a.Type.Equal(oidCertificateRefs):
			v = &certRefs
		case a.Type.Equal(oidRevocationRefs):
			v = &revocationRefs
		case a.Type.Equal(oidCertValues):
			v = &certValues
		case a.Type.Equal(oidRevocationValues):
			v = &revocations
		default:
			continue
		}
		if err := unmarshal(a.Values.Bytes, v); err != nil {
			return nil, nil, fmt.Errorf("attribute %v: %w", a.Type, err)
		}
	}
	if certValues == nil && revocations.OCSP == nil {
		return nil, nil, nil
	}

	rawCerts := make([][]byte, 0, len(certValues))
	pool = slices.Clone(pool)
	for _, v := range certValues {
		c, err := x509.ParseCertificate(v.FullBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("certValues: %w", err)
		}
		rawCerts = append(rawCerts, v.FullBytes)
		pool = append(pool, c)
	}
	basics := make([][]byte, 0, len(revocations.OCSP))
	for _, v := range revocations.OCSP {
		basics = append(basics, v.FullBytes)
	}
	for _, ref := range certRefs {
		if err := referenced(ref.Hash, rawCerts); err != nil {
			return nil, nil, fmt.Errorf("completeCertificateRefs: %w", err)
		}
	}
	for _, ref := range revocationRefs {
		for _, id := range ref.OCSP.Responses {
			if id.Hash.Algorithm.Algorithm == nil {
				continue // without ocspRepHash a reference names no value
			}
			if err := referenced(id.Hash, basics); err != nil {
				return nil, nil, fmt.Errorf("completeRevocationRefs: %w", err)
			}
		}
	}

	path, err := certificatePath(cert, pool)
	if err != nil {
		return nil, nil, err
	}
	responses := make([]*OCSPResponse, 0, len(path)-1)
	for i, c := range path[:len(path)-1] {
		resp, err := findOCSPResponse(basics, c, path[i+1])
		if err != nil {
			return nil, nil, err
		}
		responses = append(responses, resp)
	}
	return path, responses, nil
}

// findOCSPResponse returns the first of the BasicOCSPResponses basics that
// ParseOCSPResponse accepts about cert issued by issuer.
func findOCSPResponse(basics [][]byte, cert, issuer *x509.Certificate) (*OCSPResponse, error) {
	type responseBytes struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}
	errs := fmt.Errorf("no OCSP response about %s", cert.Subject)
	for _, basic := range basics {
		der, err := asn1.Marshal(struct {
			Status asn1.Enumerated
			Bytes  responseBytes `asn1:"explicit,tag:0"`
		}{0, responseBytes{oidOCSPBasic, basic}})
		if err != nil {
			return nil, fmt.Errorf("OCSPResponse: %w", err)
		}
		resp, err := ParseOCSPResponse(der, cert.SerialNumber, issuer)
		if err == nil {
			return resp, nil
		}
		errs = errors.Join(errs, err)
	}
	return nil, errs
}

// referenced checks that ref is the hash of one of values.
func referenced(ref otherHash, values [][]byte) error {
	for _, v := range values {
		hash, err := hashOf(ref.Algorithm.Algorithm, v)
		if err != nil {
			return err
		}
		if bytes.Equal(hash.Value, ref.Value) {
			return nil
		}
	}
	return fmt.Errorf("the %v hash %x names no value", ref.Algorithm.Algorithm, ref.Value)
}
