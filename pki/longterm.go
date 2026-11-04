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
	IssuerSerial issuerSerial `asn1:"optional"`
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

// AddValidationData turns CAdES-T into CAdES-X Long (RFC 5126, 6.3.4) as IIT
// writes it with "full CA data", the format the ЦЗО test examples name
// CAdES-X Long. For every signer it builds the path from the signer
// certificate to a self-signed root out of the certificates in signed and
// certs, asks ocsp about every certificate in the path but the root, and
// adds the unsigned attributes completeCertificateRefs and certValues over
// the CA certificates of the path, completeRevocationRefs with one
// reference per certificate of the path, and revocationValues with the
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
// returns the CAdES-X Long attributes with references hashed by alg. The
// responder is the issuer or carried in its response, so certValues holds
// the CAs of the path only.
func validationData(ctx context.Context, path []*x509.Certificate, ocsp *OCSPClient, alg asn1.ObjectIdentifier) ([]attribute, error) {
	// RFC 5126, 5.7.2: the signer's reference, then one per completeCertificateRefs entry
	revocationRefs := make([]crlOcspRef, len(path))
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
		var id ocspResponsesID
		id.Identifier.ResponderID = asn1.RawValue{FullBytes: resp.responderID}
		id.Identifier.ProducedAt = resp.ProducedAt
		if id.Hash, err = hashOf(alg, resp.basic); err != nil {
			return nil, err
		}
		revocationRefs[i].OCSP.Responses = []ocspResponsesID{id}
		ocspValues = append(ocspValues, asn1.RawValue{FullBytes: resp.basic})
	}
	cas := path[1:]
	certRefs := make([]otherCertID, 0, len(cas))
	certValues := make([]asn1.RawValue, 0, len(cas))
	for _, c := range cas {
		hash, err := hashOf(alg, c.Raw)
		if err != nil {
			return nil, err
		}
		certRefs = append(certRefs, otherCertID{Hash: hash, IssuerSerial: newIssuerSerial(c)})
		certValues = append(certValues, asn1.RawValue{FullBytes: c.Raw})
	}

	var attrs []attribute
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value any
	}{
		{oidCertificateRefs, certRefs},
		{oidRevocationRefs, revocationRefs},
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

// longTermData is the CAdES-C references and CAdES-X Long values of a signer.
type longTermData struct {
	certRefs       []otherCertID
	revocationRefs []crlOcspRef
	rawCerts       [][]byte // certValues
	certs          []*x509.Certificate
	basics         [][]byte // the BasicOCSPResponses of revocationValues
}

// parseLongTermData reads the CAdES-C and CAdES-X Long attributes among the
// unsigned attributes attrs.
func parseLongTermData(attrs []attribute) (longTermData, error) {
	var d longTermData
	var certValues []asn1.RawValue
	var revocations revocationValues
	for _, a := range attrs {
		var v any
		switch {
		case a.Type.Equal(oidCertificateRefs):
			v = &d.certRefs
		case a.Type.Equal(oidRevocationRefs):
			v = &d.revocationRefs
		case a.Type.Equal(oidCertValues):
			v = &certValues
		case a.Type.Equal(oidRevocationValues):
			v = &revocations
		default:
			continue
		}
		if err := unmarshal(a.Values.Bytes, v); err != nil {
			return longTermData{}, fmt.Errorf("attribute %v: %w", a.Type, err)
		}
	}
	for _, v := range certValues {
		c, err := x509.ParseCertificate(v.FullBytes)
		if err != nil {
			return longTermData{}, fmt.Errorf("certValues: %w", err)
		}
		d.rawCerts = append(d.rawCerts, v.FullBytes)
		d.certs = append(d.certs, c)
	}
	for _, v := range revocations.OCSP {
		d.basics = append(d.basics, v.FullBytes)
	}
	return d, nil
}

// verify checks d for the signer with cert: every reference names a value,
// the certificates make a path to a self-signed root, and every OCSP
// response about a certificate of the path verifies. A signer without
// values has nil path and responses; responses[i] is about path[i], nil when
// there is none.
func (d longTermData) verify(cert *x509.Certificate, pool []*x509.Certificate) ([]*x509.Certificate, []*OCSPResponse, error) {
	if d.rawCerts == nil && d.basics == nil {
		return nil, nil, nil // CAdES-C references alone name values kept elsewhere
	}
	for _, ref := range d.certRefs {
		if err := referenced(ref.Hash, d.rawCerts); err != nil {
			return nil, nil, fmt.Errorf("completeCertificateRefs: %w", err)
		}
	}
	for _, ref := range d.revocationRefs {
		for _, id := range ref.OCSP.Responses {
			if id.Hash.Algorithm.Algorithm == nil {
				continue // without ocspRepHash a reference names no value
			}
			if err := referenced(id.Hash, d.basics); err != nil {
				return nil, nil, fmt.Errorf("completeRevocationRefs: %w", err)
			}
		}
	}

	path, err := certificatePath(cert, pool)
	if err != nil {
		return nil, nil, err
	}
	responses := make([]*OCSPResponse, len(path)-1)
	for i, c := range path[:len(path)-1] {
		resp, err := findOCSPResponse(d.basics, c, path[i+1], pool)
		if errors.Is(err, errNoStatus) {
			continue // IIT stores no response about the CAs without "full CA data"
		}
		if err != nil {
			return nil, nil, err
		}
		responses[i] = resp
	}
	return path, responses, nil
}

// findOCSPResponse returns the first of the BasicOCSPResponses basics about
// cert issued by issuer, verified with the responder taken from the response
// or from pool; errNoStatus when none is about cert.
func findOCSPResponse(basics [][]byte, cert, issuer *x509.Certificate, pool []*x509.Certificate) (*OCSPResponse, error) {
	type responseBytes struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}
	for _, basic := range basics {
		der, err := asn1.Marshal(struct {
			Status asn1.Enumerated
			Bytes  responseBytes `asn1:"explicit,tag:0"`
		}{0, responseBytes{oidOCSPBasic, basic}})
		if err != nil {
			return nil, fmt.Errorf("OCSPResponse: %w", err)
		}
		resp, _, err := parseOCSPResponse(der, cert.SerialNumber, issuer, pool)
		if errors.Is(err, errNoStatus) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("OCSP response about %s: %w", cert.Subject, err)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("%w %x of %s", errNoStatus, cert.SerialNumber, issuer.Subject)
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
