package pki

import (
	"crypto/md5"  //nolint:gosec // G501: a CertID hash identifies a certificate the client names; it signs nothing
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is the usual CertID hash of RFC 6960
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
)

// certIDHashes are the hashes of a CertID that Bouncy Castle matches,
// besides GOST 34.311 and Kupyna.
var certIDHashes = map[string]func() hash.Hash{
	"1.2.840.113549.2.5":      md5.New,
	"1.3.14.3.2.26":           sha1.New,
	"2.16.840.1.101.3.4.2.4":  sha256.New224,
	"2.16.840.1.101.3.4.2.1":  sha256.New,
	"2.16.840.1.101.3.4.2.2":  sha512.New384,
	"2.16.840.1.101.3.4.2.3":  sha512.New,
	"2.16.840.1.101.3.4.2.5":  sha512.New512_224,
	"2.16.840.1.101.3.4.2.6":  sha512.New512_256,
	"2.16.840.1.101.3.4.2.7":  func() hash.Hash { return sha3.New224() },
	"2.16.840.1.101.3.4.2.8":  func() hash.Hash { return sha3.New256() },
	"2.16.840.1.101.3.4.2.9":  func() hash.Hash { return sha3.New384() },
	"2.16.840.1.101.3.4.2.10": func() hash.Hash { return sha3.New512() },
}

// certIDHash returns the hash of a CertID under alg: GOST 34.311 with
// ДКЕ №1, Kupyna, SHA-1, SHA-2, SHA-3 or MD5.
func certIDHash(alg asn1.ObjectIdentifier) (hash.Hash, error) {
	if h, ok := certIDHashes[alg.String()]; ok {
		return h(), nil
	}
	return newHash(alg, gost28147.DKE1())
}

// An OCSPCertID names a certificate in an OCSP request (RFC 6960, 4.1.1):
// hashes of the name and the key of its issuer, and its serial number.
type OCSPCertID struct {
	HashAlgorithm  asn1.ObjectIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
	Raw            []byte // DER, as the request carried it
}

// IssuedBy reports whether id names a certificate of issuer: the hashes of
// the issuer name and key under HashAlgorithm match. A hash other than
// GOST 34.311 (ДКЕ №1), Kupyna, SHA-1, SHA-2, SHA-3 and MD5, which Bouncy
// Castle responders accept, wraps x509.ErrUnsupportedAlgorithm.
func (id *OCSPCertID) IssuedBy(issuer *x509.Certificate) (bool, error) {
	want, err := newCertID(id.HashAlgorithm, id.SerialNumber, issuer)
	if err != nil {
		return false, err
	}
	return string(id.IssuerNameHash) == string(want.NameHash) && string(id.IssuerKeyHash) == string(want.KeyHash), nil
}

// An OCSPRequest is an OCSP request (RFC 6960) as a responder reads it.
type OCSPRequest struct {
	CertIDs    []OCSPCertID
	Extensions []pkix.Extension // requestExtensions, the nonce among them
}

// ParseOCSPRequest parses an OCSP request in DER or BER. The request
// signature and requestor name, if any, are not read.
func ParseOCSPRequest(der []byte) (*OCSPRequest, error) {
	der, err := toDER(der)
	if err != nil {
		return nil, err
	}
	var req struct {
		TBS struct {
			Version   int           `asn1:"optional,explicit,default:0,tag:0"`
			Requestor asn1.RawValue `asn1:"optional,explicit,tag:1"`
			Requests  []struct {
				CertID     asn1.RawValue
				Extensions asn1.RawValue `asn1:"optional,explicit,tag:0"`
			}
			Extensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
		}
		Signature asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	if err := unmarshal(der, &req); err != nil {
		return nil, fmt.Errorf("pki: OCSPRequest: %w", err)
	}
	if len(req.TBS.Requests) == 0 {
		return nil, errors.New("pki: the OCSP request names no certificate")
	}
	r := &OCSPRequest{Extensions: req.TBS.Extensions}
	for _, single := range req.TBS.Requests {
		var id certID
		if err := unmarshal(single.CertID.FullBytes, &id); err != nil {
			return nil, fmt.Errorf("pki: CertID: %w", err)
		}
		r.CertIDs = append(r.CertIDs, OCSPCertID{
			HashAlgorithm:  id.HashAlgorithm.Algorithm,
			IssuerNameHash: id.NameHash,
			IssuerKeyHash:  id.KeyHash,
			SerialNumber:   id.Serial,
			Raw:            single.CertID.FullBytes,
		})
	}
	return r, nil
}

// An OCSPSingleResponse is the status of one certificate in a response that
// CreateOCSPResponse signs.
type OCSPSingleResponse struct {
	CertID OCSPCertID // its Raw is written as it is when set
	Status OCSPStatus

	// RevokedAt and RevocationReason, a CRLReason code, are written for
	// OCSPRevoked only.
	RevokedAt        time.Time
	RevocationReason int

	ThisUpdate time.Time
	NextUpdate time.Time // zero: none
}

// An OCSPResponseTemplate is the content of a response that
// CreateOCSPResponse signs.
type OCSPResponseTemplate struct {
	ProducedAt time.Time
	Responses  []OCSPSingleResponse
	Extensions []pkix.Extension // responseExtensions, such as the nonce of the request
}

// CreateOCSPResponse returns a successful DER OCSP response (RFC 6960) with
// the basic response of template, signed by key with DSTU 4145 and
// GOST 34.311 (dstu4145le) under the DKE of responder's key, naming
// responder by its subject and carrying its certificate. key must belong to
// responder. A revoked status always carries its reason.
func CreateOCSPResponse(random io.Reader, template *OCSPResponseTemplate, responder *x509.Certificate, key *dstu4145.PrivateKey) ([]byte, error) {
	responderKey, err := ParsePublicKey(responder.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	if !responderKey.belongsTo(key) {
		return nil, errors.New("pki: the private key does not belong to the OCSP responder")
	}

	type singleResponse struct {
		CertID     asn1.RawValue
		Status     asn1.RawValue
		ThisUpdate time.Time `asn1:"generalized"`
		NextUpdate time.Time `asn1:"optional,explicit,generalized,tag:0"`
	}
	singles := make([]singleResponse, 0, len(template.Responses))
	for _, r := range template.Responses {
		id := r.CertID.Raw
		if id == nil {
			if id, err = asn1.Marshal(certID{
				HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: r.CertID.HashAlgorithm},
				NameHash:      r.CertID.IssuerNameHash,
				KeyHash:       r.CertID.IssuerKeyHash,
				Serial:        r.CertID.SerialNumber,
			}); err != nil {
				return nil, fmt.Errorf("pki: CertID: %w", err)
			}
		}
		status := asn1.RawValue{Class: asn1.ClassContextSpecific} // good [0] IMPLICIT NULL
		switch r.Status {
		case OCSPGood:
		case OCSPRevoked:
			// RevokedInfo in [1] IMPLICIT: revocationTime, [0] EXPLICIT revocationReason
			revokedAt, err := asn1.MarshalWithParams(r.RevokedAt.UTC(), "generalized")
			if err != nil {
				return nil, fmt.Errorf("pki: revocation time: %w", err)
			}
			reason, err := asn1.MarshalWithParams(asn1.Enumerated(r.RevocationReason), "explicit,tag:0")
			if err != nil {
				return nil, fmt.Errorf("pki: revocation reason: %w", err)
			}
			status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: append(revokedAt, reason...)}
		case OCSPUnknown:
			status.Tag = 2
		default:
			return nil, fmt.Errorf("pki: OCSP status %d", r.Status)
		}
		var next time.Time
		if !r.NextUpdate.IsZero() {
			next = r.NextUpdate.UTC()
		}
		singles = append(singles, singleResponse{asn1.RawValue{FullBytes: id}, status, r.ThisUpdate.UTC(), next})
	}

	tbs, err := asn1.Marshal(struct {
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []singleResponse
		Extensions  []pkix.Extension `asn1:"optional,explicit,tag:1"`
	}{
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: responder.RawSubject}, // byName
		template.ProducedAt.UTC(),
		singles,
		template.Extensions,
	})
	if err != nil {
		return nil, fmt.Errorf("pki: ResponseData: %w", err)
	}
	signature, err := signDSTU(random, key, responderKey.DKE, tbs)
	if err != nil {
		return nil, err
	}
	basic, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
		Certs     []asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		asn1.RawValue{FullBytes: tbs},
		pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE},
		asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
		[]asn1.RawValue{{FullBytes: responder.Raw}},
	})
	if err != nil {
		return nil, fmt.Errorf("pki: BasicOCSPResponse: %w", err)
	}
	type responseBytes struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}
	return asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  responseBytes `asn1:"explicit,tag:0"`
	}{0, responseBytes{oidOCSPBasic, basic}})
}
