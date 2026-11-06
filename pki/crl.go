package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/h0rn3t/uacrypto/dstu4145"
)

var oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// reasonRemoveFromCRL is the CRLReason of a delta CRL entry that releases a
// certificate on hold.
const reasonRemoveFromCRL = 8

// ParseRevocationList parses a DER certificate revocation list that issuer
// signed with DSTU 4145, the full or delta CRL of a Ukrainian CA, and checks
// it: the issuer name, the authority key identifier when both have one, the
// cRLSign key usage of issuer when it lists key usages, and the signature. A
// signature that does not verify is ErrInvalidSignature. crypto/x509 parses
// the list; ParseRevocationList does not check its ThisUpdate and NextUpdate.
func ParseRevocationList(der []byte, issuer *x509.Certificate) (*x509.RevocationList, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return nil, fmt.Errorf("pki: the CRL of %s is not issued by %s", crl.Issuer, issuer.Subject)
	}
	if crl.AuthorityKeyId != nil && issuer.SubjectKeyId != nil && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return nil, fmt.Errorf("pki: the CRL of %s is signed by another key of the CA", crl.Issuer)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("pki: %s may not sign CRLs", issuer.Subject)
	}
	if err := checkSignedBy(crl.Raw, crl.RawTBSRevocationList, issuer); err != nil {
		return nil, err
	}
	return crl, nil
}

// CreateRevocationList issues a CRL as crypto/x509.CreateRevocationList does,
// signed by key with DSTU 4145 and GOST 34.311 (dstu4145le), hashed with the
// DKE of the issuer's key; key must belong to issuer. The template fields are
// those of crypto/x509, which takes the authority key identifier from
// issuer.SubjectKeyId and requires the cRLSign key usage. A delta CRL carries
// the critical delta CRL indicator (2.5.29.27, the number of its base CRL) and
// a full CRL of Ukrainian CAs the freshest CRL extension (2.5.29.46, where the
// delta is), both in ExtraExtensions.
func CreateRevocationList(random io.Reader, template *x509.RevocationList, issuer *x509.Certificate, key *dstu4145.PrivateKey) ([]byte, error) {
	issuerKey, err := ParsePublicKey(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	if !issuerKey.belongsTo(key) {
		return nil, errors.New("pki: the private key does not belong to the issuer")
	}
	// as in CreateCertificate: crypto/x509 builds the TBSCertList for a stand-in key
	standIn, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	tmpl := *template
	tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	der, err := x509.CreateRevocationList(rand.Reader, &tmpl, issuer, standIn)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	// TBSCertList: version, signature, issuer, thisUpdate, nextUpdate, …
	return resignDSTU(random, der, 1, nil, key, issuerKey.DKE)
}

// RevocationStatus reports whether full, a full CRL, and delta, a delta CRL
// on it or nil, as ParseRevocationList returned them for the issuer of the
// certificate, revoke the certificate with serial number serial, and returns
// the entry that does. An entry of delta takes precedence, and one with the
// reason removeFromCRL releases a certificate that full holds. Of several
// entries for the certificate in one CRL the latest counts. A certificate on
// hold is revoked with the reason certificateHold. Check ThisUpdate and
// NextUpdate of the CRLs against the time you need.
//
// RevocationStatus fails if full is a delta CRL, delta is not one, delta is of
// another CA or key, or its base CRL is newer than full.
func RevocationStatus(serial *big.Int, full, delta *x509.RevocationList) (entry *x509.RevocationListEntry, revoked bool, err error) {
	if _, isDelta, err := deltaBase(full); err != nil || isDelta {
		return nil, false, fmt.Errorf("pki: the full CRL %v is a delta CRL or malformed: %v", full.Number, err)
	}
	if delta != nil {
		base, isDelta, err := deltaBase(delta)
		switch {
		case err != nil:
			return nil, false, err
		case !isDelta:
			return nil, false, fmt.Errorf("pki: CRL %v is not a delta CRL", delta.Number)
		case !bytes.Equal(delta.RawIssuer, full.RawIssuer) || !bytes.Equal(delta.AuthorityKeyId, full.AuthorityKeyId):
			return nil, false, errors.New("pki: the delta CRL is of another CA or key than the full CRL")
		case full.Number == nil || base.Cmp(full.Number) > 0:
			return nil, false, fmt.Errorf("pki: the delta CRL is on CRL %v, newer than the full CRL %v", base, full.Number)
		}
		if e := latestEntry(delta, serial); e != nil {
			return e, e.ReasonCode != reasonRemoveFromCRL, nil
		}
	}
	e := latestEntry(full, serial)
	return e, e != nil, nil
}

// deltaBase returns the base CRL number of the delta CRL indicator of crl;
// isDelta is false when crl has none.
func deltaBase(crl *x509.RevocationList) (base *big.Int, isDelta bool, err error) {
	for _, e := range crl.Extensions {
		if e.Id.Equal(oidDeltaCRLIndicator) {
			base = new(big.Int)
			if err := unmarshal(e.Value, &base); err != nil {
				return nil, false, fmt.Errorf("pki: delta CRL indicator: %w", err)
			}
			return base, true, nil
		}
	}
	return nil, false, nil
}

// latestEntry returns the entry of crl for serial with the latest revocation
// time, nil when there is none.
func latestEntry(crl *x509.RevocationList, serial *big.Int) *x509.RevocationListEntry {
	var latest *x509.RevocationListEntry
	for i := range crl.RevokedCertificateEntries {
		e := &crl.RevokedCertificateEntries[i]
		if e.SerialNumber.Cmp(serial) == 0 && (latest == nil || e.RevocationTime.After(latest.RevocationTime)) {
			latest = e
		}
	}
	return latest
}
