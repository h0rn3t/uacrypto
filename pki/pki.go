// Package pki reads DSTU 4145 keys and checks DSTU 4145 signatures in
// Ukrainian X.509 certificates and CMS SignedData.
//
// crypto/x509 parses these certificates but leaves their public keys and
// signatures unknown. ParsePublicKey reads the key from
// Certificate.RawSubjectPublicKeyInfo, and CheckCertificateSignature checks the
// signature of a certificate parsed by crypto/x509, the way Bouncy Castle and
// the IIT library do. VerifySignedData checks CMS SignedData: signed files
// (.p7s) and time-stamp tokens.
//
// Supported keys use the OID dstu4145le (1.2.804.2.1.1.1.1.3.1.1) or
// dstu4145be (1.2.804.2.1.1.1.1.3.1.1.1.1) with one of the ten named curves,
// given by OID or by explicit parameters, and an optional DKE. Supported
// signatures are DSTU 4145 with GOST 34.311-95 (the same two OIDs), with
// Kupyna-256 (1.2.804.2.1.1.1.1.3.6.1.1) and with Kupyna-512
// (1.2.804.2.1.1.1.1.3.6.3.1).
package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kupyna"
)

// ErrInvalidSignature is returned when a well-formed signature does not verify.
var ErrInvalidSignature = errors.New("pki: invalid signature")

var (
	oidDSTU4145LE        = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	oidDSTU4145BE        = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1}
	oidNamedCurves       = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2}
	oidDSTU4145Kupyna256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 1, 1}
	oidDSTU4145Kupyna512 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 3, 1}

	// Digest algorithms, UAObjectIdentifiers in Bouncy Castle.
	oidGOST34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 1}
	oidKupyna256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1}
	oidKupyna384 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 2}
	oidKupyna512 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 3}
)

// A PublicKey is a DSTU 4145 key from a certificate with the S-box that
// GOST 34.311 uses to hash what the key signs.
type PublicKey struct {
	Key *dstu4145.PublicKey
	DKE gost28147.Sbox // from the key parameters, ДКЕ №1 when they omit it
}

// ParsePublicKey parses a DER SubjectPublicKeyInfo with a DSTU 4145 key. A
// key of another algorithm is an error wrapping x509.ErrUnsupportedAlgorithm.
func ParsePublicKey(der []byte) (*PublicKey, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if err := unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("pki: SubjectPublicKeyInfo: %w", err)
	}
	littleEndian := spki.Algorithm.Algorithm.Equal(oidDSTU4145LE)
	if !littleEndian && !spki.Algorithm.Algorithm.Equal(oidDSTU4145BE) {
		return nil, fmt.Errorf("pki: public key algorithm %v: %w", spki.Algorithm.Algorithm, x509.ErrUnsupportedAlgorithm)
	}

	var params struct {
		Curve asn1.RawValue // namedCurve OID or DSTU4145ECBinary
		DKE   []byte        `asn1:"optional"`
	}
	if err := unmarshal(spki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pki: DSTU 4145 parameters: %w", err)
	}
	curve, err := parseCurve(params.Curve.FullBytes, littleEndian)
	if err != nil {
		return nil, err
	}
	dke := gost28147.DKE1()
	if params.DKE != nil {
		if dke, err = gost28147.UnpackDKE(params.DKE); err != nil {
			return nil, fmt.Errorf("pki: %w", err)
		}
	}

	var point []byte
	if err := unmarshal(spki.PublicKey.RightAlign(), &point); err != nil {
		return nil, fmt.Errorf("pki: public key: %w", err)
	}
	if littleEndian {
		slices.Reverse(point)
	}
	key, err := dstu4145.ParsePublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return &PublicKey{Key: key, DKE: dke}, nil
}

// parseCurve reads the curve of DSTU4145Params: a named curve OID or
// DSTU4145ECBinary, whose b and base point are reversed for dstu4145le.
func parseCurve(der []byte, littleEndian bool) (*dstu4145.Curve, error) {
	var oid asn1.ObjectIdentifier
	if unmarshal(der, &oid) == nil {
		if len(oid) != len(oidNamedCurves)+1 || !slices.Equal(oid[:len(oidNamedCurves)], oidNamedCurves) {
			return nil, fmt.Errorf("pki: curve %v: %w", oid, x509.ErrUnsupportedAlgorithm)
		}
		return dstu4145.NamedCurve(oid[len(oid)-1])
	}

	var ec struct {
		Version int `asn1:"optional,explicit,default:0,tag:0"`
		Field   struct {
			M int
			K asn1.RawValue // INTEGER for a trinomial, SEQUENCE of three for a pentanomial
		}
		A int
		B []byte
		N *big.Int
		G []byte
	}
	if err := unmarshal(der, &ec); err != nil {
		return nil, fmt.Errorf("pki: DSTU 4145 curve: %w", err)
	}
	var k []int
	var k1 int
	if unmarshal(ec.Field.K.FullBytes, &k1) == nil {
		k = []int{k1}
	} else {
		var k3 struct{ K1, K2, K3 int }
		if err := unmarshal(ec.Field.K.FullBytes, &k3); err != nil {
			return nil, fmt.Errorf("pki: DSTU 4145 field polynomial: %w", err)
		}
		k = []int{k3.K1, k3.K2, k3.K3}
	}
	if littleEndian {
		slices.Reverse(ec.B)
		slices.Reverse(ec.G)
	}
	curve, err := dstu4145.CurveFromParams(dstu4145.CurveParams{
		M: ec.Field.M, K: k, A: ec.A, B: new(big.Int).SetBytes(ec.B), N: ec.N, G: ec.G,
	})
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return curve, nil
}

// CheckSignature checks that signature is a valid signature of signed by k
// under the signature algorithm alg. The signature is the content of the
// signature BIT STRING: a DER OCTET STRING holding r||s little-endian for
// dstu4145le and Kupyna, s||r big-endian for dstu4145be. A signature that
// does not verify is ErrInvalidSignature; an unknown algorithm wraps
// x509.ErrUnsupportedAlgorithm.
func (k *PublicKey) CheckSignature(alg asn1.ObjectIdentifier, signed, signature []byte) error {
	digestAlg, littleEndian, err := signatureScheme(alg)
	if err != nil {
		return err
	}
	h, err := newHash(digestAlg, k.DKE)
	if err != nil {
		return err
	}
	h.Write(signed)
	var sig []byte
	if err := unmarshal(signature, &sig); err != nil {
		return fmt.Errorf("pki: signature: %w", err)
	}
	return k.verify(h.Sum(nil), sig, littleEndian)
}

// signatureScheme returns the digest algorithm and the byte order of the
// DSTU 4145 signature algorithm alg.
func signatureScheme(alg asn1.ObjectIdentifier) (digestAlg asn1.ObjectIdentifier, littleEndian bool, err error) {
	switch {
	case alg.Equal(oidDSTU4145LE):
		return oidGOST34311, true, nil
	case alg.Equal(oidDSTU4145BE):
		return oidGOST34311, false, nil
	case alg.Equal(oidDSTU4145Kupyna256):
		return oidKupyna256, true, nil
	case alg.Equal(oidDSTU4145Kupyna512):
		return oidKupyna512, true, nil
	}
	return nil, false, fmt.Errorf("pki: signature algorithm %v: %w", alg, x509.ErrUnsupportedAlgorithm)
}

// newHash returns the hash of digest algorithm alg; GOST 34.311 uses dke.
func newHash(alg asn1.ObjectIdentifier, dke gost28147.Sbox) (hash.Hash, error) {
	switch {
	case alg.Equal(oidGOST34311):
		h, err := gost34311.NewWithSbox(dke)
		if err != nil {
			return nil, fmt.Errorf("pki: %w", err)
		}
		return h, nil
	case alg.Equal(oidKupyna256):
		return kupyna.New256(), nil
	case alg.Equal(oidKupyna384):
		return kupyna.New384(), nil
	case alg.Equal(oidKupyna512):
		return kupyna.New512(), nil
	}
	return nil, fmt.Errorf("pki: digest algorithm %v: %w", alg, x509.ErrUnsupportedAlgorithm)
}

// verify checks sig, r||s little-endian or s||r big-endian, over digest.
func (k *PublicKey) verify(digest, sig []byte, littleEndian bool) error {
	if !littleEndian {
		sig = slices.Clone(sig)
		slices.Reverse(sig) // s||r big-endian becomes r||s little-endian
	}
	r, s, err := dstu4145.ParseSignature(sig)
	if err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	if !dstu4145.Verify(k.Key, digest, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// CheckCertificateSignature checks that cert carries a valid DSTU 4145
// signature by the key of parent. It does not check validity periods, key
// usage or names: build and check the chain with crypto/x509 for that.
func CheckCertificateSignature(cert, parent *x509.Certificate) error {
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if err := unmarshal(cert.Raw, &outer); err != nil {
		return fmt.Errorf("pki: certificate: %w", err)
	}
	key, err := ParsePublicKey(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	return key.CheckSignature(outer.Algorithm.Algorithm, cert.RawTBSCertificate, outer.Signature.RightAlign())
}

// unmarshal parses der into v and rejects trailing data.
func unmarshal(der []byte, v any) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data after DER value")
	}
	return nil
}
