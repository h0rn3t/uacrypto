package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/pki"
)

func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	der, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(%s) error = %v", name, err)
	}
	return c
}

func TestCheckCertificateSignature(t *testing.T) {
	tests := []struct {
		cert, parent string
	}{
		{"nbu-root-gost.der", "nbu-root-gost.der"},
		{"nbu-root-kupyna.der", "nbu-root-kupyna.der"},
		{"vchasno-gost.der", "czo-2020.der"},
		{"vchasno-kupyna.der", "czo-2601.der"},
		{"dksu-ocsp-be.der", "dksu-ca.der"},
		{"monobank-cmp-kupyna512.der", "monobank-ca.der"},
	}
	for _, tt := range tests {
		t.Run(tt.cert, func(t *testing.T) {
			t.Parallel()
			cert, parent := readCert(t, tt.cert), readCert(t, tt.parent)
			if err := pki.CheckCertificateSignature(cert, parent); err != nil {
				t.Errorf("CheckCertificateSignature(%s, %s) = %v, want nil", tt.cert, tt.parent, err)
			}

			tampered := *cert
			tampered.RawTBSCertificate = bytes.Clone(cert.RawTBSCertificate)
			tampered.RawTBSCertificate[len(tampered.RawTBSCertificate)-1] ^= 1
			if err := pki.CheckCertificateSignature(&tampered, parent); !errors.Is(err, pki.ErrInvalidSignature) {
				t.Errorf("CheckCertificateSignature(tampered %s, %s) = %v, want ErrInvalidSignature", tt.cert, tt.parent, err)
			}
		})
	}
}

func TestCheckCertificateSignatureWrongParent(t *testing.T) {
	cert, other := readCert(t, "vchasno-gost.der"), readCert(t, "czo-2601.der")
	if err := pki.CheckCertificateSignature(cert, other); !errors.Is(err, pki.ErrInvalidSignature) {
		t.Errorf("CheckCertificateSignature(vchasno-gost, czo-2601) = %v, want ErrInvalidSignature", err)
	}
}

func TestCheckCertificateSignatureNotDSTU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ecdsa"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ecCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dstu := readCert(t, "nbu-root-gost.der")
	for name, pair := range map[string][2]*x509.Certificate{
		"ECDSA parent":    {dstu, ecCert},
		"ECDSA signature": {ecCert, dstu},
	} {
		if err := pki.CheckCertificateSignature(pair[0], pair[1]); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			t.Errorf("%s: CheckCertificateSignature = %v, want x509.ErrUnsupportedAlgorithm", name, err)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		cert      string
		curveBits int // bit length of the order n
	}{
		{"nbu-root-gost.der", 430},  // m = 431, explicit parameters, little-endian
		{"dksu-ocsp-be.der", 256},   // dstu4145be, M257
		{"vchasno-kupyna.der", 256}, // M257
	}
	for _, tt := range tests {
		t.Run(tt.cert, func(t *testing.T) {
			cert := readCert(t, tt.cert)
			k, err := pki.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
			if err != nil {
				t.Fatalf("ParsePublicKey(%s) error = %v", tt.cert, err)
			}
			if got := k.Key.Curve().Order().BitLen(); got != tt.curveBits {
				t.Errorf("ParsePublicKey(%s): order has %d bits, want %d", tt.cert, got, tt.curveBits)
			}
		})
	}
}

// namedCurveSPKI is a SubjectPublicKeyInfo with the curve as an OID, the form
// Bouncy Castle writes.
func namedCurveSPKI(t *testing.T, alg asn1.ObjectIdentifier, curve int, dke []byte, point []byte) []byte {
	t.Helper()
	params := struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte `asn1:"optional"`
	}{asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, curve}, dke}
	rawParams, err := asn1.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	key, err := asn1.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: alg, Parameters: asn1.RawValue{FullBytes: rawParams}}, asn1.BitString{Bytes: key, BitLength: 8 * len(key)}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

var (
	oidLE = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	oidBE = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1}
)

func TestParsePublicKeyNamedCurve(t *testing.T) {
	c, err := dstu4145.NamedCurve(6)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dstu4145.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := key.Public().Bytes()
	reversed := slices.Clone(want)
	slices.Reverse(reversed)

	for name, der := range map[string][]byte{
		"big-endian":    namedCurveSPKI(t, oidBE, 6, nil, want),
		"little-endian": namedCurveSPKI(t, oidLE, 6, nil, reversed),
	} {
		k, err := pki.ParsePublicKey(der)
		if err != nil {
			t.Fatalf("%s: ParsePublicKey error = %v", name, err)
		}
		if got := k.Key.Bytes(); !bytes.Equal(got, want) {
			t.Errorf("%s: ParsePublicKey key = %x, want %x", name, got, want)
		}
		if k.DKE != gost28147.DKE1() {
			t.Errorf("%s: ParsePublicKey DKE = %v, want DKE1 when the parameters omit it", name, k.DKE)
		}
	}

	for name, der := range map[string][]byte{
		"unknown curve":    namedCurveSPKI(t, oidBE, 10, nil, want),
		"short DKE":        namedCurveSPKI(t, oidBE, 6, make([]byte, 63), want),
		"wrong byte order": namedCurveSPKI(t, oidLE, 6, nil, want),
	} {
		if k, err := pki.ParsePublicKey(der); err == nil {
			t.Errorf("%s: ParsePublicKey = %v, want error", name, k)
		}
	}
}

func TestParsePublicKeyRejects(t *testing.T) {
	good := readCert(t, "nbu-root-gost.der").RawSubjectPublicKeyInfo
	ec := func() []byte {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		return der
	}()
	tests := map[string][]byte{
		"nil":           nil,
		"trailing data": append(bytes.Clone(good), 0),
		"truncated":     good[:len(good)-1],
		"ECDSA key":     ec,
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if k, err := pki.ParsePublicKey(der); err == nil {
				t.Errorf("ParsePublicKey(%s) = %v, want error", name, k)
			}
		})
	}
}
