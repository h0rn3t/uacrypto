package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/pki"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// jkurwa-store-a040.dat is jkurwa's STORE_A040.dat: jkurwa-key40a0.der
// (Key40A0.pem) under the password "password", with the salt and IV of its
// test "should encrypt raw key and serialize into PBES2".
func TestDecryptPKCS8PrivateKey(t *testing.T) {
	store := readTestdata(t, "jkurwa-store-a040.dat")
	want := readTestdata(t, "jkurwa-key40a0.der")

	got, err := pki.DecryptPKCS8PrivateKey(store, "password")
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("DecryptPKCS8PrivateKey(STORE_A040, password) = %x, %v, want %x", got, err, want)
	}
	if _, err := pki.DecryptPKCS8PrivateKey(store, "passworD"); !errors.Is(err, pki.ErrIncorrectPassword) {
		t.Errorf("DecryptPKCS8PrivateKey(STORE_A040, wrong password) error = %v, want %v", err, pki.ErrIncorrectPassword)
	}
	if _, err := pki.DecryptPKCS8PrivateKey(want, "password"); err == nil {
		t.Error("DecryptPKCS8PrivateKey(an unencrypted key) error = nil, want error")
	}
}

func TestEncryptPKCS8PrivateKey(t *testing.T) {
	key := readTestdata(t, "jkurwa-key40a0.der")
	salt := mustHex(t, "31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876")
	iv := mustHex(t, "4bb10f5c2945d49e")
	random := bytes.NewReader(slices.Concat(salt, iv))

	got, err := pki.EncryptPKCS8PrivateKey(random, key, "password", 10000)
	if want := readTestdata(t, "jkurwa-store-a040.dat"); err != nil || !bytes.Equal(got, want) {
		t.Errorf("EncryptPKCS8PrivateKey(Key40A0, salt %x, IV %x) = %x, %v, want STORE_A040 %x", salt, iv, got, err, want)
	}
	if _, err := pki.EncryptPKCS8PrivateKey(rand.Reader, key, "password", 0); err == nil {
		t.Error("EncryptPKCS8PrivateKey(0 iterations) error = nil, want error")
	}
}

// Key40A0.pem keeps d little-endian in a bare OCTET STRING, as IIT and
// cryptonite do; SELF_SIGNED_ENC_40A0.cer is its certificate in jkurwa's
// test-box.js. Its authority key identifier is one crypto/x509 rejects, so
// the test takes the SubjectPublicKeyInfo by hand.
func TestParsePKCS8PrivateKeyIIT(t *testing.T) {
	pub, err := pki.ParsePublicKey(certSPKI(t, readTestdata(t, "jkurwa-self-signed-enc-40a0.cer")))
	if err != nil {
		t.Fatal(err)
	}

	key, err := pki.ParsePKCS8PrivateKey(readTestdata(t, "jkurwa-key40a0.der"))
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey(Key40A0) error = %v", err)
	}
	if !bytes.Equal(key.Public().Bytes(), pub.Key.Bytes()) {
		t.Errorf("ParsePKCS8PrivateKey(Key40A0) public key = %x, want the certificate's %x", key.Public().Bytes(), pub.Key.Bytes())
	}
}

func TestParsePKCS8KeyAgreementKey(t *testing.T) {
	curveOID := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}
	params := mustMarshal(t, struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte
	}{curveOID, gost28147.PackDKE(gost28147.DKE1())})
	// d = 0x0102: little-endian 02 01 00…00, every bit of it reversed
	bits := make([]byte, 32)
	bits[30], bits[31] = 0x80, 0x40
	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	attrs := []attribute{
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3},
			[]asn1.RawValue{{FullBytes: mustMarshal(t, asn1.BitString{Bytes: bits, BitLength: 256})}}},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2},
			[]asn1.RawValue{{FullBytes: params}}},
	}
	withAttrs := func(attrs []attribute) []byte {
		return mustMarshal(t, struct {
			Version   int
			Algorithm struct {
				Algorithm asn1.ObjectIdentifier
				Params    asn1.RawValue
			}
			PrivateKey []byte
			Attributes []attribute `asn1:"optional,tag:0,set"`
		}{
			Algorithm: struct {
				Algorithm asn1.ObjectIdentifier
				Params    asn1.RawValue
			}{asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}, asn1.RawValue{FullBytes: params}},
			PrivateKey: []byte{7},
			Attributes: attrs,
		})
	}

	got, err := pki.ParsePKCS8KeyAgreementKey(withAttrs(attrs))
	if want := mustHex(t, "0102"); err != nil || !bytes.Equal(bytes.TrimLeft(got.Bytes(), "\x00"), want) {
		t.Errorf("ParsePKCS8KeyAgreementKey(bits %x) = %v, %v, want d = %x", bits, got, err, want)
	}
	if curve, _ := dstu4145.NamedCurve(6); err == nil && got.Public().Curve() != curve {
		t.Errorf("ParsePKCS8KeyAgreementKey() curve = %v, want named curve 6", got.Public().Curve())
	}
	if _, err := pki.ParsePKCS8KeyAgreementKey(withAttrs(nil)); !errors.Is(err, pki.ErrNoKeyAgreementKey) {
		t.Errorf("ParsePKCS8KeyAgreementKey(no attributes) error = %v, want %v", err, pki.ErrNoKeyAgreementKey)
	}
	if _, err := pki.ParsePKCS8KeyAgreementKey(withAttrs(attrs[:1])); err == nil {
		t.Error("ParsePKCS8KeyAgreementKey(key bits without curve) error = nil, want error")
	}
}

// iit-123456.pfx is cryptonite's storageUtest/resources/pkcs12_by_iit(123456).pfx:
// two keys IIT stored under the password 123456, one on a 257-bit curve and
// one on a 431-bit curve, both with explicit parameters.
func TestDecodePFXIIT(t *testing.T) {
	data := readTestdata(t, "iit-123456.pfx")

	pfx, err := pki.DecodePFX(data, "123456")
	if err != nil {
		t.Fatalf("DecodePFX(iit-123456.pfx) error = %v", err)
	}
	var bits []int
	for _, k := range pfx.Keys {
		bits = append(bits, k.Public().Curve().Order().BitLen())
	}
	if want := []int{256, 430}; !slices.Equal(bits, want) || len(pfx.Certificates) != 0 {
		t.Errorf("DecodePFX(iit-123456.pfx) = keys of orders %v bits and %d certificates, want %v and none", bits, len(pfx.Certificates), want)
	}

	if _, err := pki.DecodePFX(data, "654321"); !errors.Is(err, pki.ErrIncorrectPassword) {
		t.Errorf("DecodePFX(iit-123456.pfx, wrong password) error = %v, want %v", err, pki.ErrIncorrectPassword)
	}
	tampered := bytes.Clone(data)
	tampered[100] ^= 1
	if _, err := pki.DecodePFX(tampered, "123456"); err == nil {
		t.Error("DecodePFX(tampered content) error = nil, want error")
	}
}

func TestEncodePFX(t *testing.T) {
	key, other := newKey(t), newKey(t)
	template := rootTemplate()
	der, err := pki.CreateCertificate(rand.Reader, template, template, marshalKey(t, key), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	in := &pki.PFX{Keys: []*dstu4145.PrivateKey{other, key}, Certificates: []*x509.Certificate{cert}}

	data, err := pki.EncodePFX(rand.Reader, in, "пароль", 1024)
	if err != nil {
		t.Fatalf("EncodePFX() error = %v", err)
	}
	out, err := pki.DecodePFX(data, "пароль")
	if err != nil {
		t.Fatalf("DecodePFX(EncodePFX()) error = %v", err)
	}
	if len(out.Keys) != 2 || !bytes.Equal(out.Keys[0].Bytes(), other.Bytes()) || !bytes.Equal(out.Keys[1].Bytes(), key.Bytes()) {
		t.Errorf("DecodePFX(EncodePFX()) keys = %v, want the keys in order", out.Keys)
	}
	if len(out.Certificates) != 1 || !out.Certificates[0].Equal(cert) {
		t.Errorf("DecodePFX(EncodePFX()) certificates = %v, want the certificate", out.Certificates)
	}
	if _, err := pki.DecodePFX(data, "парол"); !errors.Is(err, pki.ErrIncorrectPassword) {
		t.Errorf("DecodePFX(EncodePFX(), wrong password) error = %v, want %v", err, pki.ErrIncorrectPassword)
	}

	got, err := out.KeyFor(cert)
	if err != nil || !bytes.Equal(got.Bytes(), key.Bytes()) {
		t.Errorf("KeyFor(certificate of the second key) = %v, %v, want the second key", got, err)
	}
	stranger := &pki.PFX{Keys: []*dstu4145.PrivateKey{other}}
	if _, err := stranger.KeyFor(cert); err == nil {
		t.Error("KeyFor(certificate of no key) error = nil, want error")
	}
}
