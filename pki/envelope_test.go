package pki_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/pki"
)

// certSPKI returns the SubjectPublicKeyInfo of a DER certificate, the seventh
// field of TBSCertificate, for the jkurwa certificates crypto/x509 rejects.
func certSPKI(t *testing.T, der []byte) []byte {
	t.Helper()
	var cert struct{ TBS asn1.RawValue }
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		t.Fatal(err)
	}
	var field asn1.RawValue
	rest := cert.TBS.Bytes
	for range 7 { // version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			t.Fatal(err)
		}
	}
	return field.FullBytes
}

// jkurwa-enc-message.p7 is enc_message.p7 of jkurwa's test-box.js: "123"
// from the key of jkurwa-key6929.der to the certificate
// jkurwa-self-signed-enc-40a0.cer, made with a random source that always
// returns "12345678901234567890123456789012". jkurwa's test helper hands
// back all 32 bytes, so the file has a 32-byte UKM and a 32-byte IV whose
// first 8 bytes the cipher used; DecryptEnvelopedData rejects such an IV,
// and crypto/x509 rejects the certificates, so the steps are checked one by
// one with the values of the file.
func TestEnvelopeJkurwaVector(t *testing.T) {
	sender, err := pki.ParsePKCS8PrivateKey(readTestdata(t, "jkurwa-key6929.der"))
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey(Key6929) error = %v", err)
	}
	recipient, err := pki.ParsePKCS8PrivateKey(readTestdata(t, "jkurwa-key40a0.der"))
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey(Key40A0) error = %v", err)
	}
	senderPub, err := pki.ParsePublicKey(certSPKI(t, readTestdata(t, "jkurwa-self-signed-enc-6929.cer")))
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := pki.ParsePublicKey(certSPKI(t, readTestdata(t, "jkurwa-self-signed-enc-40a0.cer")))
	if err != nil {
		t.Fatal(err)
	}

	notRandom := []byte("12345678901234567890123456789012")
	cek, iv := notRandom, notRandom[:gost28147.BlockSize]
	wrapped := mustHex(t, "ff047d15e162cda20abf2fef944b0881cff3c2f463c4e2ebe9ed1b336503b5f4f9066248799067666c5a2403")

	kek, err := pki.EnvelopeKEK(sender, recipientPub.Key, notRandom)
	if err != nil {
		t.Fatalf("EnvelopeKEK(Key6929, 40A0) error = %v", err)
	}
	back, err := pki.EnvelopeKEK(recipient, senderPub.Key, notRandom)
	if err != nil || !bytes.Equal(back, kek) {
		t.Errorf("EnvelopeKEK(Key40A0, 6929) = %x, %v, want the sender's %x", back, err, kek)
	}
	if got, err := pki.GOST28147Wrap(kek, cek, iv, recipientPub.DKE); err != nil || !bytes.Equal(got, wrapped) {
		t.Errorf("GOST28147Wrap(KEK, %q, IV %q) = %x, %v, want encryptedKey %x", cek, iv, got, err, wrapped)
	}
	if got, err := pki.GOST28147Unwrap(kek, wrapped, recipientPub.DKE); err != nil || !bytes.Equal(got, cek) {
		t.Errorf("GOST28147Unwrap(KEK, encryptedKey) = %q, %v, want %q", got, err, cek)
	}

	block, err := gost28147.NewCipher(cek, senderPub.DKE)
	if err != nil {
		t.Fatal(err)
	}
	content := mustHex(t, "3ad940")
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(content, content) //nolint:staticcheck // SA1019: the mode of the envelope
	if string(content) != "123" {
		t.Errorf("GOST 28147 CFB of encryptedContent = %q, want %q", content, "123")
	}
}

func TestGOST28147UnwrapTampered(t *testing.T) {
	kek, cek := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	wrapped, err := pki.GOST28147Wrap(kek, cek, []byte("8 bytes!"), gost28147.DKE1())
	if err != nil {
		t.Fatal(err)
	}
	for i := range wrapped {
		bad := bytes.Clone(wrapped)
		bad[i] ^= 1
		if got, err := pki.GOST28147Unwrap(kek, bad, gost28147.DKE1()); err == nil {
			t.Errorf("GOST28147Unwrap(wrapped key with byte %d flipped) = %x, want error", i, got)
		}
	}
	if _, err := pki.GOST28147Unwrap(kek, wrapped[:43], gost28147.DKE1()); err == nil {
		t.Error("GOST28147Unwrap(43 bytes) error = nil, want error")
	}
}

type envelopeParty struct {
	cert *x509.Certificate
	key  *dstu4145.PrivateKey
}

// newEnvelopeParty issues a self-signed key agreement certificate for a new
// key on named curve curve.
func newEnvelopeParty(t *testing.T, curve int, name string) envelopeParty {
	t.Helper()
	c, err := dstu4145.NamedCurve(curve)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dstu4145.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	der, err := pki.CreateCertificate(rand.Reader, tmpl, tmpl, marshalKey(t, key), key)
	if err != nil {
		t.Fatalf("CreateCertificate(%s) error = %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return envelopeParty{cert, key}
}

func TestEnvelopedData(t *testing.T) {
	sender := newEnvelopeParty(t, 6, "відправник")
	same := newEnvelopeParty(t, 6, "одержувач на тій самій кривій")
	other := newEnvelopeParty(t, 9, "одержувач на іншій кривій")
	stranger := newEnvelopeParty(t, 6, "сторонній")
	content := bytes.Repeat([]byte("Конверт ДСТУ. "), 50)

	der, err := pki.EncryptEnvelopedData(rand.Reader, content, sender.key, sender.cert, []*x509.Certificate{same.cert, other.cert})
	if err != nil {
		t.Fatalf("EncryptEnvelopedData() error = %v", err)
	}

	tests := []struct {
		name    string
		der     []byte
		to      envelopeParty
		key     *dstu4145.PrivateKey
		certs   []*x509.Certificate
		wantErr bool
	}{
		{name: "static key", der: der, to: same, key: same.key, certs: []*x509.Certificate{sender.cert}},
		{name: "static key in BER", der: toBER(t, der), to: same, key: same.key, certs: []*x509.Certificate{sender.cert}},
		{name: "ephemeral key on another curve", der: der, to: other, key: other.key},
		{name: "sender certificate missing", der: der, to: same, key: same.key, wantErr: true},
		{name: "not a recipient", der: der, to: stranger, key: stranger.key, certs: []*x509.Certificate{sender.cert}, wantErr: true},
		{name: "key of another certificate", der: der, to: same, key: stranger.key, certs: []*x509.Certificate{sender.cert}, wantErr: true},
		{name: "SignedData", der: mustSign(t, newTestSigner(t), content), to: same, key: same.key, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pki.DecryptEnvelopedData(tt.der, tt.key, tt.to.cert, tt.certs)
			if tt.wantErr {
				if err == nil {
					t.Errorf("DecryptEnvelopedData(%s) = %q, want error", tt.name, got)
				}
				return
			}
			if err != nil || !bytes.Equal(got, content) {
				t.Errorf("DecryptEnvelopedData(%s) = %q, %v, want %q", tt.name, got, err, content)
			}
		})
	}
}

func TestEncryptEnvelopedDataErrors(t *testing.T) {
	sender := newEnvelopeParty(t, 6, "відправник")
	recipient := newEnvelopeParty(t, 6, "одержувач")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ECDSA"}}
	ecDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecCert, err := x509.ParseCertificate(ecDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		key        *dstu4145.PrivateKey
		recipients []*x509.Certificate
	}{
		{"no recipients", sender.key, nil},
		{"key not of the sender certificate", recipient.key, []*x509.Certificate{recipient.cert}},
		{"recipient with an ECDSA key", sender.key, []*x509.Certificate{ecCert}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pki.EncryptEnvelopedData(rand.Reader, []byte("x"), tt.key, sender.cert, tt.recipients); err == nil {
				t.Errorf("EncryptEnvelopedData(%s) error = nil, want error", tt.name)
			}
		})
	}
}
