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
	"io"
	"math/big"
	"slices"
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

// newECDSACert returns a self-signed CA certificate of a P-256 key, a key the
// package does not take.
func newECDSACert(t *testing.T) *x509.Certificate {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ECDSA"},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestEncryptEnvelopedDataErrors(t *testing.T) {
	sender := newEnvelopeParty(t, 6, "відправник")
	recipient := newEnvelopeParty(t, 6, "одержувач")
	ecCert := newECDSACert(t)

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
	if _, err := pki.EncryptEnvelopedData(rand.Reader, []byte("x"), sender.key, ecCert, []*x509.Certificate{recipient.cert}); err == nil {
		t.Error("EncryptEnvelopedData(sender with an ECDSA certificate) error = nil, want error")
	}

	// A source that runs dry before the content key, the IV, the UKM, the
	// wrap IV or the ephemeral key of a recipient on another curve.
	other := newEnvelopeParty(t, 9, "на іншій кривій")
	for _, n := range []int{10, 35, 100, 104} {
		random := io.LimitReader(rand.Reader, int64(n))
		if _, err := pki.EncryptEnvelopedData(random, []byte("x"), sender.key, sender.cert, []*x509.Certificate{recipient.cert}); err == nil {
			t.Errorf("EncryptEnvelopedData(%d random bytes) error = nil, want error", n)
		}
	}
	if _, err := pki.EncryptEnvelopedData(io.LimitReader(rand.Reader, 40), []byte("x"), sender.key, sender.cert, []*x509.Certificate{other.cert}); err == nil {
		t.Error("EncryptEnvelopedData(40 random bytes, recipient on another curve) error = nil, want error")
	}
}

// testEnvelope mirrors EnvelopedData and its first KeyAgreeRecipientInfo, so
// that a test can change one field of a valid envelope.
type testEnvelope struct {
	Version              int
	OriginatorInfo       asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo struct {
		ContentType      asn1.ObjectIdentifier
		Algorithm        pkix.AlgorithmIdentifier
		EncryptedContent asn1.RawValue `asn1:"optional,tag:0"`
	}
}

type testKARI struct {
	Version                int
	Originator             asn1.RawValue `asn1:"explicit,tag:0"` // the whole [0] element
	UKM                    []byte        `asn1:"optional,explicit,tag:1"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	RecipientEncryptedKeys []struct {
		RID          asn1.RawValue
		EncryptedKey []byte
	}
}

// editEnvelope returns der, a ContentInfo with EnvelopedData, after edit
// has changed the envelope and its first KeyAgreeRecipientInfo.
func editEnvelope(t *testing.T, der []byte, edit func(ed *testEnvelope, kari *testKARI)) []byte {
	t.Helper()
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"` // the whole [0] element
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var ed testEnvelope
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	var kari testKARI
	if _, err := asn1.UnmarshalWithParams(ed.RecipientInfos[0].FullBytes, &kari, "tag:1"); err != nil {
		t.Fatal(err)
	}
	edit(&ed, &kari)
	kariDER, err := asn1.MarshalWithParams(kari, "tag:1")
	if err != nil {
		t.Fatal(err)
	}
	ed.RecipientInfos[0] = asn1.RawValue{FullBytes: kariDER}
	return mustMarshal(t, struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{ci.Type, contextTag(0, mustMarshal(t, ed))})
}

// contextTag returns the constructed [tag] element with contents.
func contextTag(tag int, contents []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: contents}
}

// issuerAndSerial returns the DER IssuerAndSerialNumber of cert.
func issuerAndSerial(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return mustMarshal(t, struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: cert.RawIssuer}, cert.SerialNumber})
}

func TestDecryptEnvelopedDataForms(t *testing.T) {
	sender := newEnvelopeParty(t, 6, "відправник")
	same := newEnvelopeParty(t, 6, "одержувач на тій самій кривій")
	other := newEnvelopeParty(t, 9, "одержувач на іншій кривій")
	content := []byte("Конверт, записаний інакше.")
	toSame, err := pki.EncryptEnvelopedData(rand.Reader, content, sender.key, sender.cert, []*x509.Certificate{same.cert})
	if err != nil {
		t.Fatal(err)
	}
	toOther, err := pki.EncryptEnvelopedData(rand.Reader, content, sender.key, sender.cert, []*x509.Certificate{other.cert})
	if err != nil {
		t.Fatal(err)
	}
	senderPub, err := pki.ParsePublicKey(sender.cert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	samePub, err := pki.ParsePublicKey(same.cert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	if same.cert.SubjectKeyId == nil {
		t.Fatal("the recipient certificate has no subject key identifier")
	}

	tests := []struct {
		name  string
		der   []byte
		to    envelopeParty
		certs []*x509.Certificate
	}{
		{"sender certificate in OriginatorInfo", editEnvelope(t, toSame, func(ed *testEnvelope, _ *testKARI) {
			ed.OriginatorInfo = contextTag(0, mustMarshal(t, contextTag(0, sender.cert.Raw)))
		}), same, nil},
		{"recipient by subject key identifier", editEnvelope(t, toSame, func(_ *testEnvelope, kari *testKARI) {
			kari.RecipientEncryptedKeys[0].RID = contextTag(0, mustMarshal(t, same.cert.SubjectKeyId))
		}), same, []*x509.Certificate{sender.cert}},
		{"other kinds of recipients first", editEnvelope(t, toSame, func(ed *testEnvelope, _ *testKARI) {
			// a SEQUENCE, as KeyTransRecipientInfo is, sorts first in the SET
			ed.RecipientInfos = append(ed.RecipientInfos, asn1.RawValue{FullBytes: mustMarshal(t, struct{ V int }{0})})
		}), same, []*x509.Certificate{sender.cert}},
		{"content in chunks", editEnvelope(t, toSame, func(ed *testEnvelope, _ *testKARI) {
			enc := ed.EncryptedContentInfo.EncryptedContent.Bytes
			ed.EncryptedContentInfo.EncryptedContent = contextTag(0, append(mustMarshal(t, enc[:5]), mustMarshal(t, enc[5:])...))
		}), same, []*x509.Certificate{sender.cert}},
		{"content in gamma mode", editEnvelope(t, toSame, func(ed *testEnvelope, kari *testKARI) {
			// The content key, unwrapped as the recipient does.
			kek, err := pki.EnvelopeKEK(same.key, senderPub.Key, kari.UKM)
			if err != nil {
				t.Fatal(err)
			}
			cek, err := pki.GOST28147Unwrap(kek, kari.RecipientEncryptedKeys[0].EncryptedKey, samePub.DKE)
			if err != nil {
				t.Fatal(err)
			}
			var params struct{ IV, DKE []byte }
			if _, err := asn1.Unmarshal(ed.EncryptedContentInfo.Algorithm.Parameters.FullBytes, &params); err != nil {
				t.Fatal(err)
			}
			block, err := gost28147.NewCipher(cek, senderPub.DKE)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := gost28147.NewCTR(block, params.IV)
			if err != nil {
				t.Fatal(err)
			}
			enc := make([]byte, len(content))
			stream.XORKeyStream(enc, content)
			ed.EncryptedContentInfo.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 2}
			ed.EncryptedContentInfo.EncryptedContent = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: enc}
		}), same, []*x509.Certificate{sender.cert}},
		{"ephemeral key big-endian", editEnvelope(t, toOther, func(_ *testEnvelope, kari *testKARI) {
			var opk struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, err := asn1.UnmarshalWithParams(kari.Originator.Bytes, &opk, "tag:1"); err != nil {
				t.Fatal(err)
			}
			var point []byte
			if _, err := asn1.Unmarshal(opk.PublicKey.Bytes, &point); err != nil {
				t.Fatal(err)
			}
			slices.Reverse(point)
			octets := mustMarshal(t, point)
			opk.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1}
			opk.PublicKey = asn1.BitString{Bytes: octets, BitLength: 8 * len(octets)}
			der, err := asn1.MarshalWithParams(opk, "tag:1")
			if err != nil {
				t.Fatal(err)
			}
			kari.Originator = contextTag(0, der)
		}), other, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pki.DecryptEnvelopedData(tt.der, tt.to.key, tt.to.cert, tt.certs)
			if err != nil || !bytes.Equal(got, content) {
				t.Errorf("DecryptEnvelopedData(%s) = %q, %v, want %q", tt.name, got, err, content)
			}
		})
	}
}

func TestDecryptEnvelopedDataMalformed(t *testing.T) {
	sender := newEnvelopeParty(t, 6, "відправник")
	same := newEnvelopeParty(t, 6, "одержувач")
	other := newEnvelopeParty(t, 9, "на іншій кривій")
	ecCert := newECDSACert(t)
	der, err := pki.EncryptEnvelopedData(rand.Reader, []byte("x"), sender.key, sender.cert, []*x509.Certificate{same.cert})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := pki.EncryptEnvelopedData(rand.Reader, []byte("x"), sender.key, sender.cert, []*x509.Certificate{other.cert})
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(ed *testEnvelope, kari *testKARI)) []byte { return editEnvelope(t, der, f) }
	originator := func(opk any) func(*testEnvelope, *testKARI) {
		return func(_ *testEnvelope, kari *testKARI) {
			kari.Originator = contextTag(0, mustMarshal(t, opk))
		}
	}
	ephemeralKey := func(alg asn1.ObjectIdentifier, key []byte) []byte {
		return editEnvelope(t, ephemeral, func(_ *testEnvelope, kari *testKARI) {
			opk, err := asn1.MarshalWithParams(struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}{pkix.AlgorithmIdentifier{Algorithm: alg}, asn1.BitString{Bytes: key, BitLength: 8 * len(key)}}, "tag:1")
			if err != nil {
				t.Fatal(err)
			}
			kari.Originator = contextTag(0, opk)
		})
	}
	dstu4145le := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	contentAlgorithm := func(alg pkix.AlgorithmIdentifier) []byte {
		return edit(func(ed *testEnvelope, _ *testKARI) { ed.EncryptedContentInfo.Algorithm = alg })
	}
	cfb := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}

	tests := []struct {
		name  string
		der   []byte
		to    envelopeParty
		cert  *x509.Certificate // the recipient certificate when not to.cert
		certs []*x509.Certificate
	}{
		{name: "truncated", der: der[:len(der)-1], to: same},
		{name: "not a ContentInfo", der: mustMarshal(t, 5), to: same},
		{name: "malformed EnvelopedData", der: mustMarshal(t, struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue
		}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}, contextTag(0, mustMarshal(t, 5))}), to: same},
		{name: "recipient certificate with an ECDSA key", der: der, to: same, cert: ecCert},
		{name: "malformed KeyAgreeRecipientInfo", der: edit(func(ed *testEnvelope, _ *testKARI) {
			ed.RecipientInfos = append(ed.RecipientInfos, contextTag(1, mustMarshal(t, 5)))
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "malformed RecipientKeyIdentifier", der: edit(func(_ *testEnvelope, kari *testKARI) {
			kari.RecipientEncryptedKeys[0].RID = contextTag(0, mustMarshal(t, 5))
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "another key agreement", der: edit(func(_ *testEnvelope, kari *testKARI) {
			kari.KeyEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "another key wrap", der: edit(func(_ *testEnvelope, kari *testKARI) {
			kari.KeyEncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: mustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}})}
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "primitive OriginatorInfo", der: edit(func(ed *testEnvelope, _ *testKARI) {
			ed.OriginatorInfo = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: []byte{1}}
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "malformed certificate in OriginatorInfo", der: edit(func(ed *testEnvelope, _ *testKARI) {
			ed.OriginatorInfo = contextTag(0, mustMarshal(t, contextTag(0, mustMarshal(t, struct{ A int }{5}))))
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "truncated originator", der: edit(func(_ *testEnvelope, kari *testKARI) {
			kari.Originator = contextTag(0, []byte{0x30})
		}), to: same},
		{name: "originator named by an INTEGER", der: edit(originator(5)), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "truncated certificate in OriginatorInfo", der: edit(func(ed *testEnvelope, _ *testKARI) {
			ed.OriginatorInfo = contextTag(0, mustMarshal(t, contextTag(0, []byte{0x30})))
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "originator with an ECDSA key", der: edit(func(_ *testEnvelope, kari *testKARI) {
			kari.Originator = contextTag(0, issuerAndSerial(t, ecCert))
		}), to: same, certs: []*x509.Certificate{ecCert}},
		{name: "originator on another curve", der: edit(func(_ *testEnvelope, kari *testKARI) {
			kari.Originator = contextTag(0, issuerAndSerial(t, other.cert))
		}), to: same, certs: []*x509.Certificate{other.cert}},
		{name: "malformed ephemeral key", der: edit(originator(contextTag(1, mustMarshal(t, 5)))), to: same},
		{name: "ephemeral key of another algorithm", der: ephemeralKey(asn1.ObjectIdentifier{1, 2, 3}, mustMarshal(t, []byte{1})), to: other},
		{name: "ephemeral key not an OCTET STRING", der: ephemeralKey(dstu4145le, mustMarshal(t, 5)), to: other},
		{name: "no encrypted content", der: edit(func(ed *testEnvelope, _ *testKARI) {
			ed.EncryptedContentInfo.EncryptedContent = asn1.RawValue{}
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "malformed content chunk", der: edit(func(ed *testEnvelope, _ *testKARI) {
			ed.EncryptedContentInfo.EncryptedContent = contextTag(0, mustMarshal(t, 5))
		}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "malformed content parameters", der: contentAlgorithm(pkix.AlgorithmIdentifier{Algorithm: cfb, Parameters: asn1.NullRawValue}),
			to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "another content cipher", der: contentAlgorithm(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3},
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, struct{ IV []byte }{make([]byte, 8)})}}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "content IV of 7 bytes", der: contentAlgorithm(pkix.AlgorithmIdentifier{Algorithm: cfb,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, struct{ IV []byte }{make([]byte, 7)})}}), to: same, certs: []*x509.Certificate{sender.cert}},
		{name: "malformed content DKE", der: contentAlgorithm(pkix.AlgorithmIdentifier{Algorithm: cfb,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, struct{ IV, DKE []byte }{make([]byte, 8), []byte{1}})}}), to: same, certs: []*x509.Certificate{sender.cert}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.to.cert
			if tt.cert != nil {
				cert = tt.cert
			}
			if got, err := pki.DecryptEnvelopedData(tt.der, tt.to.key, cert, tt.certs); err == nil {
				t.Errorf("DecryptEnvelopedData(%s) = %q, want error", tt.name, got)
			}
		})
	}
}
