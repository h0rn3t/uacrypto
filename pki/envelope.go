package pki

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
)

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	// dhSinglePass-cofactorDH-gost34311kdf, the key agreement of Ukrainian
	// envelopes, with GOST28147Wrap as its parameter.
	oidDHCofactorGOST34311KDF = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 4}
	oidGOST28147Wrap          = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 5}
)

// wrapIV is the IV of the outer encryption of GOST28147Wrap, наказ
// Адміністрації Держспецзв'язку № 108 (22640), VI.1.
var wrapIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// ukmSize is the length of the UKM that cryptonite writes and requires.
const ukmSize = 64

type envelopedData struct {
	Version              int
	OriginatorInfo       asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo struct {
		ContentType      asn1.ObjectIdentifier
		Algorithm        pkix.AlgorithmIdentifier
		EncryptedContent asn1.RawValue `asn1:"optional,tag:0"`
	}
	UnprotectedAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

// keyAgreeRecipientInfo is the [1] kari choice of RecipientInfo.
type keyAgreeRecipientInfo struct {
	Version int
	// Originator keeps the [0] EXPLICIT wrapper: Bytes is the
	// OriginatorIdentifierOrKey.
	Originator             asn1.RawValue `asn1:"explicit,tag:0"`
	UKM                    []byte        `asn1:"optional,explicit,tag:1"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	RecipientEncryptedKeys []struct {
		RID          asn1.RawValue // IssuerAndSerialNumber or [0] RecipientKeyIdentifier
		EncryptedKey []byte
	}
}

// originatorPublicKey is the [1] originatorKey choice of
// OriginatorIdentifierOrKey: the ephemeral key of the sender.
type originatorPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type issuerAndSerialNumber struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// EncryptEnvelopedData encrypts content for each certificate of recipients and
// returns a DER ContentInfo with a CMS EnvelopedData, as cryptonite, IIT and
// jkurwa write it: the content type data, encrypted with GOST 28147-89 in CFB
// under a new key with the DKE of cert, and for every recipient a
// KeyAgreeRecipientInfo of dhSinglePass-cofactorDH-gost34311kdf that wraps
// that key with GOST28147Wrap and the DKE of the recipient.
//
// key is the sender's DSTU 4145 key agreement key and cert its certificate.
// A recipient whose key is on the curve of key agrees with key itself, and
// names cert by issuer and serial number, so it needs cert to decrypt; for a
// recipient on another curve the sender agrees with a new ephemeral key and
// stores its public key in the envelope, as cryptonite does. random, normally
// crypto/rand.Reader, provides the content key, the IVs, the UKMs and the
// ephemeral keys.
//
// EncryptEnvelopedData fails if key does not belong to cert or a recipient
// has no DSTU 4145 key.
func EncryptEnvelopedData(random io.Reader, content []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, recipients []*x509.Certificate) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("pki: EnvelopedData without recipients")
	}
	sender, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	if !sender.belongsTo(key) {
		return nil, errors.New("pki: the key does not belong to the sender certificate")
	}
	cek := make([]byte, gost28147.KeySize)
	params := gost28147Params{IV: make([]byte, gost28147.BlockSize), DKE: gost28147.PackDKE(sender.DKE)}
	if _, err := io.ReadFull(random, cek); err != nil {
		return nil, fmt.Errorf("pki: content key: %w", err)
	}
	if _, err := io.ReadFull(random, params.IV); err != nil {
		return nil, fmt.Errorf("pki: IV: %w", err)
	}

	var ed envelopedData
	ed.Version = 2
	for _, r := range recipients {
		ri, err := keyAgreeRecipient(random, key, cert, r, cek)
		if err != nil {
			return nil, fmt.Errorf("pki: recipient %s: %w", r.Subject, err)
		}
		ed.RecipientInfos = append(ed.RecipientInfos, ri)
	}

	block, err := gost28147.NewCipher(cek, sender.DKE)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	encrypted := make([]byte, len(content))
	cipher.NewCFBEncrypter(block, params.IV).XORKeyStream(encrypted, content) //nolint:staticcheck // SA1019: the mode of Ukrainian envelopes
	der, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("pki: GOST 28147-89 parameters: %w", err)
	}
	eci := &ed.EncryptedContentInfo
	eci.ContentType = oidData
	eci.Algorithm = pkix.AlgorithmIdentifier{Algorithm: oidGOST28147CFB, Parameters: asn1.RawValue{FullBytes: der}}
	eci.EncryptedContent = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: encrypted}

	inner, err := asn1.Marshal(ed)
	if err != nil {
		return nil, fmt.Errorf("pki: EnvelopedData: %w", err)
	}
	return asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidEnvelopedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}

// keyAgreeRecipient returns the KeyAgreeRecipientInfo that wraps cek for
// recipient, agreed with key of cert or, on another curve, an ephemeral key.
func keyAgreeRecipient(random io.Reader, key *dstu4145.PrivateKey, cert, recipient *x509.Certificate, cek []byte) (asn1.RawValue, error) {
	pub, err := ParsePublicKey(recipient.RawSubjectPublicKeyInfo)
	if err != nil {
		return asn1.RawValue{}, err
	}
	var originator []byte
	if pub.Key.Curve() == key.Public().Curve() {
		originator, err = asn1.Marshal(issuerAndSerialNumber{asn1.RawValue{FullBytes: cert.RawIssuer}, cert.SerialNumber})
	} else {
		if key, err = dstu4145.GenerateKey(pub.Key.Curve(), random); err != nil {
			return asn1.RawValue{}, fmt.Errorf("ephemeral key: %w", err)
		}
		point := key.Public().Bytes()
		slices.Reverse(point)
		var octets []byte
		if octets, err = asn1.Marshal(point); err != nil {
			return asn1.RawValue{}, err
		}
		// cryptonite names the key by the signature algorithm of the
		// recipient certificate, dstu4145le with NULL parameters.
		originator, err = asn1.MarshalWithParams(originatorPublicKey{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE, Parameters: asn1.NullRawValue},
			PublicKey: asn1.BitString{Bytes: octets, BitLength: 8 * len(octets)},
		}, "tag:1")
	}
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("originator: %w", err)
	}

	ukm, wrapIVRandom := make([]byte, ukmSize), make([]byte, gost28147.BlockSize)
	if _, err := io.ReadFull(random, ukm); err != nil {
		return asn1.RawValue{}, fmt.Errorf("UKM: %w", err)
	}
	if _, err := io.ReadFull(random, wrapIVRandom); err != nil {
		return asn1.RawValue{}, fmt.Errorf("IV: %w", err)
	}
	kek, err := envelopeKEK(key, pub.Key, ukm)
	if err != nil {
		return asn1.RawValue{}, err
	}
	wrapped, err := gost28147Wrap(kek, cek, wrapIVRandom, pub.DKE)
	if err != nil {
		return asn1.RawValue{}, err
	}
	rid, err := asn1.Marshal(issuerAndSerialNumber{asn1.RawValue{FullBytes: recipient.RawIssuer}, recipient.SerialNumber})
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("recipient identifier: %w", err)
	}
	wrapAlg, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidGOST28147Wrap, Parameters: asn1.NullRawValue})
	if err != nil {
		return asn1.RawValue{}, err
	}

	kari := keyAgreeRecipientInfo{
		Version:                3,
		Originator:             asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: originator},
		UKM:                    ukm,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidDHCofactorGOST34311KDF, Parameters: asn1.RawValue{FullBytes: wrapAlg}},
	}
	kari.RecipientEncryptedKeys = append(kari.RecipientEncryptedKeys, struct {
		RID          asn1.RawValue
		EncryptedKey []byte
	}{asn1.RawValue{FullBytes: rid}, wrapped})
	der, err := asn1.MarshalWithParams(kari, "tag:1")
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("KeyAgreeRecipientInfo: %w", err)
	}
	return asn1.RawValue{FullBytes: der}, nil
}

// DecryptEnvelopedData decrypts a CMS EnvelopedData in a ContentInfo, in DER
// or BER, that EncryptEnvelopedData, cryptonite, IIT or jkurwa wrote for cert,
// with key, the DSTU 4145 key agreement key of cert: for IIT keys that is
// ParsePKCS8KeyAgreementKey of the key file, or ParsePKCS8PrivateKey when the
// file has no second key. It finds the KeyAgreeRecipientInfo of cert by issuer
// and serial number or by subject key identifier, agrees on the key with the
// ephemeral key in the envelope or with the sender certificate it names, which
// is looked up in the OriginatorInfo and then in certs, unwraps the content
// key with the DKE of cert and decrypts the content, GOST 28147-89 in CFB or
// in gamma mode.
//
// The envelope authenticates nobody: a sender certificate only says whose key
// was used, and is not checked against any trust anchor. A wrapped key that
// does not match its MAC, because key is not the key of cert or the envelope
// was damaged, is an error; the content itself carries no MAC.
func DecryptEnvelopedData(der []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, certs []*x509.Certificate) ([]byte, error) {
	der, err := toDER(der)
	if err != nil {
		return nil, err
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if err := unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("pki: ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf("pki: content type %v is not EnvelopedData", ci.ContentType)
	}
	var ed envelopedData
	if err := unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("pki: EnvelopedData: %w", err)
	}
	recipient, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	kari, wrapped, err := findKeyAgreeRecipient(ed.RecipientInfos, cert)
	if err != nil {
		return nil, err
	}
	if !kari.KeyEncryptionAlgorithm.Algorithm.Equal(oidDHCofactorGOST34311KDF) {
		return nil, fmt.Errorf("pki: key agreement %v: %w", kari.KeyEncryptionAlgorithm.Algorithm, x509.ErrUnsupportedAlgorithm)
	}
	var wrapAlg pkix.AlgorithmIdentifier
	if err := unmarshal(kari.KeyEncryptionAlgorithm.Parameters.FullBytes, &wrapAlg); err != nil || !wrapAlg.Algorithm.Equal(oidGOST28147Wrap) {
		return nil, fmt.Errorf("pki: key wrap %v: %w", wrapAlg.Algorithm, x509.ErrUnsupportedAlgorithm)
	}
	var originatorInfo struct {
		Certs asn1.RawValue `asn1:"optional,tag:0"`
		CRLs  asn1.RawValue `asn1:"optional,tag:1"`
	}
	if ed.OriginatorInfo.FullBytes != nil {
		if _, err := asn1.UnmarshalWithParams(ed.OriginatorInfo.FullBytes, &originatorInfo, "tag:0"); err != nil {
			return nil, fmt.Errorf("pki: OriginatorInfo: %w", err)
		}
	}
	pool, err := certificateSet(originatorInfo.Certs.Bytes)
	if err != nil {
		return nil, err
	}
	sender, err := originatorKey(kari.Originator, key.Public().Curve(), append(pool, certs...))
	if err != nil {
		return nil, fmt.Errorf("pki: originator: %w", err)
	}
	kek, err := envelopeKEK(key, sender, kari.UKM)
	if err != nil {
		return nil, err
	}
	cek, err := gost28147Unwrap(kek, wrapped, recipient.DKE)
	if err != nil {
		return nil, err
	}

	eci := ed.EncryptedContentInfo
	if eci.EncryptedContent.FullBytes == nil {
		return nil, errors.New("pki: EnvelopedData carries no encrypted content")
	}
	encrypted := eci.EncryptedContent.Bytes
	if eci.EncryptedContent.IsCompound { // the chunks of a streamed envelope, each already DER
		encrypted = nil
		for rest := eci.EncryptedContent.Bytes; len(rest) > 0; {
			var chunk []byte
			if rest, err = asn1.Unmarshal(rest, &chunk); err != nil {
				return nil, fmt.Errorf("pki: encryptedContent: %w", err)
			}
			encrypted = append(encrypted, chunk...)
		}
	}
	var params gost28147Params
	if err := unmarshal(eci.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pki: GOST 28147-89 parameters: %w", err)
	}
	stream, err := gost28147Decrypter(eci.Algorithm.Algorithm, params, cek)
	if err != nil {
		return nil, err
	}
	content := make([]byte, len(encrypted))
	stream.XORKeyStream(content, encrypted)
	return content, nil
}

// findKeyAgreeRecipient returns the KeyAgreeRecipientInfo of infos with a
// RecipientEncryptedKey for cert, and that key.
func findKeyAgreeRecipient(infos []asn1.RawValue, cert *x509.Certificate) (*keyAgreeRecipientInfo, []byte, error) {
	for _, ri := range infos {
		if ri.Class != asn1.ClassContextSpecific || ri.Tag != 1 {
			continue // key transport, KEK, password and other recipients
		}
		kari := new(keyAgreeRecipientInfo)
		// ri.FullBytes is one value: nothing can trail it
		if _, err := asn1.UnmarshalWithParams(ri.FullBytes, kari, "tag:1"); err != nil {
			return nil, nil, fmt.Errorf("pki: KeyAgreeRecipientInfo: %w", err)
		}
		for _, rek := range kari.RecipientEncryptedKeys {
			id := rek.RID
			if id.Class == asn1.ClassContextSpecific && id.Tag == 0 {
				// RecipientKeyIdentifier: the subject key identifier, then optional fields
				var ski []byte
				if _, err := asn1.Unmarshal(id.Bytes, &ski); err != nil {
					return nil, nil, fmt.Errorf("pki: RecipientKeyIdentifier: %w", err)
				}
				id = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ski}
			}
			if _, err := findCertificate(id, []*x509.Certificate{cert}); err == nil {
				return kari, rek.EncryptedKey, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("pki: %s is not a recipient of the EnvelopedData", cert.Subject)
}

// originatorKey returns the sender's public key of the [0] EXPLICIT
// OriginatorIdentifierOrKey wrapper: an ephemeral key on curve, or the key
// of the certificate of pool that it names.
func originatorKey(wrapper asn1.RawValue, curve *dstu4145.Curve, pool []*x509.Certificate) (*dstu4145.PublicKey, error) {
	var id asn1.RawValue
	if err := unmarshal(wrapper.Bytes, &id); err != nil {
		return nil, err
	}
	if id.Class != asn1.ClassContextSpecific || id.Tag != 1 {
		cert, err := findCertificate(id, pool)
		if err != nil {
			return nil, err
		}
		pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			return nil, err
		}
		return pub.Key, nil
	}

	var opk originatorPublicKey
	if _, err := asn1.UnmarshalWithParams(id.FullBytes, &opk, "tag:1"); err != nil {
		return nil, err
	}
	littleEndian := opk.Algorithm.Algorithm.Equal(oidDSTU4145LE)
	if !littleEndian && !opk.Algorithm.Algorithm.Equal(oidDSTU4145BE) {
		return nil, fmt.Errorf("key algorithm %v: %w", opk.Algorithm.Algorithm, x509.ErrUnsupportedAlgorithm)
	}
	var point []byte
	if err := unmarshal(opk.PublicKey.RightAlign(), &point); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if littleEndian {
		slices.Reverse(point)
	}
	return dstu4145.ParsePublicKey(curve, point)
}

// envelopeKEK returns the key encryption key that key and remote agree on
// with ukm: GOST 34.311 with ДКЕ №1 over the x coordinate of the cofactor
// Diffie–Hellman point, big-endian without leading zero bytes, the counter
// 00000001 and the DER SharedInfo of GOST28147Wrap, ukm and the key length
// of 256 bits (iso15946_generate_secretc of cryptonite).
func envelopeKEK(key *dstu4145.PrivateKey, remote *dstu4145.PublicKey, ukm []byte) ([]byte, error) {
	zx, err := key.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	sharedInfo, err := asn1.Marshal(struct {
		KeyInfo     pkix.AlgorithmIdentifier
		EntityInfo  []byte `asn1:"optional,explicit,tag:0"`
		SuppPubInfo []byte `asn1:"explicit,tag:2"`
	}{pkix.AlgorithmIdentifier{Algorithm: oidGOST28147Wrap, Parameters: asn1.NullRawValue}, ukm, []byte{0, 0, 1, 0}})
	if err != nil {
		return nil, fmt.Errorf("pki: SharedInfo: %w", err)
	}
	h := gost34311.New()
	// cryptonite drops every leading zero byte; jkurwa drops one, which
	// differs only when the two top bytes of x are zero.
	h.Write(bytes.TrimLeft(zx, "\x00"))
	h.Write([]byte{0, 0, 0, 1})
	h.Write(sharedInfo)
	clear(zx)
	return h.Sum(nil), nil
}

// gost28147Wrap wraps the 32-byte cek under kek with GOST28147Wrap and the
// 8-byte iv: the 4-byte GOST 28147-89 MAC of cek, cek||MAC encrypted in CFB
// with iv, iv and that reversed, and the 44 bytes encrypted in CFB with wrapIV.
func gost28147Wrap(kek, cek, iv []byte, sbox gost28147.Sbox) ([]byte, error) {
	if len(cek) != gost28147.KeySize || len(iv) != gost28147.BlockSize {
		return nil, errors.New("pki: GOST28147Wrap of a key or IV of the wrong size")
	}
	block, err := gost28147.NewCipher(kek, sbox)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	mac, err := gost28147.NewMAC(kek, sbox, 4)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	mac.Write(cek)
	w := slices.Concat(iv, cek, mac.Sum(nil))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(w[len(iv):], w[len(iv):]) //nolint:staticcheck // SA1019: GOST28147Wrap is built on CFB
	slices.Reverse(w)
	cipher.NewCFBEncrypter(block, wrapIV).XORKeyStream(w, w) //nolint:staticcheck,gosec // SA1019, G407: GOST28147Wrap is CFB with this fixed IV by the standard
	return w, nil
}

// gost28147Unwrap reverses gost28147Wrap and checks the MAC of the key.
func gost28147Unwrap(kek, wrapped []byte, sbox gost28147.Sbox) ([]byte, error) {
	if len(wrapped) != gost28147.BlockSize+gost28147.KeySize+4 {
		return nil, fmt.Errorf("pki: wrapped key of %d bytes", len(wrapped))
	}
	block, err := gost28147.NewCipher(kek, sbox)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	w := make([]byte, len(wrapped))
	cipher.NewCFBDecrypter(block, wrapIV).XORKeyStream(w, wrapped) //nolint:staticcheck // SA1019: GOST28147Wrap is built on CFB
	slices.Reverse(w)
	iv, rest := w[:gost28147.BlockSize], w[gost28147.BlockSize:]
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(rest, rest) //nolint:staticcheck // SA1019: GOST28147Wrap is built on CFB
	cek, sum := rest[:gost28147.KeySize], rest[gost28147.KeySize:]
	mac, err := gost28147.NewMAC(kek, sbox, 4)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	mac.Write(cek)
	if subtle.ConstantTimeCompare(mac.Sum(nil), sum) != 1 {
		return nil, errors.New("pki: the wrapped key does not match its MAC")
	}
	return cek, nil
}
