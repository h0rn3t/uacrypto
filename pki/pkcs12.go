package pki

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"slices"
	"unicode/utf16"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
)

// ErrIncorrectPassword is returned when a key or a PFX does not open with the
// password: its MAC does not match, or what it decrypts to is not DER.
var ErrIncorrectPassword = errors.New("pki: incorrect password")

// ErrNoKeyAgreementKey is returned by ParsePKCS8KeyAgreementKey for a key
// without the key agreement key of IIT.
var ErrNoKeyAgreementKey = errors.New("pki: no key agreement key in the PKCS#8 key")

// maxIterations bounds the iteration counts read from a file, so that a
// crafted one cannot keep the CPU busy for hours; IIT writes 10000.
const maxIterations = 1 << 24

var (
	oidPBES2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACGOST34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 2}
	oidGOST28147OFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 2}
	oidGOST28147CFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}

	// The second key IIT stores in the attributes of a PKCS#8 key, and its curve.
	oidIITKeyAgreementKey   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3}
	oidIITKeyAgreementCurve = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2}

	oidEncryptedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidShroudedKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509CertificateBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidLocalKeyID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

type pbes2Params struct {
	KDF struct {
		Algorithm asn1.ObjectIdentifier
		Params    struct {
			Salt       []byte
			Iterations int
			KeyLength  int `asn1:"optional"`
			PRF        pkix.AlgorithmIdentifier
		}
	}
	Scheme struct {
		Algorithm asn1.ObjectIdentifier
		Params    gost28147Params
	}
}

// gost28147Params are the parameters of GOST 28147-89 in CFB and in gamma
// mode, in PBES2 and in the content of EnvelopedData.
type gost28147Params struct {
	IV  []byte
	DKE []byte `asn1:"optional"`
}

// gost28147Decrypt decrypts data with key in mode, CFB or
// gamma, with params: the DKE of params, ДКЕ №1 when they omit it.
func gost28147Decrypt(mode asn1.ObjectIdentifier, params gost28147Params, key, data []byte) ([]byte, error) {
	sbox := gost28147.DKE1()
	if params.DKE != nil {
		var err error
		if sbox, err = gost28147.UnpackDKE(params.DKE); err != nil {
			return nil, fmt.Errorf("pki: %w", err)
		}
	}
	if len(params.IV) != gost28147.BlockSize {
		return nil, fmt.Errorf("pki: GOST 28147-89 IV of %d bytes", len(params.IV))
	}
	block, err := gost28147.NewCipher(key, sbox)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	defer gost28147.Destroy(block)
	var stream cipher.Stream
	switch {
	case mode.Equal(oidGOST28147CFB):
		stream = cipher.NewCFBDecrypter(block, params.IV) //nolint:staticcheck // SA1019: the mode Ukrainian key files and envelopes use
	case mode.Equal(oidGOST28147OFB):
		if stream, err = gost28147.NewCTR(block, params.IV); err != nil {
			return nil, fmt.Errorf("pki: %w", err)
		}
	default:
		return nil, fmt.Errorf("pki: encryption scheme %v: %w", mode, x509.ErrUnsupportedAlgorithm)
	}
	plain := make([]byte, len(data))
	stream.XORKeyStream(plain, data)
	return plain, nil
}

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// DecryptPKCS8PrivateKey decrypts an EncryptedPrivateKeyInfo in DER as IIT,
// cryptonite and jkurwa write it, and returns the PKCS#8 key inside for
// ParsePKCS8PrivateKey: PBES2 with PBKDF2 on HMAC GOST 34.311 over the
// password in UTF-8, and GOST 28147-89 in CFB or in gamma mode with the DKE
// of its parameters, ДКЕ №1 when they omit it. A password that decrypts the
// key to something other than DER is an error wrapping ErrIncorrectPassword.
func DecryptPKCS8PrivateKey(der []byte, password string) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if err := unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("pki: EncryptedPrivateKeyInfo: %w", err)
	}
	return decryptPBES2(info.Algorithm, info.Data, password)
}

func decryptPBES2(alg pkix.AlgorithmIdentifier, data []byte, password string) ([]byte, error) {
	if !alg.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("pki: encryption %v: %w", alg.Algorithm, x509.ErrUnsupportedAlgorithm)
	}
	var params pbes2Params
	if err := unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pki: PBES2 parameters: %w", err)
	}
	kdf := params.KDF
	if !kdf.Algorithm.Equal(oidPBKDF2) || !kdf.Params.PRF.Algorithm.Equal(oidHMACGOST34311) {
		return nil, fmt.Errorf("pki: key derivation %v with %v: %w", kdf.Algorithm, kdf.Params.PRF.Algorithm, x509.ErrUnsupportedAlgorithm)
	}
	if kdf.Params.Iterations < 1 || kdf.Params.Iterations > maxIterations {
		return nil, fmt.Errorf("pki: PBKDF2 with %d iterations", kdf.Params.Iterations)
	}
	key, err := pbkdf2.Key(gost34311.New, password, kdf.Params.Salt, kdf.Params.Iterations, gost28147.KeySize)
	if err != nil {
		return nil, fmt.Errorf("pki: PBKDF2: %w", err)
	}
	plain, err := gost28147Decrypt(params.Scheme.Algorithm, params.Scheme.Params, key, data)
	clear(key)
	if err != nil {
		return nil, err
	}
	var v asn1.RawValue
	if unmarshal(plain, &v) != nil || v.Tag != asn1.TagSequence {
		clear(plain)
		return nil, ErrIncorrectPassword
	}
	return plain, nil
}

// EncryptPKCS8PrivateKey encrypts a PKCS#8 key in DER as IIT and cryptonite
// do and DecryptPKCS8PrivateKey reads: PBES2 with PBKDF2 on HMAC GOST 34.311
// in iterations rounds over a 32-byte salt, and GOST 28147-89 in CFB with
// ДКЕ №1 and an 8-byte IV. It reads the salt and then the IV from random.
// IIT uses 10000 iterations.
func EncryptPKCS8PrivateKey(random io.Reader, pkcs8 []byte, password string, iterations int) ([]byte, error) {
	if iterations < 1 || iterations > maxIterations {
		return nil, fmt.Errorf("pki: PBKDF2 with %d iterations", iterations)
	}
	var params pbes2Params
	params.KDF.Algorithm = oidPBKDF2
	params.KDF.Params.Salt = make([]byte, 32)
	params.KDF.Params.Iterations = iterations
	params.KDF.Params.PRF = pkix.AlgorithmIdentifier{Algorithm: oidHMACGOST34311, Parameters: asn1.NullRawValue}
	params.Scheme.Algorithm = oidGOST28147CFB
	params.Scheme.Params.IV = make([]byte, gost28147.BlockSize)
	params.Scheme.Params.DKE = gost28147.PackDKE(gost28147.DKE1())
	if _, err := io.ReadFull(random, params.KDF.Params.Salt); err != nil {
		return nil, fmt.Errorf("pki: salt: %w", err)
	}
	if _, err := io.ReadFull(random, params.Scheme.Params.IV); err != nil {
		return nil, fmt.Errorf("pki: IV: %w", err)
	}

	key, err := pbkdf2.Key(gost34311.New, password, params.KDF.Params.Salt, iterations, gost28147.KeySize)
	if err != nil {
		return nil, fmt.Errorf("pki: PBKDF2: %w", err)
	}
	block, err := gost28147.NewCipher(key, gost28147.DKE1())
	clear(key)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	data := make([]byte, len(pkcs8))
	cipher.NewCFBEncrypter(block, params.Scheme.Params.IV).XORKeyStream(data, pkcs8) //nolint:staticcheck // SA1019: the mode the key files use
	gost28147.Destroy(block)

	der, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("pki: PBES2 parameters: %w", err)
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: der}},
		Data:      data,
	})
}

// ParsePKCS8KeyAgreementKey returns the second key that IIT keeps in the
// attributes of a PKCS#8 key for key agreement, the key that opens
// envelopes: its d with every bit reversed in the BIT STRING of attribute
// 1.3.6.1.4.1.19398.1.1.2.3, and its curve in the DSTU4145Params of
// attribute 1.3.6.1.4.1.19398.1.1.2.2. A key without it is an error
// wrapping ErrNoKeyAgreementKey.
func ParsePKCS8KeyAgreementKey(der []byte) (*dstu4145.PrivateKey, error) {
	var pkcs8 struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		Attributes []struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		} `asn1:"optional,tag:0,set"`
	}
	if err := unmarshal(der, &pkcs8); err != nil {
		return nil, fmt.Errorf("pki: PKCS#8: %w", err)
	}
	var keyBits, curveParams []byte
	for _, a := range pkcs8.Attributes {
		if len(a.Values) != 1 {
			continue
		}
		switch {
		case a.Type.Equal(oidIITKeyAgreementKey):
			var bs asn1.BitString
			if err := unmarshal(a.Values[0].FullBytes, &bs); err != nil {
				return nil, fmt.Errorf("pki: key agreement key: %w", err)
			}
			keyBits = bs.Bytes
		case a.Type.Equal(oidIITKeyAgreementCurve):
			curveParams = a.Values[0].FullBytes
		}
	}
	if keyBits == nil {
		return nil, ErrNoKeyAgreementKey
	}
	if curveParams == nil {
		return nil, errors.New("pki: the key agreement key has no curve")
	}
	var params struct {
		Curve asn1.RawValue
		DKE   []byte `asn1:"optional"`
	}
	if err := unmarshal(curveParams, &params); err != nil {
		return nil, fmt.Errorf("pki: key agreement key parameters: %w", err)
	}
	curve, err := parseCurve(params.Curve.FullBytes, true)
	if err != nil {
		return nil, err
	}
	// Reversing every bit of little-endian d leaves it big-endian with the
	// bits of each byte reversed.
	d := make([]byte, len(keyBits))
	for i, b := range keyBits {
		d[i] = bits.Reverse8(b)
	}
	key, err := dstu4145.NewPrivateKey(curve, d)
	clear(d)
	if err != nil {
		return nil, fmt.Errorf("pki: key agreement key: %w", err)
	}
	return key, nil
}

// A PFX is what a PKCS#12 file (.pfx, .p12) holds: the private keys and
// certificates of its owner. DecodeIITKey6 and DecodeJKS return what the key
// files of IIT and of Java hold in a PFX too.
type PFX struct {
	Keys         []*dstu4145.PrivateKey
	Certificates []*x509.Certificate
}

type pfxContainer struct {
	Version  int
	AuthSafe struct {
		ContentType asn1.ObjectIdentifier
		Content     []byte `asn1:"explicit,tag:0"`
	}
	MacData struct {
		Mac struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		Salt       []byte
		Iterations int `asn1:"optional,default:1"`
	} `asn1:"optional"`
}

// DecodePFX opens a PKCS#12 file in DER or BER as IIT and cryptonite write
// it: a MAC on HMAC GOST 34.311, keys in PKCS#8 encrypted as
// DecryptPKCS8PrivateKey reads, and X.509 certificates, in the clear or
// encrypted the same way. Keys come in the order of the file, the key
// agreement key of a PKCS#8 key right after it; other bags are skipped. A
// MAC that does not match is an error wrapping ErrIncorrectPassword.
func DecodePFX(data []byte, password string) (*PFX, error) {
	der, err := toDER(data)
	if err != nil {
		return nil, err
	}
	var pfx pfxContainer
	if err := unmarshal(der, &pfx); err != nil {
		return nil, fmt.Errorf("pki: PFX: %w", err)
	}
	if !pfx.AuthSafe.ContentType.Equal(oidData) {
		return nil, fmt.Errorf("pki: PFX content %v, want data", pfx.AuthSafe.ContentType)
	}
	authSafe := pfx.AuthSafe.Content
	if mac := pfx.MacData; mac.Mac.Algorithm.Algorithm != nil {
		if !mac.Mac.Algorithm.Algorithm.Equal(oidGOST34311) {
			return nil, fmt.Errorf("pki: PFX MAC on %v: %w", mac.Mac.Algorithm.Algorithm, x509.ErrUnsupportedAlgorithm)
		}
		if mac.Iterations < 1 || mac.Iterations > maxIterations {
			return nil, fmt.Errorf("pki: PFX MAC with %d iterations", mac.Iterations)
		}
		h := hmac.New(gost34311.New, pfxMACKey(password, mac.Salt, mac.Iterations))
		h.Write(authSafe)
		if !hmac.Equal(h.Sum(nil), mac.Mac.Digest) {
			return nil, ErrIncorrectPassword
		}
	}

	var contents []struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if err := unmarshal(authSafe, &contents); err != nil {
		return nil, fmt.Errorf("pki: AuthenticatedSafe: %w", err)
	}
	out := new(PFX)
	for _, c := range contents {
		var bags []byte
		switch {
		case c.ContentType.Equal(oidData):
			if err := unmarshal(c.Content.Bytes, &bags); err != nil {
				return nil, fmt.Errorf("pki: SafeContents: %w", err)
			}
		case c.ContentType.Equal(oidEncryptedData):
			var ed struct {
				Version int
				Info    struct {
					ContentType asn1.ObjectIdentifier
					Algorithm   pkix.AlgorithmIdentifier
					Content     []byte `asn1:"optional,tag:0"`
				}
			}
			if err := unmarshal(c.Content.Bytes, &ed); err != nil {
				return nil, fmt.Errorf("pki: EncryptedData: %w", err)
			}
			if bags, err = decryptPBES2(ed.Info.Algorithm, ed.Info.Content, password); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("pki: PFX content %v: %w", c.ContentType, x509.ErrUnsupportedAlgorithm)
		}
		if err := out.addBags(bags, password); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// addBags adds the keys and certificates of SafeContents in DER to p.
func (p *PFX) addBags(der []byte, password string) error {
	var bags []struct {
		ID         asn1.ObjectIdentifier
		Value      asn1.RawValue `asn1:"explicit,tag:0"`
		Attributes asn1.RawValue `asn1:"optional,set"`
	}
	if err := unmarshal(der, &bags); err != nil {
		return fmt.Errorf("pki: SafeContents: %w", err)
	}
	for _, bag := range bags {
		switch {
		case bag.ID.Equal(oidShroudedKeyBag):
			pkcs8, err := DecryptPKCS8PrivateKey(bag.Value.Bytes, password)
			if err != nil {
				return err
			}
			if p.Keys, err = appendPKCS8Keys(p.Keys, pkcs8); err != nil {
				return err
			}
		case bag.ID.Equal(oidCertBag):
			var cb struct {
				ID    asn1.ObjectIdentifier
				Value []byte `asn1:"explicit,tag:0"`
			}
			if err := unmarshal(bag.Value.Bytes, &cb); err != nil {
				return fmt.Errorf("pki: CertBag: %w", err)
			}
			if !cb.ID.Equal(oidX509CertificateBag) {
				continue
			}
			cert, err := x509.ParseCertificate(cb.Value)
			if err != nil {
				return fmt.Errorf("pki: PFX certificate: %w", err)
			}
			p.Certificates = append(p.Certificates, cert)
		}
	}
	return nil
}

// pfxMACKey derives the HMAC key of a PFX MAC on GOST 34.311 (RFC 7292,
// appendix B, with ID 3) from the password in UTF-16 big-endian with two
// zero bytes at the end.
func pfxMACKey(password string, salt []byte, iterations int) []byte {
	var pass []byte
	for _, c := range utf16.Encode([]rune(password)) {
		pass = binary.BigEndian.AppendUint16(pass, c)
	}
	pass = append(pass, 0, 0)
	// fill repeats b up to a whole number of blocks
	fill := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		out := make([]byte, (len(b)+gost34311.BlockSize-1)/gost34311.BlockSize*gost34311.BlockSize)
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	h := gost34311.New()
	h.Write(bytes.Repeat([]byte{3}, gost34311.BlockSize))
	h.Write(fill(salt))
	h.Write(fill(pass))
	a := h.Sum(nil)
	for range iterations - 1 {
		sum := gost34311.Sum(a)
		a = sum[:]
	}
	return a
}

// EncodePFX writes p as a PKCS#12 file that DecodePFX and cryptonite read:
// each key in PKCS#8 as IIT writes it (dstu4145le with the explicit
// parameters of the curve and ДКЕ №1, d little-endian), encrypted by
// EncryptPKCS8PrivateKey, the certificates in the clear, and a MAC on HMAC
// GOST 34.311 over a 32-byte salt. Like IIT, it marks each key and the
// certificate of a key with localKeyID, the SKI of the key; friendlyName is
// not written. Key derivation and the MAC take iterations rounds; IIT uses
// 10000. To change the password of a PFX, decode it with the old password
// and encode it with the new one.
func EncodePFX(random io.Reader, p *PFX, password string, iterations int) ([]byte, error) {
	if iterations < 1 || iterations > maxIterations {
		return nil, fmt.Errorf("pki: PFX with %d iterations", iterations)
	}
	type attribute struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	type safeBag struct {
		ID         asn1.ObjectIdentifier
		Value      asn1.RawValue
		Attributes []attribute `asn1:"optional,set"`
	}
	explicit0 := func(der []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
	}
	// IIT marks each key with localKeyID, the GOST 34.311 hash of the key's
	// BIT STRING, which is also the SKI of its certificate.
	localKeyID := func(pub *dstu4145.PublicKey) ([]attribute, error) {
		le := pub.Bytes()
		slices.Reverse(le)
		point, err := asn1.Marshal(le)
		if err != nil {
			return nil, fmt.Errorf("pki: public key: %w", err)
		}
		sum := gost34311.Sum(point)
		id := asn1.RawValue{Tag: asn1.TagOctetString, Bytes: sum[:]}
		return []attribute{{oidLocalKeyID, []asn1.RawValue{id}}}, nil
	}
	var bags []safeBag
	for _, key := range p.Keys {
		pkcs8, err := marshalIITPrivateKey(key)
		if err != nil {
			return nil, err
		}
		encrypted, err := EncryptPKCS8PrivateKey(random, pkcs8, password, iterations)
		clear(pkcs8)
		if err != nil {
			return nil, err
		}
		attrs, err := localKeyID(key.Public())
		if err != nil {
			return nil, err
		}
		bags = append(bags, safeBag{oidShroudedKeyBag, explicit0(encrypted), attrs})
	}
	for _, cert := range p.Certificates {
		cb, err := asn1.Marshal(struct {
			ID    asn1.ObjectIdentifier
			Value []byte `asn1:"explicit,tag:0"`
		}{oidX509CertificateBag, cert.Raw})
		if err != nil {
			return nil, fmt.Errorf("pki: CertBag: %w", err)
		}
		var attrs []attribute
		if key, err := p.KeyFor(cert); err == nil {
			if attrs, err = localKeyID(key.Public()); err != nil {
				return nil, err
			}
		}
		bags = append(bags, safeBag{oidCertBag, explicit0(cb), attrs})
	}
	safeContents, err := asn1.Marshal(bags)
	if err != nil {
		return nil, fmt.Errorf("pki: SafeContents: %w", err)
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     []byte `asn1:"explicit,tag:0"`
	}
	authSafe, err := asn1.Marshal([]contentInfo{{oidData, safeContents}})
	if err != nil {
		return nil, fmt.Errorf("pki: AuthenticatedSafe: %w", err)
	}

	var pfx pfxContainer
	pfx.Version = 3
	pfx.AuthSafe.ContentType = oidData
	pfx.AuthSafe.Content = authSafe
	pfx.MacData.Salt = make([]byte, 32)
	if _, err := io.ReadFull(random, pfx.MacData.Salt); err != nil {
		return nil, fmt.Errorf("pki: MAC salt: %w", err)
	}
	pfx.MacData.Iterations = iterations
	pfx.MacData.Mac.Algorithm = pkix.AlgorithmIdentifier{Algorithm: oidGOST34311, Parameters: asn1.NullRawValue}
	h := hmac.New(gost34311.New, pfxMACKey(password, pfx.MacData.Salt, iterations))
	h.Write(authSafe)
	pfx.MacData.Mac.Digest = h.Sum(nil)
	return asn1.Marshal(pfx)
}

// marshalIITPrivateKey returns key in PKCS#8 as IIT writes it: dstu4145le
// with DSTU4145Params of the explicit curve parameters and ДКЕ №1, and d
// itself little-endian.
func marshalIITPrivateKey(key *dstu4145.PrivateKey) ([]byte, error) {
	curve, err := marshalCurve(key.Public().Curve())
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(struct {
		Curve asn1.RawValue
		DKE   []byte
	}{asn1.RawValue{FullBytes: curve}, gost28147.PackDKE(gost28147.DKE1())})
	if err != nil {
		return nil, fmt.Errorf("pki: DSTU 4145 parameters: %w", err)
	}
	d := key.Bytes()
	defer clear(d)
	slices.Reverse(d)
	return asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidDSTU4145LE, Parameters: asn1.RawValue{FullBytes: params}}, d})
}

// KeyFor returns the key of p whose public key cert certifies.
func (p *PFX) KeyFor(cert *x509.Certificate) (*dstu4145.PrivateKey, error) {
	pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	for _, key := range p.Keys {
		if bytes.Equal(key.Public().Bytes(), pub.Key.Bytes()) {
			return key, nil
		}
	}
	return nil, errors.New("pki: no key in the PFX for the certificate")
}
