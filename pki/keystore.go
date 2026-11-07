package pki

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: the JKS key protector and store digest are SHA-1
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
)

var (
	// The key store of IIT before PBES2, in Key-6.dat.
	oidIITStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 1, 2}
	// The key protector of Sun JKS.
	oidJKSKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}
)

var errJKSShort = errors.New("pki: JKS key store cut short")

// DecodeIITKey6 opens Key-6.dat, the key file of IIT «Користувач ЦСК», and
// returns its key, followed by the key agreement key IIT may add to it, as
// DecodePFX returns them. The file holds one PKCS#8 key in one of two forms,
// as jkurwa reads it:
//
//   - EncryptedPrivateKeyInfo, as DecryptPKCS8PrivateKey reads it;
//   - the older store of IIT (1.3.6.1.4.1.19398.1.1.1.2): the key in
//     GOST 28147-89 ECB with ДКЕ №1 under GOST 34.311 applied 10000 times to
//     the password in UTF-8, the tail of its last block kept apart.
//
// The 4-byte check value of the older store is not verified, as jkurwa does
// not verify it. A password that decrypts the key to something other than
// DER is an error wrapping ErrIncorrectPassword.
func DecodeIITKey6(data []byte, password string) (*PFX, error) {
	der, err := toDER(data)
	if err != nil {
		return nil, err
	}
	var store struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		Data []byte
	}
	if err := unmarshal(der, &store); err != nil {
		return nil, fmt.Errorf("pki: Key-6: %w", err)
	}
	var pkcs8 []byte
	if store.Algorithm.Algorithm.Equal(oidIITStore) {
		pkcs8, err = decryptIITStore(store.Algorithm.Parameters.FullBytes, store.Data, password)
	} else {
		pkcs8, err = DecryptPKCS8PrivateKey(der, password)
	}
	if err != nil {
		return nil, err
	}
	keys, err := appendPKCS8Keys(nil, pkcs8)
	if err != nil {
		return nil, err
	}
	return &PFX{Keys: keys}, nil
}

// decryptIITStore decrypts body, the key in the older IIT store, with
// params, the SEQUENCE of its check value and of the tail of its ciphertext.
func decryptIITStore(params, body []byte, password string) ([]byte, error) {
	var p struct {
		MAC []byte
		Pad []byte `asn1:"optional"`
	}
	if err := unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("pki: Key-6 store parameters: %w", err)
	}
	ciphertext := append(bytes.Clone(body), p.Pad...)
	if len(p.MAC) != 4 || len(p.Pad) >= gost28147.BlockSize || len(body) == 0 || len(ciphertext)%gost28147.BlockSize != 0 {
		return nil, fmt.Errorf("pki: Key-6 store of %d bytes with a tail of %d and a check value of %d", len(body), len(p.Pad), len(p.MAC))
	}
	// GOST 34.311 of the password, then of the hash: 10000 hashes in all.
	key := gost34311.Sum([]byte(password))
	for range 10000 - 1 {
		key = gost34311.Sum(key[:])
	}
	block, err := gost28147.NewCipher(key[:], gost28147.DKE1())
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	for i := 0; i < len(ciphertext); i += gost28147.BlockSize {
		block.Decrypt(ciphertext[i:], ciphertext[i:])
	}
	pkcs8 := ciphertext[:len(body)]
	if unmarshal(pkcs8, new(asn1.RawValue)) != nil {
		return nil, ErrIncorrectPassword
	}
	return pkcs8, nil
}

// DecodeJKS opens a Sun JKS key store (.jks), in which PrivatBank issues
// DSTU 4145 keys: the keys of its private key entries, each followed by the
// key agreement key IIT may add to it, and its X.509 certificates in the
// order of the store, the chains of key entries and trusted certificate
// entries alike. A key is PKCS#8 under the JKS key protector
// (1.3.6.1.4.1.42.2.17.1.1), as ParsePKCS8PrivateKey parses it. The password
// opens the store and every key in it, hashed in UTF-16 big-endian as Java
// does. Six bytes before the store that start with 0x51, which jkurwa skips
// in the files of PrivatBank, are skipped too. A store digest or a key check
// value that does not match is an error wrapping ErrIncorrectPassword.
func DecodeJKS(data []byte, password string) (*PFX, error) {
	if len(data) >= 6 && data[0] == 0x51 {
		data = data[6:]
	}
	if len(data) < 12+sha1.Size || binary.BigEndian.Uint32(data) != 0xFEEDFEED {
		return nil, errors.New("pki: not a JKS key store")
	}
	pw := jksPassword(password)
	body, digest := data[:len(data)-sha1.Size], data[len(data)-sha1.Size:]
	h := sha1.New() //nolint:gosec // G401: the JKS store digest is SHA-1
	h.Write(pw)
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(body)
	if subtle.ConstantTimeCompare(h.Sum(nil), digest) != 1 {
		return nil, ErrIncorrectPassword
	}

	r := bytes.NewReader(body[4:])
	version, _ := jksUint32(r) // the length check above leaves both in body
	count, _ := jksUint32(r)
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("pki: JKS version %d", version)
	}
	out := new(PFX)
	readCertificate := func() error {
		certType := []byte("X.509") // version 1 has X.509 only and does not name it
		if version == 2 {
			var err error
			if certType, err = jksBytes(r, 2); err != nil {
				return err
			}
		}
		der, err := jksBytes(r, 4)
		if err != nil || string(certType) != "X.509" {
			return err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("pki: JKS certificate: %w", err)
		}
		out.Certificates = append(out.Certificates, cert)
		return nil
	}
	for range count {
		tag, err := jksUint32(r)
		if err != nil {
			return nil, err
		}
		if _, err := jksBytes(r, 2); err != nil { // alias
			return nil, err
		}
		if r.Len() < 8 {
			return nil, errJKSShort
		}
		_, _ = r.Seek(8, io.SeekCurrent) // creation time; r holds 8 bytes more
		switch tag {
		case 1: // PrivateKeyEntry
			protected, err := jksBytes(r, 4)
			if err != nil {
				return nil, err
			}
			pkcs8, err := jksUnprotect(protected, pw)
			if err != nil {
				return nil, err
			}
			if out.Keys, err = appendPKCS8Keys(out.Keys, pkcs8); err != nil {
				return nil, err
			}
			chain, err := jksUint32(r)
			if err != nil {
				return nil, err
			}
			for range chain {
				if err := readCertificate(); err != nil {
					return nil, err
				}
			}
		case 2: // TrustedCertEntry
			if err := readCertificate(); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("pki: JKS entry of type %d", tag)
		}
	}
	if r.Len() != 0 {
		return nil, errors.New("pki: trailing data in the JKS key store")
	}
	return out, nil
}

// jksUnprotect returns the PKCS#8 key in an EncryptedPrivateKeyInfo under the
// JKS key protector: salt(20) ‖ key XOR keystream ‖ SHA-1(password ‖ key),
// keystream block i = SHA-1(password ‖ block i−1), block 0 the salt.
func jksUnprotect(der, pw []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if err := unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("pki: JKS key: %w", err)
	}
	if !info.Algorithm.Algorithm.Equal(oidJKSKeyProtector) {
		return nil, fmt.Errorf("pki: JKS key protection %v: %w", info.Algorithm.Algorithm, x509.ErrUnsupportedAlgorithm)
	}
	n := len(info.Data)
	if n < 2*sha1.Size {
		return nil, errors.New("pki: JKS key cut short")
	}
	salt, masked, check := info.Data[:sha1.Size], info.Data[sha1.Size:n-sha1.Size], info.Data[n-sha1.Size:]
	key := make([]byte, len(masked))
	block := salt
	for i := range masked {
		if i%sha1.Size == 0 {
			next := sha1.Sum(append(bytes.Clone(pw), block...)) //nolint:gosec // G401: the JKS key protector is SHA-1
			block = next[:]
		}
		key[i] = masked[i] ^ block[i%sha1.Size]
	}
	sum := sha1.Sum(append(bytes.Clone(pw), key...)) //nolint:gosec // G401: the JKS key protector is SHA-1
	if subtle.ConstantTimeCompare(sum[:], check) != 1 {
		return nil, ErrIncorrectPassword
	}
	return key, nil
}

// jksPassword is the password as Java hashes it: UTF-16 big-endian.
func jksPassword(password string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(password)) {
		b = binary.BigEndian.AppendUint16(b, c)
	}
	return b
}

func jksUint32(r *bytes.Reader) (uint32, error) {
	var n uint32
	if binary.Read(r, binary.BigEndian, &n) != nil {
		return 0, errJKSShort
	}
	return n, nil
}

// jksBytes reads bytes counted by a big-endian length of lenSize bytes, 2 or 4.
func jksBytes(r *bytes.Reader, lenSize int) ([]byte, error) {
	var n uint32
	if lenSize == 2 {
		var n16 uint16
		if binary.Read(r, binary.BigEndian, &n16) != nil {
			return nil, errJKSShort
		}
		n = uint32(n16)
	} else {
		var err error
		if n, err = jksUint32(r); err != nil {
			return nil, err
		}
	}
	if int64(n) > int64(r.Len()) {
		return nil, errJKSShort
	}
	b := make([]byte, n)
	_, _ = r.Read(b) // r holds n bytes or more
	return b, nil
}

// appendPKCS8Keys appends to keys the key of a PKCS#8 key and the key
// agreement key IIT may keep in its attributes.
func appendPKCS8Keys(keys []*dstu4145.PrivateKey, pkcs8 []byte) ([]*dstu4145.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	keys = append(keys, key)
	switch agreement, err := ParsePKCS8KeyAgreementKey(pkcs8); {
	case err == nil:
		keys = append(keys, agreement)
	case !errors.Is(err, ErrNoKeyAgreementKey):
		return nil, err
	}
	return keys, nil
}
