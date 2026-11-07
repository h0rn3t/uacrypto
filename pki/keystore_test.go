package pki_test

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: the JKS store digest is SHA-1
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/h0rn3t/uacrypto/pki"
)

// jkurwa-key6-40a0.dat and jkurwa-key6-iit-123456.dat are the older IIT
// store written with jkurwa's ASN.1 and gost89's KDF and cipher; the public
// keys are jkurwa's for what it decrypts from them.
func TestDecodeIITKey6(t *testing.T) {
	pub40a0, err := pki.ParsePublicKey(certSPKI(t, readTestdata(t, "jkurwa-self-signed-enc-40a0.cer")))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		file, password string
		wantPub        string
	}{
		{"jkurwa-key6-40a0.dat", "password", hex.EncodeToString(pub40a0.Key.Bytes())},
		{"jkurwa-key6-iit-123456.dat", "123456", "01e0d6d2b19e9e0cb559219f61d6e1c932217767a1d354f493c7a6479debc446cb"},
		// Key-6.dat in PBES2, as IIT writes it now.
		{"jkurwa-store-a040.dat", "password", hex.EncodeToString(pub40a0.Key.Bytes())},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data := readTestdata(t, tt.file)
			store, err := pki.DecodeIITKey6(data, tt.password)
			if err != nil {
				t.Fatalf("DecodeIITKey6(%s) error = %v", tt.file, err)
			}
			if len(store.Keys) != 1 || len(store.Certificates) != 0 {
				t.Fatalf("DecodeIITKey6(%s) = %d keys and %d certificates, want 1 and none", tt.file, len(store.Keys), len(store.Certificates))
			}
			if got := hex.EncodeToString(store.Keys[0].Public().Bytes()); got != tt.wantPub {
				t.Errorf("DecodeIITKey6(%s) public key = %s, want %s", tt.file, got, tt.wantPub)
			}
			if _, err := pki.DecodeIITKey6(data, "wrong"); !errors.Is(err, pki.ErrIncorrectPassword) {
				t.Errorf("DecodeIITKey6(%s, wrong password) error = %v, want %v", tt.file, err, pki.ErrIncorrectPassword)
			}
			for n := range len(data) {
				if _, err := pki.DecodeIITKey6(data[:n], tt.password); err == nil {
					t.Errorf("DecodeIITKey6(%s cut to %d bytes) error = nil, want error", tt.file, n)
				}
			}
		})
	}
}

type iitStore struct {
	Algorithm struct {
		Algorithm asn1.ObjectIdentifier
		Params    struct{ MAC, Pad []byte }
	}
	Data []byte
}

func TestDecodeIITKey6Malformed(t *testing.T) {
	var good iitStore
	if _, err := asn1.Unmarshal(readTestdata(t, "jkurwa-key6-40a0.dat"), &good); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(s *iitStore)
	}{
		{"check value of 3 bytes", func(s *iitStore) { s.Algorithm.Params.MAC = s.Algorithm.Params.MAC[:3] }},
		{"tail of a whole block", func(s *iitStore) { s.Algorithm.Params.Pad = make([]byte, 8) }},
		{"not whole blocks", func(s *iitStore) { s.Data = s.Data[:len(s.Data)-1] }},
		{"no key", func(s *iitStore) { s.Data, s.Algorithm.Params.Pad = nil, nil }},
		{"unknown store", func(s *iitStore) { s.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := good
			s.Algorithm.Params.MAC = bytes.Clone(good.Algorithm.Params.MAC)
			tt.change(&s)
			der, err := asn1.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pki.DecodeIITKey6(der, "password"); err == nil || errors.Is(err, pki.ErrIncorrectPassword) {
				t.Errorf("DecodeIITKey6(%s) error = %v, want a format error", tt.name, err)
			}
		})
	}
}

// The d of the key in both stores, from the PKCS#8 key Bouncy Castle wrote
// for it.
const jksKeyD = "50bf5cd548a70b65a24619392637f6bdcf55e86510eea9a9e212399769d1a523"

// jdk-bc-dstu4145.jks is written by the JDK, its key and certificate made by
// Bouncy Castle; rust-dstu4145.jks holds the same key and certificate,
// written by ua-cryptography-pki with the key in the form of IIT.
func TestDecodeJKS(t *testing.T) {
	czoRoot := readTestdata(t, "czo-test-ocsp-root.der")
	tests := []struct {
		file      string
		wantCerts int
	}{
		{"jdk-bc-dstu4145.jks", 2},
		{"rust-dstu4145.jks", 1},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data := readTestdata(t, tt.file)
			for _, in := range [][]byte{data, append([]byte{0x51, 1, 2, 3, 4, 5}, data...)} {
				store, err := pki.DecodeJKS(in, "пароль")
				if err != nil {
					t.Fatalf("DecodeJKS(%s, % x…) error = %v", tt.file, in[:6], err)
				}
				if len(store.Keys) != 1 || len(store.Certificates) != tt.wantCerts {
					t.Fatalf("DecodeJKS(%s) = %d keys and %d certificates, want 1 and %d", tt.file, len(store.Keys), len(store.Certificates), tt.wantCerts)
				}
				if got := hex.EncodeToString(store.Keys[0].Bytes()); got != jksKeyD {
					t.Errorf("DecodeJKS(%s) key d = %s, want %s", tt.file, got, jksKeyD)
				}
				leaf := store.Certificates[len(store.Certificates)-1]
				if _, err := store.KeyFor(leaf); err != nil {
					t.Errorf("DecodeJKS(%s).KeyFor(%s) error = %v", tt.file, leaf.Subject, err)
				}
				if tt.wantCerts == 2 && !bytes.Equal(store.Certificates[0].Raw, czoRoot) {
					t.Errorf("DecodeJKS(%s) trusted certificate = %s, want czo-test-ocsp-root.der", tt.file, store.Certificates[0].Subject)
				}
			}
			if _, err := pki.DecodeJKS(data, "parol"); !errors.Is(err, pki.ErrIncorrectPassword) {
				t.Errorf("DecodeJKS(%s, wrong password) error = %v, want %v", tt.file, err, pki.ErrIncorrectPassword)
			}
			// The store opens with another password, the key does not.
			other := withJKSDigest(data[:len(data)-sha1.Size], "інший")
			if _, err := pki.DecodeJKS(other, "інший"); !errors.Is(err, pki.ErrIncorrectPassword) {
				t.Errorf("DecodeJKS(%s, wrong key password) error = %v, want %v", tt.file, err, pki.ErrIncorrectPassword)
			}
			body := data[:len(data)-sha1.Size]
			for n := range len(body) {
				if _, err := pki.DecodeJKS(withJKSDigest(body[:n], "пароль"), "пароль"); err == nil {
					t.Errorf("DecodeJKS(%s cut to %d bytes) error = nil, want error", tt.file, n)
				}
			}
		})
	}
}

func TestDecodeJKSMalformed(t *testing.T) {
	data := readTestdata(t, "rust-dstu4145.jks")
	body := data[:len(data)-sha1.Size]
	tests := []struct {
		name   string
		change func(b []byte) []byte
	}{
		{"not JKS", func(b []byte) []byte { b[0] = 0xCE; return b }},
		{"version 3", func(b []byte) []byte { binary.BigEndian.PutUint32(b[4:], 3); return b }},
		{"one entry more", func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 2); return b }},
		{"entry of type 3", func(b []byte) []byte { binary.BigEndian.PutUint32(b[12:], 3); return b }},
		{"trailing byte", func(b []byte) []byte { return append(b, 0) }},
		{"huge alias", func(b []byte) []byte { binary.BigEndian.PutUint16(b[16:], 0xFFFF); return b }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := withJKSDigest(tt.change(bytes.Clone(body)), "пароль")
			if _, err := pki.DecodeJKS(in, "пароль"); err == nil || errors.Is(err, pki.ErrIncorrectPassword) {
				t.Errorf("DecodeJKS(%s) error = %v, want a format error", tt.name, err)
			}
		})
	}
}

func FuzzDecodeJKS(f *testing.F) {
	for _, name := range []string{"jdk-bc-dstu4145.jks", "rust-dstu4145.jks"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data[:len(data)-sha1.Size])
	}
	// The digest is made for every input, so that the parser behind it runs:
	// any input is an error or a store, never a panic.
	f.Fuzz(func(t *testing.T, body []byte) {
		store, err := pki.DecodeJKS(withJKSDigest(body, "пароль"), "пароль")
		if err == nil && store == nil {
			t.Errorf("DecodeJKS(% x) = nil, nil", body)
		}
	})
}

// withJKSDigest appends the store digest of Java's JKS to body:
// SHA-1(password in UTF-16BE ‖ "Mighty Aphrodite" ‖ body).
func withJKSDigest(body []byte, password string) []byte {
	h := sha1.New() //nolint:gosec // G401: the JKS store digest is SHA-1
	for _, c := range utf16.Encode([]rune(password)) {
		h.Write(binary.BigEndian.AppendUint16(nil, c))
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(body)
	return h.Sum(bytes.Clone(body))
}
