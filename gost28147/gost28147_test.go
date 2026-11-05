package gost28147

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", s, err)
	}
	return b
}

func sequence(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// The vector comes from GOST28147Engine of Bouncy Castle 1.86 with DSTU4145Params.getDefaultDKE.
func TestCipherVector(t *testing.T) {
	key := sequence(KeySize)
	plaintext := mustHex(t, "0123456789abcdef")
	want := mustHex(t, "e6e54bd045e6cd49")

	block, err := NewCipher(key, DKE1())
	if err != nil {
		t.Fatalf("NewCipher(%x, DKE1()) error = %v", key, err)
	}
	got := make([]byte, BlockSize)
	block.Encrypt(got, plaintext)
	if !bytes.Equal(got, want) {
		t.Errorf("Encrypt(%x) = %x, want %x", plaintext, got, want)
	}
	back := make([]byte, BlockSize)
	block.Decrypt(back, got)
	if !bytes.Equal(back, plaintext) {
		t.Errorf("Decrypt(%x) = %x, want %x", got, back, plaintext)
	}
}

func TestDecryptInvertsEncrypt(t *testing.T) {
	block, err := NewCipher(mustHex(t, "c0ffee00112233445566778899aabbccddeeff0123456789abcdef0011223344"), DKE1())
	if err != nil {
		t.Fatalf("NewCipher error = %v", err)
	}
	for _, in := range [][]byte{make([]byte, BlockSize), bytes.Repeat([]byte{0xff}, BlockSize), sequence(BlockSize)} {
		enc := make([]byte, BlockSize)
		block.Encrypt(enc, in)
		dec := make([]byte, BlockSize)
		block.Decrypt(dec, enc)
		if !bytes.Equal(dec, in) {
			t.Errorf("Decrypt(Encrypt(%x)) = %x, want %x", in, dec, in)
		}
	}
}

func TestNewCipherRejects(t *testing.T) {
	badSbox := DKE1()
	badSbox[3][7] = 16
	tests := []struct {
		name string
		key  []byte
		sbox Sbox
	}{
		{"short key", sequence(KeySize - 1), DKE1()},
		{"long key", sequence(KeySize + 1), DKE1()},
		{"nil key", nil, DKE1()},
		{"sbox value over 15", sequence(KeySize), badSbox},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewCipher(tt.key, tt.sbox); err == nil {
				t.Errorf("NewCipher(%x, sbox) error = nil, want error", tt.key)
			}
		})
	}
}

// DKE1 row 0 is the first 8 bytes of the packed DKE "a9d6eb45f13c7082", high nibble first.
func TestDKE1Layout(t *testing.T) {
	want := [16]byte{0xa, 0x9, 0xd, 0x6, 0xe, 0xb, 0x4, 0x5, 0xf, 0x1, 0x3, 0xc, 0x7, 0x0, 0x8, 0x2}
	if got := DKE1()[0]; got != want {
		t.Errorf("DKE1()[0] = %x, want %x", got, want)
	}
}

func TestUnpackDKE(t *testing.T) {
	packed := mustHex(t, "a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904")
	got, err := UnpackDKE(packed)
	if err != nil {
		t.Fatalf("UnpackDKE(default DKE) error = %v", err)
	}
	if got != DKE1() {
		t.Errorf("UnpackDKE(default DKE) = %x, want DKE1() %x", got, DKE1())
	}
	for _, n := range []int{0, 63, 65} {
		if _, err := UnpackDKE(make([]byte, n)); err == nil {
			t.Errorf("UnpackDKE(%d bytes) error = nil, want error", n)
		}
	}
}

func TestPackDKE(t *testing.T) {
	packed := mustHex(t, "a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904")
	if got := PackDKE(DKE1()); !bytes.Equal(got, packed) {
		t.Errorf("PackDKE(DKE1()) = %x, want %x", got, packed)
	}
	other := DKE1()
	other[7][15], other[7][14] = other[7][14], other[7][15]
	if back, err := UnpackDKE(PackDKE(other)); err != nil || back != other {
		t.Errorf("UnpackDKE(PackDKE(s)) = %x, %v, want s", back, err)
	}
}

func TestLookup16(t *testing.T) {
	for i, row := range DKE1() {
		for x := range uint32(16) {
			if got, want := lookup16(&row, x), uint32(row[x]); got != want {
				t.Fatalf("lookup16(DKE1 row %d, %d) = %d, want %d", i, x, got, want)
			}
		}
	}
}
