package gost28147

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The vectors are those of the certified cryptonite library
// (src/cryptoniteAtest/c/atest_gost28147.c and
// src/cryptoniteUtest/c/utest_gost28147.c, BSD-2-Clause, see
// THIRD_PARTY_NOTICES.md), computed with the S-box of the GOST 34.311-95
// examples.
const (
	modeKey = "0100000002000000030000000400000005000000060000000700000008000000"
	modeIV  = "0300000003000000"
)

func exampleCipher(t *testing.T, key string) cipher.Block {
	t.Helper()
	b, err := NewCipher(mustHex(t, key), GOST34311ExampleSbox())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExampleSboxECB(t *testing.T) {
	b := exampleCipher(t, "348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf")
	in := mustHex(t, "34c01533e37d1c56e9431604f57e37a18f90eb0333a33362")
	want := "863e78dd2d60d13ce38f0f691f68f7feb99bb76c3073142d"
	got := make([]byte, len(in))
	for i := 0; i < len(in); i += BlockSize {
		b.Encrypt(got[i:], in[i:])
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("Encrypt(%x) = %x, want %s", in, got, want)
	}
}

func TestCTR(t *testing.T) {
	tests := []struct{ in, want string }{
		{"0102030405060708090a0b0c0d0e0f101112131415161718", "da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4"},
		{"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
			"da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f40bd18016490ddff6e446981c559778e4273350c755e2113dd8c2533450b2d481d004af84b8daa2cc"},
	}
	b := exampleCipher(t, modeKey)
	for _, tt := range tests {
		in := mustHex(t, tt.in)
		for _, cut := range []int{0, 3, 8, 9, len(in)} {
			s, err := NewCTR(b, mustHex(t, modeIV))
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(in))
			s.XORKeyStream(got[:cut], in[:cut])
			s.XORKeyStream(got[cut:], in[cut:])
			if hex.EncodeToString(got) != tt.want {
				t.Errorf("CTR(%x) split at %d = %x, want %s", in, cut, got, tt.want)
			}
		}
	}
	if _, err := NewCTR(b, make([]byte, 7)); err == nil {
		t.Error("NewCTR(7-byte IV) error = nil, want an error")
	}
}

// GOST 28147-89 cipher feedback is the CFB of crypto/cipher over the block.
func TestCFB(t *testing.T) {
	b := exampleCipher(t, modeKey)
	in := mustHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718")
	want := "d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3"
	got := make([]byte, len(in))
	cipher.NewCFBEncrypter(b, mustHex(t, modeIV)).XORKeyStream(got, in) //nolint:staticcheck // SA1019: the mode GOST 28147-89 defines
	if hex.EncodeToString(got) != want {
		t.Errorf("CFB(%x) = %x, want %s", in, got, want)
	}
	back := make([]byte, len(got))
	cipher.NewCFBDecrypter(b, mustHex(t, modeIV)).XORKeyStream(back, got) //nolint:staticcheck // SA1019: the mode GOST 28147-89 defines
	if !bytes.Equal(back, in) {
		t.Errorf("CFB decrypt(%x) = %x, want %x", got, back, in)
	}
}

func TestMAC(t *testing.T) {
	data := mustHex(t, "d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3")
	h, err := NewMAC(mustHex(t, modeKey), GOST34311ExampleSbox(), 4)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(data[:5])
	h.Write(data[5:])
	if got := hex.EncodeToString(h.Sum(nil)); got != "7e4a9667" {
		t.Errorf("MAC(%x) = %s, want 7e4a9667", data, got)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != "7e4a9667" {
		t.Errorf("second Sum = %s, want 7e4a9667: Sum must not change the state", got)
	}

	long, err := NewMAC(mustHex(t, modeKey), GOST34311ExampleSbox(), 8)
	if err != nil {
		t.Fatal(err)
	}
	long.Write(data)
	if got := long.Sum(nil); !bytes.HasPrefix(got, mustHex(t, "7e4a9667")) || len(got) != 8 {
		t.Errorf("8-byte MAC(%x) = %x, want 8 bytes starting 7e4a9667", data, got)
	}
	h.Reset()
	h.Write(data)
	if got := hex.EncodeToString(h.Sum(nil)); got != "7e4a9667" {
		t.Errorf("MAC after Reset = %s, want 7e4a9667", got)
	}

	for _, size := range []int{0, 9} {
		if _, err := NewMAC(mustHex(t, modeKey), GOST34311ExampleSbox(), size); err == nil {
			t.Errorf("NewMAC(size %d) error = nil, want an error", size)
		}
	}
	if _, err := NewMAC(make([]byte, 31), GOST34311ExampleSbox(), 4); err == nil {
		t.Error("NewMAC(31-byte key) error = nil, want an error")
	}
}

// A message that ends inside a block is padded with zero bytes. The MACs are
// those gost89 0.1.12 (jkurwa) computes under ДКЕ №1.
func TestMACPartialBlock(t *testing.T) {
	tests := []struct{ msg, want string }{
		{"0102030405060708090a0b0c0d", "12ac1591e5415c03"},
		{"0102030405060708090a0b0c0d0e0f1011", "90db516165409514"},
	}
	for _, tt := range tests {
		h, err := NewMAC(mustHex(t, modeKey), DKE1(), 8)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(mustHex(t, tt.msg))
		if got := h.Sum([]byte{0xff}); hex.EncodeToString(got) != "ff"+tt.want {
			t.Errorf("MAC(%s) appended to ff = %x, want ff%s", tt.msg, got, tt.want)
		}
		if h.Size() != 8 || h.BlockSize() != BlockSize {
			t.Errorf("Size(), BlockSize() = %d, %d, want 8, %d", h.Size(), h.BlockSize(), BlockSize)
		}
	}
}

func TestCTRErrors(t *testing.T) {
	if _, err := NewCTR(nil, make([]byte, BlockSize)); err == nil {
		t.Error("NewCTR(nil block) error = nil, want an error")
	}
	s, err := NewCTR(exampleCipher(t, modeKey), mustHex(t, modeIV))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("XORKeyStream(3-byte dst, 4-byte src) did not panic, want a panic")
		}
	}()
	s.XORKeyStream(make([]byte, 3), make([]byte, 4))
}

// The high word adds 0x01010104 modulo 2^32-1: a carry out of 32 bits comes
// back in as 1, and a sum of exactly 2^32-1 stays as it is.
func TestCTRCounterModulus(t *testing.T) {
	tests := []struct{ high, want uint32 }{
		{0x00000000, 0x01010104},
		{0xfefefefb, 0xffffffff},
		{0xfefefefc, 0x00000001},
		{0xffffffff, 0x01010104},
	}
	for _, tt := range tests {
		c := &ctr{block: exampleCipher(t, modeKey)}
		binary.LittleEndian.PutUint32(c.counter[:4], 0xfefefeff)
		binary.LittleEndian.PutUint32(c.counter[4:], tt.high)
		c.next()
		if got := binary.LittleEndian.Uint32(c.counter[4:]); got != tt.want {
			t.Errorf("high word %#x + 0x01010104 mod 2^32-1 = %#x, want %#x", tt.high, got, tt.want)
		}
		if got := binary.LittleEndian.Uint32(c.counter[:4]); got != 0x00000000 {
			t.Errorf("low word 0xfefefeff + 0x01010101 mod 2^32 = %#x, want 0", got)
		}
	}
}

func TestDKE1Appendix(t *testing.T) {
	first, err := DKE1Appendix(1)
	if err != nil || first != DKE1() {
		t.Errorf("DKE1Appendix(1) = %v, %v; want DKE1()", first, err)
	}
	seen := map[Sbox]int{}
	for n := 1; n <= 10; n++ {
		s, err := DKE1Appendix(n)
		if err != nil {
			t.Fatalf("DKE1Appendix(%d) error = %v", n, err)
		}
		if m, ok := seen[s]; ok {
			t.Errorf("DKE1Appendix(%d) = DKE1Appendix(%d)", n, m)
		}
		seen[s] = n
	}
	for _, n := range []int{0, 11} {
		if _, err := DKE1Appendix(n); err == nil {
			t.Errorf("DKE1Appendix(%d) error = nil, want an error", n)
		}
	}
}
