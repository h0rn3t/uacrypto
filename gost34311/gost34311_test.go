package gost34311

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/h0rn3t/uacrypto/gost28147"
)

func sequence(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// Vectors come from GOST3411Digest of Bouncy Castle 1.86 with the expanded ДКЕ №1;
// "" and "abc" also match the hashes the IIT library accepted from test-ca.
var vectors = []struct {
	name string
	in   []byte
	want string
}{
	{"empty", nil, "da37bdf41145e39e34111775b40646e8059c2e969c1460bb98abccb26f0f76a5"},
	{"abc", []byte("abc"), "a34a53504d8ba070cb73a583146167a0a3c226d793440d9cea24465fe02251f2"},
	{"31 bytes", sequence(31), "695e4c73aa9d4884c3b9c74c8b77d0239e84e8bce0a9117ee6368144cf388cf9"},
	{"one block", sequence(32), "811cb06a8ee423182d9cc9d281f783908f4cfbaf47a68be8415d3499674a3063"},
	{"33 bytes", sequence(33), "1b2968cb9d37a2108fec6ac9f8feba278dac9cd2a11e6a4746a5b2c076714f69"},
	{"two blocks", sequence(64), "c03ee3bc611ae3acb822664325b3ec6e6278ddc93c9bcd7e757813d0e31fe281"},
	{"1000 bytes", sequence(1000), "306e602094d5685caf0e0802fbcf27213f96df6816da615c572b47544b9f1394"},
}

func TestSum(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Sum(tt.in); hex.EncodeToString(got[:]) != tt.want {
				t.Errorf("Sum(%s) = %x, want %s", tt.name, got, tt.want)
			}
		})
	}
}

// The examples of GOST 34.311-95 and GOST R 34.11-94 use their own test S-box,
// not a ДКЕ; the long messages are those of the standards' appendix.
func TestStandardExamples(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"},
		{"a", "d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd"},
		{"message digest", "ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d"},
		{"This is message, length=32 bytes", "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa"},
		{"Suppose the original message has length = 50 bytes", "471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208"},
	}
	for _, tt := range tests {
		h, err := NewWithSbox(gost28147.GOST34311ExampleSbox())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write([]byte(tt.in)) // hash.Hash.Write never returns an error
		if got := hex.EncodeToString(h.Sum(nil)); got != tt.want {
			t.Errorf("GOST 34.311 with the example S-box(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

// HMAC with GOST 34.311 is the HMAC of crypto/hmac over New: the vectors of
// cryptonite (atest_gost34_311.c, utest_hmac.c; BSD-2-Clause, see
// THIRD_PARTY_NOTICES.md) with ДКЕ №1.
func TestHMAC(t *testing.T) {
	tests := []struct{ key, data, want string }{
		{"70617373776f7264", "31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876",
			"482e7ae77f7607584c883961770fb374bd85062a1970df77a847c3f9c18ea9a0"},
		{"646e333130373836646d6931", "cf818caddfbdcdc940c8a530947427ed1a27949062602da471ada0d5cbff32d800000001",
			"20df9d6f41f32160b77b4d9394257bee5f71adf35025083e52bfa680296a2f15"},
	}
	for _, tt := range tests {
		key, _ := hex.DecodeString(tt.key)
		data, _ := hex.DecodeString(tt.data)
		m := hmac.New(New, key)
		_, _ = m.Write(data) // hash.Hash.Write never returns an error
		if got := hex.EncodeToString(m.Sum(nil)); got != tt.want {
			t.Errorf("HMAC(key %s, %s) = %s, want %s", tt.key, tt.data, got, tt.want)
		}
	}
}

// Writing in uneven chunks must give the one-shot result: the chunks cross block boundaries.
func TestStreaming(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := New()
			for chunk := range slices.Chunk(tt.in, 7) {
				_, _ = h.Write(chunk) // hash.Hash.Write never returns an error
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != tt.want {
				t.Errorf("New().Write(%s in 7-byte chunks).Sum = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

// Sum appends to its argument and leaves the running state alone, as hash.Hash requires.
func TestSumKeepsState(t *testing.T) {
	h := New()
	_, _ = h.Write([]byte("ab")) // hash.Hash.Write never returns an error
	prefix := []byte("prefix")
	first := h.Sum(bytes.Clone(prefix))
	if !bytes.HasPrefix(first, prefix) || len(first) != len(prefix)+Size {
		t.Fatalf("Sum(%q) = %x, want %q followed by %d bytes", prefix, first, prefix, Size)
	}
	if again := h.Sum(nil); !bytes.Equal(again, first[len(prefix):]) {
		t.Errorf("second Sum(nil) = %x, want %x", again, first[len(prefix):])
	}
	_, _ = h.Write([]byte("c")) // hash.Hash.Write never returns an error
	if got := hex.EncodeToString(h.Sum(nil)); got != vectors[1].want {
		t.Errorf("Sum after Write(ab), Sum, Write(c) = %s, want %s", got, vectors[1].want)
	}
	h.Reset()
	if got := hex.EncodeToString(h.Sum(nil)); got != vectors[0].want {
		t.Errorf("Sum after Reset = %s, want %s", got, vectors[0].want)
	}
	if h.Size() != Size || h.BlockSize() != BlockSize {
		t.Errorf("Size(), BlockSize() = %d, %d, want %d, %d", h.Size(), h.BlockSize(), Size, BlockSize)
	}
}

func TestNewWithSbox(t *testing.T) {
	h, err := NewWithSbox(gost28147.DKE1())
	if err != nil {
		t.Fatalf("NewWithSbox(DKE1()) error = %v", err)
	}
	_, _ = h.Write([]byte("abc")) // hash.Hash.Write never returns an error
	if got := hex.EncodeToString(h.Sum(nil)); got != vectors[1].want {
		t.Errorf("NewWithSbox(DKE1()) Sum(abc) = %s, want %s", got, vectors[1].want)
	}

	bad := gost28147.DKE1()
	bad[0][0] = 0x10
	if _, err := NewWithSbox(bad); err == nil {
		t.Error("NewWithSbox(S-box with value 16) error = nil, want error")
	}
}
