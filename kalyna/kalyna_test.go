package kalyna_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/h0rn3t/uacrypto/kalyna"
)

type constructor func(key []byte) (cipher.Block, error)

// sequence returns n bytes start, start+1, ...: the key and input pattern of
// the DSTU 7624:2014 examples.
func sequence(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i) //nolint:gosec // G115: wraps by design, the pattern continues mod 256
	}
	return b
}

// TestVectors uses key 00 01 02 ... and input that continues the key
// sequence. Encryption of 128/128 is the example of DSTU 7624:2014; all
// values are from DSTU7624Engine of Bouncy Castle 1.86.
func TestVectors(t *testing.T) {
	tests := []struct {
		name       string
		newCipher  constructor
		block, key int
		encrypted  string
		decrypted  string
	}{
		{"128/128", kalyna.NewCipher128, 16, 16,
			"81bf1c7d779bac20e1c9ea39b4d2ad06",
			"22fdd5e27e7d4b2242029573eaebc373"},
		{"128/256", kalyna.NewCipher128, 16, 32,
			"58ec3e091000158a1148f7166f334f14",
			"f8ec42620c308145774b29af98e64afb"},
		{"256/256", kalyna.NewCipher256, 32, 32,
			"f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c",
			"dd335334d5805bd5ef2eb16a999a0a528529d2c359d451a7cf3d8e85957be24b"},
		{"256/512", kalyna.NewCipher256, 32, 64,
			"606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9",
			"6eb5014750c396239a0b0887229b5186310ad320d15a48ea8e005244c23f803f"},
		{"512/512", kalyna.NewCipher512, 64, 64,
			"4a26e31b811c356aa61dd6ca0596231a67ba8354aa47f3a13e1deec320eb56b895d0f417175bab662fd6f134bb15c86ccb906a26856efeb7c5bc6472940dd9d9",
			"5a15251a2997d7b609729d865d07331aab40aa530fef8d9da8386c272204e283dc3fc22e2b908254e6b9e5bb5f9e39dcbc12ee032abfc9f8d75612c414b5f9cc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := tt.newCipher(sequence(0, tt.key))
			if err != nil {
				t.Fatal(err)
			}
			if b.BlockSize() != tt.block {
				t.Errorf("BlockSize() = %d, want %d", b.BlockSize(), tt.block)
			}
			in := sequence(tt.key, tt.block)
			out := make([]byte, tt.block)
			b.Encrypt(out, in)
			if got := hex.EncodeToString(out); got != tt.encrypted {
				t.Errorf("Encrypt(%x) = %s, want %s", in, got, tt.encrypted)
			}
			b.Decrypt(out, in)
			if got := hex.EncodeToString(out); got != tt.decrypted {
				t.Errorf("Decrypt(%x) = %s, want %s", in, got, tt.decrypted)
			}
		})
	}
}

func TestRoundTripInPlace(t *testing.T) {
	tests := []struct {
		name      string
		newCipher constructor
		key       int
	}{
		{"128/128", kalyna.NewCipher128, 16},
		{"128/256", kalyna.NewCipher128, 32},
		{"256/256", kalyna.NewCipher256, 32},
		{"256/512", kalyna.NewCipher256, 64},
		{"512/512", kalyna.NewCipher512, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := tt.newCipher(sequence(7, tt.key))
			if err != nil {
				t.Fatal(err)
			}
			want := sequence(200, b.BlockSize())
			buf := bytes.Clone(want)
			b.Encrypt(buf, buf)
			if bytes.Equal(buf, want) {
				t.Fatalf("Encrypt(%x) left the block unchanged", want)
			}
			b.Decrypt(buf, buf)
			if !bytes.Equal(buf, want) {
				t.Errorf("Decrypt(Encrypt(%x)) = %x", want, buf)
			}
		})
	}
}

func TestRejectsKeySize(t *testing.T) {
	tests := []struct {
		name      string
		newCipher constructor
		key       []byte
	}{
		{"128 nil key", kalyna.NewCipher128, nil},
		{"128 with 24-byte key", kalyna.NewCipher128, make([]byte, 24)},
		{"128 with 64-byte key", kalyna.NewCipher128, make([]byte, 64)},
		{"256 with 16-byte key", kalyna.NewCipher256, make([]byte, 16)},
		{"512 with 32-byte key", kalyna.NewCipher512, make([]byte, 32)},
		{"512 with 128-byte key", kalyna.NewCipher512, make([]byte, 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if b, err := tt.newCipher(tt.key); err == nil {
				t.Errorf("NewCipher(%d-byte key) = %v, want error", len(tt.key), b)
			}
		})
	}
}

func TestShortBufferPanics(t *testing.T) {
	b, err := kalyna.NewCipher128(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(){
		"Encrypt short src": func() { b.Encrypt(make([]byte, 16), make([]byte, 15)) },
		"Encrypt short dst": func() { b.Encrypt(make([]byte, 15), make([]byte, 16)) },
		"Decrypt short src": func() { b.Decrypt(make([]byte, 16), make([]byte, 15)) },
		"Decrypt short dst": func() { b.Decrypt(make([]byte, 15), make([]byte, 16)) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic, want panic on a short buffer", name)
				}
			}()
			f()
		})
	}
}
