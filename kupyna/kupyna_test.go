package kupyna

import (
	"bytes"
	"encoding/hex"
	"hash"
	"slices"
	"testing"
)

func sequence(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// Vectors come from DSTU7564Digest of Bouncy Castle 1.86; Kupyna-256 of the empty
// string is also the reference example of DSTU 7564:2014.
var vectors = []struct {
	name string
	size int
	in   []byte
	want string
}{
	{"256 empty", 256, nil, "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6"},
	{"256 abc", 256, []byte("abc"), "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"},
	{"256 fox", 256, []byte("The quick brown fox jumps over the lazy dog"), "996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6"},
	{"256 1000 bytes", 256, sequence(1000), "0b1b2e91bbc285076d6d0cb4c4489643308e500ca58e30c60eb8bb95acd64146"},
	{"384 empty", 384, nil, "e445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538"},
	{"384 abc", 384, []byte("abc"), "72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88"},
	{"384 fox", 384, []byte("The quick brown fox jumps over the lazy dog"), "0956d8afa9653b5231614decb1cceb8162ae5b8ff2dc3b02417f86dc4df621d0ca5b1ff399d494766c93a6d2513cae3a"},
	{"384 1000 bytes", 384, sequence(1000), "8099d29de77fa0b06c36dfe7bb9ed124bf017ae7884676fc2c8b806431fba3ecbd28830863aebf8629c58184ca8ea98e"},
	{"512 empty", 512, nil, "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538"},
	{"512 abc", 512, []byte("abc"), "9e5be7daf7b68b49d2ecbd04c7a5b3af72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88"},
	{"512 fox", 512, []byte("The quick brown fox jumps over the lazy dog"), "d1b469f43e0963735b6cd08a6e75fc370956d8afa9653b5231614decb1cceb8162ae5b8ff2dc3b02417f86dc4df621d0ca5b1ff399d494766c93a6d2513cae3a"},
	{"512 1000 bytes", 512, sequence(1000), "c0d47e77b424cd968a5f20d6964513268099d29de77fa0b06c36dfe7bb9ed124bf017ae7884676fc2c8b806431fba3ecbd28830863aebf8629c58184ca8ea98e"},
}

func oneShot(size int, data []byte) []byte {
	switch size {
	case 256:
		s := Sum256(data)
		return s[:]
	case 384:
		s := Sum384(data)
		return s[:]
	default:
		s := Sum512(data)
		return s[:]
	}
}

func newHash(size int) hash.Hash {
	switch size {
	case 256:
		return New256()
	case 384:
		return New384()
	default:
		return New512()
	}
}

func TestSum(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hex.EncodeToString(oneShot(tt.size, tt.in)); got != tt.want {
				t.Errorf("Sum%d(%s) = %s, want %s", tt.size, tt.name, got, tt.want)
			}
		})
	}
}

// Uneven chunks cross the 64- and 128-byte block boundaries.
func TestStreaming(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHash(tt.size)
			for chunk := range slices.Chunk(tt.in, 13) {
				_, _ = h.Write(chunk) // hash.Hash.Write never returns an error
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != tt.want {
				t.Errorf("New%d().Write(%s in 13-byte chunks).Sum = %s, want %s", tt.size, tt.name, got, tt.want)
			}
			if h.Size() != tt.size/8 {
				t.Errorf("New%d().Size() = %d, want %d", tt.size, h.Size(), tt.size/8)
			}
		})
	}
}

func TestBlockSize(t *testing.T) {
	for size, want := range map[int]int{256: 64, 384: 128, 512: 128} {
		if got := newHash(size).BlockSize(); got != want {
			t.Errorf("New%d().BlockSize() = %d, want %d", size, got, want)
		}
	}
}

// Sum appends to its argument and leaves the running state alone, as hash.Hash requires.
func TestSumKeepsState(t *testing.T) {
	h := New256()
	_, _ = h.Write([]byte("ab")) // hash.Hash.Write never returns an error
	prefix := []byte("prefix")
	first := h.Sum(bytes.Clone(prefix))
	if !bytes.HasPrefix(first, prefix) || len(first) != len(prefix)+Size256 {
		t.Fatalf("Sum(%q) = %x, want %q followed by %d bytes", prefix, first, prefix, Size256)
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
}
