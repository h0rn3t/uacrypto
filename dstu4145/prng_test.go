package dstu4145

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/gost34311"
)

func fixedClock(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

func testSeed() []byte {
	seed := make([]byte, 40)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// TestPRNGCryptonite checks NewPRNG against cryptonite's generator: the table
// in testdata/cryptonite_prng.txt is printed by parity/cryptonite/prng.c,
// cryptonite built with a fixed clock (make -C parity cryptonite rebuilds it
// and compares). Each line is "seed time1 out1 data time2 out2": out1 is read
// after seeding at time1, out2 after Seed(data) at time2.
func TestPRNGCryptonite(t *testing.T) {
	raw, err := os.ReadFile("testdata/cryptonite_prng.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 8 {
		t.Fatalf("testdata/cryptonite_prng.txt has %d cases, want 8", len(lines))
	}
	for i, line := range lines {
		f := strings.Fields(line)
		if len(f) != 6 {
			t.Fatalf("case %d: %d fields, want 6", i, len(f))
		}
		seed, out1, out2 := mustHex(t, f[0]), mustHex(t, f[2]), mustHex(t, f[5])
		data := []byte(nil)
		if f[3] != "-" {
			data = mustHex(t, f[3])
		}
		t1, err1 := strconv.ParseInt(f[1], 10, 64)
		t2, err2 := strconv.ParseInt(f[4], 10, 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("case %d: times %q, %q", i, f[1], f[4])
		}

		clock := t1
		g := newPRNG(seed, func() time.Time { return time.Unix(clock, 0) })
		got := make([]byte, len(out1))
		if _, err := g.Read(got); err != nil {
			t.Fatalf("case %d: Read error = %v", i, err)
		}
		if !bytes.Equal(got, out1) {
			t.Errorf("case %d: after NewPRNG(%x) at %d, Read = %x, want %x", i, seed, t1, got, out1)
		}
		clock = t2
		g.Seed(data)
		got = make([]byte, len(out2))
		if _, err := g.Read(got); err != nil {
			t.Fatalf("case %d: Read after Seed error = %v", i, err)
		}
		if !bytes.Equal(got, out2) {
			t.Errorf("case %d: after Seed(%x) at %d, Read = %x, want %x", i, data, t2, got, out2)
		}
	}
}

func TestNewPRNGSeedLength(t *testing.T) {
	for _, n := range []int{0, 39, 41} {
		if _, err := NewPRNG(make([]byte, n)); err == nil {
			t.Errorf("NewPRNG(%d bytes) error = nil, want an error", n)
		}
	}
	if _, err := NewPRNG(make([]byte, 40)); err != nil {
		t.Errorf("NewPRNG(40 bytes) error = %v, want nil", err)
	}
}

// The output depends on the seed, the clock at seeding, and everything mixed
// in by Seed; the same inputs give the same stream.
func TestPRNGInputs(t *testing.T) {
	read := func(g *PRNG) []byte {
		t.Helper()
		out := make([]byte, 32)
		if n, err := g.Read(out); n != len(out) || err != nil {
			t.Fatalf("Read(32 bytes) = %d, %v, want 32, nil", n, err)
		}
		return out
	}
	base := read(newPRNG(testSeed(), fixedClock(1700000000)))
	if again := read(newPRNG(testSeed(), fixedClock(1700000000))); !bytes.Equal(again, base) {
		t.Errorf("same seed and clock: %x, want %x", again, base)
	}
	if later := read(newPRNG(testSeed(), fixedClock(1700000001))); bytes.Equal(later, base) {
		t.Errorf("clock one second later gives the same output %x", later)
	}
	other := testSeed()
	other[39] ^= 1
	if diff := read(newPRNG(other, fixedClock(1700000000))); bytes.Equal(diff, base) {
		t.Errorf("seed differing in the state byte gives the same output %x", diff)
	}

	g, h := newPRNG(testSeed(), fixedClock(1700000000)), newPRNG(testSeed(), fixedClock(1700000000))
	g.Seed([]byte("hello"))
	h.Seed([]byte("hellp"))
	if a, b := read(g), read(h); bytes.Equal(a, b) {
		t.Errorf("Seed(%q) and Seed(%q) give the same output %x", "hello", "hellp", a)
	}
}

// Reading in pieces gives the same stream as one read: the generator has no
// per-call state beyond its position.
func TestPRNGReadSplit(t *testing.T) {
	whole := make([]byte, 20)
	if _, err := newPRNG(testSeed(), fixedClock(1700000000)).Read(whole); err != nil {
		t.Fatal(err)
	}
	g := newPRNG(testSeed(), fixedClock(1700000000))
	var parts []byte
	for _, n := range []int{0, 1, 7, 12} {
		p := make([]byte, n)
		if _, err := g.Read(p); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, p...)
	}
	if !bytes.Equal(parts, whole) {
		t.Errorf("Read in pieces = %x, want %x", parts, whole)
	}
}

func TestPRNGLooped(t *testing.T) {
	g := newPRNG(testSeed(), fixedClock(1700000000))
	// Make the first encryption of the first bit return to the start state:
	// the generator must report the cycle instead of producing output.
	var first [8]byte
	for i := range first {
		first[i] = g.state[i] ^ g.t[i]
	}
	g.block.Encrypt(first[:], first[:])
	for i := range first {
		first[i] ^= g.t[i]
	}
	g.block.Encrypt(first[:], first[:])
	g.start = first
	n, err := g.Read(make([]byte, 4))
	if n != 0 || !errors.Is(err, errPRNGLooped) {
		t.Errorf("Read on a looping generator = %d, %v, want 0, %v", n, err, errPRNGLooped)
	}
}

func TestPRNGSignsAndVerifies(t *testing.T) {
	g, err := NewPRNG(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	k, err := GenerateKey(mustCurve(t, M257), g)
	if err != nil {
		t.Fatalf("GenerateKey(M257, PRNG) error = %v", err)
	}
	hash := gost34311.Sum([]byte("prng"))
	r, s, err := Sign(g, k, hash[:])
	if err != nil {
		t.Fatalf("Sign(PRNG) error = %v", err)
	}
	if !Verify(k.Public(), hash[:], r, s) {
		t.Error("Verify of a signature made with the PRNG = false, want true")
	}
}

func TestPRNGDestroy(t *testing.T) {
	g := newPRNG(testSeed(), fixedClock(1700000000))
	g.Destroy()
	g.Destroy() // idempotent
	if g.state != [8]byte{} || g.start != [8]byte{} || g.t != [8]byte{} {
		t.Errorf("after Destroy state, start, t = %x, %x, %x, want all zero", g.state, g.start, g.t)
	}
	g.Seed([]byte("must not revive the generator"))
	for _, n := range []int{0, 4} {
		if got, err := g.Read(make([]byte, n)); got != 0 || !errors.Is(err, errPRNGDestroyed) {
			t.Errorf("Read(%d bytes) after Destroy = %d, %v, want 0, %v", n, got, err, errPRNGDestroyed)
		}
	}
	if _, err := GenerateKey(mustCurve(t, M257), g); !errors.Is(err, errPRNGDestroyed) {
		t.Errorf("GenerateKey with a destroyed PRNG error = %v, want %v", err, errPRNGDestroyed)
	}
}
