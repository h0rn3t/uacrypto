package dstu4145

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"testing"
)

// leHex decodes a little-endian hex string of cryptonite's tests into a
// big-endian byte string.
func leHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(b)
	return b
}

// The vector of dstu4145_dh_test in cryptonite's utest_dstu4145.c
// (BSD-2-Clause, see THIRD_PARTY_NOTICES.md), on M257 with the cofactor.
func TestECDHCryptonite(t *testing.T) {
	c, err := NamedCurve(M257)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := NewPrivateKey(c, leHex(t, "4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900"))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewPrivateKey(c, leHex(t, "124356567867897806288183f164044ec3cdbd00288856db40b4cdf07123230800"))
	if err != nil {
		t.Fatal(err)
	}
	want := leHex(t, "85165e0486221b3bee3211ac63b3809b23ea2f8c63e8d38e55e99792694fbb3701")
	for _, tt := range []struct {
		name  string
		priv  *PrivateKey
		other *PublicKey
	}{{"k1·Q2", k1, k2.Public()}, {"k2·Q1", k2, k1.Public()}} {
		got, err := tt.priv.ECDH(tt.other)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("ECDH %s = %x, %v; want %x", tt.name, got, err, want)
		}
	}
}

func TestECDHAgreesOnEveryCurve(t *testing.T) {
	for id := range 10 {
		c, err := NamedCurve(id)
		if err != nil {
			t.Fatal(err)
		}
		a, err := GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b, err := GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ab, err1 := a.ECDH(b.Public())
		ba, err2 := b.ECDH(a.Public())
		if err1 != nil || err2 != nil || !bytes.Equal(ab, ba) {
			t.Errorf("curve %d: a·Qb = %x, %v; b·Qa = %x, %v; want equal", id, ab, err1, ba, err2)
		}
		if len(ab) != (c.f.m+7)/8 {
			t.Errorf("curve %d: shared secret is %d bytes, want %d", id, len(ab), (c.f.m+7)/8)
		}
	}
}

func TestECDHRejectsOtherCurve(t *testing.T) {
	c1, _ := NamedCurve(M257)
	c2, _ := NamedCurve(M257 + 1)
	a, _ := GenerateKey(c1, rand.Reader)
	b, _ := GenerateKey(c2, rand.Reader)
	if got, err := a.ECDH(b.Public()); err == nil {
		t.Errorf("ECDH(key on another curve) = %x, nil; want an error", got)
	}
}

// The curves with A = 0 (173 and 257 bits) have cofactor 4, the rest 2.
func TestCofactor(t *testing.T) {
	for id, want := range []int64{2, 2, 4, 2, 2, 2, 4, 2, 2, 2} {
		c, _ := NamedCurve(id)
		if got := c.cofactor(); got.Int64() != want {
			t.Errorf("curve %d (m = %d) cofactor = %v, want %d", id, c.f.m, got, want)
		}
	}
}
