package dstu4145

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"strconv"
	"sync"
	"testing"
	"testing/iotest"
)

// TestMulAddMatchesBig checks (r·d + e) mod n on limbs against math/big.
func TestMulAddMatchesBig(t *testing.T) {
	for _, c := range namedCurves() {
		t.Run("M"+strconv.Itoa(c.f.m), func(t *testing.T) {
			t.Parallel()
			n := c.n
			nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
			edges := []*big.Int{new(big.Int), big.NewInt(1), nMinus1}

			var triples [][3]*big.Int
			for _, r := range edges {
				for _, d := range edges {
					for _, e := range edges {
						triples = append(triples, [3]*big.Int{r, d, e})
					}
				}
			}
			rng := mrand.New(mrand.NewChaCha8([32]byte{'s', 'c', 'a', 'l', 'a', 'r', byte(c.f.m)})) //nolint:gosec // G404: reproducible test operands, not secrets
			random := func() *big.Int {
				x := new(big.Int)
				for range 7 {
					x.Lsh(x, 64).Or(x, new(big.Int).SetUint64(rng.Uint64()))
				}
				return x.Mod(x, n)
			}
			for range 100 {
				triples = append(triples, [3]*big.Int{random(), random(), random()})
			}

			for _, tr := range triples {
				r, d, e := scalarFromBig(tr[0]), scalarFromBig(tr[1]), scalarFromBig(tr[2])
				got := c.ord.mulAdd(&r, &d, &e)
				want := new(big.Int).Mul(tr[0], tr[1])
				want.Add(want, tr[2]).Mod(want, n)
				if got.big().Cmp(want) != 0 {
					t.Errorf("mulAdd(%x, %x, %x) = %x, want %x", tr[0], tr[1], tr[2], got.big(), want)
				}
			}
		})
	}
}

func TestOrderFromBytes(t *testing.T) {
	for _, c := range namedCurves() {
		t.Run("M"+strconv.Itoa(c.f.m), func(t *testing.T) {
			t.Parallel()
			n := c.n
			size := (n.BitLen() + 7) / 8
			one := big.NewInt(1)
			nMinus1 := new(big.Int).Sub(n, one)
			fill := func(x *big.Int, length int) []byte { return x.FillBytes(make([]byte, length)) }

			accept := map[string][]byte{
				"one":                     {1},
				"n-1":                     nMinus1.Bytes(),
				"n-1 with two zero bytes": append([]byte{0, 0}, fill(nMinus1, size)...),
			}
			for name, be := range accept {
				want := new(big.Int).SetBytes(be)
				k, ok := c.ord.fromBytes(be)
				if !ok || k.big().Cmp(want) != 0 {
					t.Errorf("fromBytes(%s) = %x, %t, want %x, true", name, k.big(), ok, want)
				}
				if got := c.ord.bytes(&k); !bytes.Equal(got, fill(want, size)) {
					t.Errorf("bytes(fromBytes(%s)) = %x, want %x in %d bytes", name, got, want, size)
				}
			}

			reject := map[string][]byte{
				"nil":                nil,
				"zero":               {0},
				"n":                  n.Bytes(),
				"n+1":                new(big.Int).Add(n, one).Bytes(),
				"2^(8 size)":         new(big.Int).Lsh(one, uint(8*size)).Bytes(),
				"nonzero extra byte": append([]byte{1}, fill(one, size)...),
			}
			for name, be := range reject {
				if k, ok := c.ord.fromBytes(be); ok {
					t.Errorf("fromBytes(%s) = %x, true, want false", name, k.big())
				}
			}
		})
	}
}

func TestRandomScalarRange(t *testing.T) {
	c := mustCurve(t, M257)
	size := (c.n.BitLen() + 7) / 8
	want := new(big.Int).Rsh(c.n, 1) // a valid value in [1, n-1]
	random := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0xff}, size)), bytes.NewReader(want.FillBytes(make([]byte, size))))
	k, err := randomScalar(c, random)
	if err != nil {
		t.Fatalf("randomScalar(all 0xff, then %x) error = %v", want, err)
	}
	if k.big().Cmp(want) != 0 {
		t.Errorf("randomScalar(all 0xff, then %x) = %x, want %x", want, k.big(), want)
	}

	if _, err := randomScalar(c, iotest.ErrReader(io.ErrUnexpectedEOF)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("randomScalar(failing reader) error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

// TestSignConcurrent signs with one key on one shared curve from several
// goroutines; run it with -race.
func TestSignConcurrent(t *testing.T) {
	c := mustCurve(t, M257)
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(M257) error = %v", err)
	}
	hash := mustHex(t, bcHash)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				r, s, err := Sign(rand.Reader, priv, hash)
				if err != nil {
					t.Errorf("Sign(M257) error = %v", err)
					return
				}
				if !Verify(priv.Public(), hash, r, s) {
					t.Error("Verify(Sign(M257)) = false, want true")
				}
			}
		})
	}
	wg.Wait()
}
