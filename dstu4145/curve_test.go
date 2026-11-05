package dstu4145

import (
	"math/big"
	mrand "math/rand/v2"
	"strconv"
	"testing"
)

// TestScalarMultMatchesVartime checks the ladder against double-and-add. The
// ladder passes through the point at infinity for three edge scalars: k = 1
// runs over 2n + 1, so jP = nP one step before the end; k = n-2 runs over
// 2n - 2, so (j+1)P = nP one step before the end; k = n-1 ends with
// (k+1)P = nP.
func TestScalarMultMatchesVartime(t *testing.T) {
	for _, id := range []int{M163, M257, M431} {
		c := mustCurve(t, id)
		t.Run("M"+strconv.Itoa(c.f.m), func(t *testing.T) {
			t.Parallel()
			rng := mrand.New(mrand.NewChaCha8([32]byte{'l', 'a', 'd', 'd', 'e', 'r', byte(id)})) //nolint:gosec // G404: reproducible test scalars, not secrets
			one := big.NewInt(1)
			nMinus1 := new(big.Int).Sub(c.n, one)
			random := func() *big.Int { // in [1, n-1]
				x := new(big.Int)
				for range 7 {
					x.Lsh(x, 64).Or(x, new(big.Int).SetUint64(rng.Uint64()))
				}
				return x.Mod(x, nMinus1).Add(x, one)
			}

			ks := []*big.Int{one, big.NewInt(2), big.NewInt(3), new(big.Int).Sub(c.n, big.NewInt(2)), nMinus1}
			for range 20 {
				ks = append(ks, random())
			}
			bases := map[string]point{"G": c.g, "Q": c.scalarMultVartime(c.g, random())}

			for name, p := range bases {
				for _, k := range ks {
					s := scalarFromBig(k)
					got, want := c.scalarMult(p, &s), c.scalarMultVartime(p, k)
					if got != want {
						t.Errorf("scalarMult(%s, %x) = (%x, %x, inf %t), want (%x, %x, inf %t)",
							name, k, got.x.big(), got.y.big(), got.inf, want.x.big(), want.y.big(), want.inf)
					}
				}
			}
		})
	}
}
