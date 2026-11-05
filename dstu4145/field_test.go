package dstu4145

import (
	"math/big"
	"math/rand/v2"
	"strconv"
	"testing"
)

// TestFieldMatchesReference checks the limb field against the math/big field
// it replaced, which the Bouncy Castle vectors validate.
func TestFieldMatchesReference(t *testing.T) {
	for _, c := range namedCurves() {
		t.Run("M"+strconv.Itoa(c.f.m), func(t *testing.T) {
			t.Parallel()
			f, ref := &c.f, newRefField(c.f.m, c.f.ks...)
			one := big.NewInt(1)
			all := new(big.Int).Sub(new(big.Int).Lsh(one, uint(f.m)), one)
			edges := []*big.Int{new(big.Int), one, new(big.Int).Lsh(one, uint(f.m-1)), all}

			var pairs [][2]*big.Int
			for _, a := range edges {
				for _, b := range edges {
					pairs = append(pairs, [2]*big.Int{a, b})
				}
			}
			rng := rand.New(rand.NewChaCha8([32]byte{'d', 's', 't', 'u', byte(f.m)})) //nolint:gosec // G404: reproducible test operands, not secrets
			random := func() *big.Int {
				x := new(big.Int)
				for range 7 {
					x.Lsh(x, 64).Or(x, new(big.Int).SetUint64(rng.Uint64()))
				}
				return x.And(x, all)
			}
			for range 200 {
				pairs = append(pairs, [2]*big.Int{random(), random()})
			}

			for _, p := range pairs {
				x, y := p[0], p[1]
				a, b := feFromBig(x), feFromBig(y)
				if got, want := f.mul(a, b).big(), ref.mul(x, y); got.Cmp(want) != 0 {
					t.Errorf("m=%d: mul(%x, %x) = %x, want %x", f.m, x, y, got, want)
				}
				if got, want := f.add(a, b).big(), ref.add(x, y); got.Cmp(want) != 0 {
					t.Errorf("m=%d: add(%x, %x) = %x, want %x", f.m, x, y, got, want)
				}
				if got, want := f.sqr(a).big(), ref.sqr(x); got.Cmp(want) != 0 {
					t.Errorf("m=%d: sqr(%x) = %x, want %x", f.m, x, got, want)
				}
				if x.Sign() == 0 {
					if got := f.inv(a); !got.isZero() {
						t.Errorf("m=%d: inv(0) = %x, want 0", f.m, got.big())
					}
				} else {
					if got, want := f.inv(a).big(), ref.inv(x); got.Cmp(want) != 0 {
						t.Errorf("m=%d: inv(%x) = %x, want %x", f.m, x, got, want)
					}
					if got := f.mul(a, f.inv(a)); !got.equal(felem{1}) {
						t.Errorf("m=%d: mul(%x, inv(%x)) = %x, want 1", f.m, x, x, got.big())
					}
				}
				if got, want := f.trace(a), ref.trace(x); got != uint64(want) {
					t.Errorf("m=%d: trace(%x) = %d, want %d", f.m, x, got, want)
				}
				if got, want := f.sqrt(a).big(), ref.sqrt(x); got.Cmp(want) != 0 {
					t.Errorf("m=%d: sqrt(%x) = %x, want %x", f.m, x, got, want)
				}
				got, ok := f.solveQuadratic(a)
				want, wantOK := ref.solveQuadratic(x)
				if got.big().Cmp(want) != 0 || ok != wantOK {
					t.Errorf("m=%d: solveQuadratic(%x) = %x, %t, want %x, %t", f.m, x, got.big(), ok, want, wantOK)
				}
			}
		})
	}
}
