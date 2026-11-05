package dstu4145

import "math/big"

// refField is the former math/big GF(2^m), kept as the test oracle for field:
// polynomial basis, an element is a big.Int whose bit i is the coefficient of
// x^i. Every method takes reduced elements (below 2^m) and returns a new value.
type refField struct {
	m    int
	poly *big.Int // the reduction polynomial x^m + x^k... + 1
}

func newRefField(m int, ks ...int) refField {
	poly := new(big.Int).SetBit(new(big.Int), m, 1)
	poly.SetBit(poly, 0, 1)
	for _, k := range ks {
		poly.SetBit(poly, k, 1)
	}
	return refField{m: m, poly: poly}
}

func (f refField) add(a, b *big.Int) *big.Int { return new(big.Int).Xor(a, b) }

// mul is shift-and-add multiplication, reducing after every shift.
func (f refField) mul(a, b *big.Int) *big.Int {
	x := new(big.Int).Set(a)
	z := new(big.Int)
	for i := range f.m {
		if b.Bit(i) == 1 {
			z.Xor(z, x)
		}
		x.Lsh(x, 1)
		if x.Bit(f.m) == 1 {
			x.Xor(x, f.poly)
		}
	}
	return z
}

func (f refField) sqr(a *big.Int) *big.Int { return f.mul(a, a) }

// inv is the extended Euclidean algorithm over GF(2)[x]; a must not be zero.
func (f refField) inv(a *big.Int) *big.Int {
	u := new(big.Int).Set(a)
	v := new(big.Int).Set(f.poly)
	g1 := big.NewInt(1)
	g2 := new(big.Int)
	for u.Cmp(big.NewInt(1)) != 0 {
		j := u.BitLen() - v.BitLen()
		if j < 0 {
			u, v = v, u
			g1, g2 = g2, g1
			j = -j
		}
		u.Xor(u, new(big.Int).Lsh(v, uint(j)))
		g1.Xor(g1, new(big.Int).Lsh(g2, uint(j)))
	}
	return g1
}

// trace is Tr(a) = a + a^2 + ... + a^(2^(m-1)), which is 0 or 1.
func (f refField) trace(a *big.Int) uint {
	t := new(big.Int).Set(a)
	for range f.m - 1 {
		t = f.add(f.sqr(t), a)
	}
	return t.Bit(0)
}

// sqrt is a^(2^(m-1)), the unique square root in GF(2^m).
func (f refField) sqrt(a *big.Int) *big.Int {
	r := a
	for range f.m - 1 {
		r = f.sqr(r)
	}
	return r
}

// solveQuadratic returns a z with z^2 + z = beta, or false when there is none.
// For odd m the half-trace is a solution whenever one exists.
func (f refField) solveQuadratic(beta *big.Int) (*big.Int, bool) {
	z := new(big.Int)
	t := beta
	for range (f.m + 1) / 2 {
		z = f.add(z, t)
		t = f.sqr(f.sqr(t))
	}
	return z, f.add(f.sqr(z), z).Cmp(beta) == 0
}
