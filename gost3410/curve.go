package gost3410

import (
	"errors"
	"math/big"
)

// CurveParams are the parameters of a curve y² = x³ + ax + b over GF(p)
// with a base point (X, Y) of prime order Q, in the order cryptonite's
// gost3410_alloc_with_params takes them.
type CurveParams struct {
	P, A, B, Q, X, Y *big.Int
}

// A Curve is a curve with a base point of prime order q, both p and q below
// 2^256. Curves are immutable and safe for concurrent use.
type Curve struct {
	p, q  modulus
	a, b  nat // Montgomery form
	b3    nat // 3b, Montgomery form
	g     point
	order *big.Int
}

// point is a projective point (X:Y:Z) with coordinates in Montgomery form;
// Z = 0 is the point at infinity.
type point struct{ x, y, z nat }

// NewCurve checks params and returns the curve. P and Q must be primes below
// 2^256, A and B must define a non-singular curve, and the base point must
// lie on it with order Q.
func NewCurve(params CurveParams) (*Curve, error) {
	p, q := params.P, params.Q
	for _, v := range []*big.Int{p, params.A, params.B, q, params.X, params.Y} {
		if v == nil || v.Sign() < 0 {
			return nil, errors.New("gost3410: curve parameter missing or negative")
		}
	}
	if p.BitLen() > 256 || q.BitLen() > 256 || p.Cmp(big.NewInt(3)) <= 0 || q.Cmp(big.NewInt(2)) <= 0 {
		return nil, errors.New("gost3410: p and q must be in (3, 2^256)")
	}
	if !p.ProbablyPrime(20) || !q.ProbablyPrime(20) {
		return nil, errors.New("gost3410: p or q is not prime")
	}
	for _, v := range []*big.Int{params.A, params.B, params.X, params.Y} {
		if v.Cmp(p) >= 0 {
			return nil, errors.New("gost3410: curve parameter outside the field")
		}
	}
	// 4a³ + 27b² ≠ 0 mod p
	disc := new(big.Int).Exp(params.A, big.NewInt(3), p)
	disc.Mul(disc, big.NewInt(4))
	disc.Add(disc, new(big.Int).Mul(big.NewInt(27), new(big.Int).Mul(params.B, params.B)))
	if disc.Mod(disc, p).Sign() == 0 {
		return nil, errors.New("gost3410: singular curve")
	}

	c := &Curve{p: newModulus(p), q: newModulus(q), order: new(big.Int).Set(q)}
	c.a = c.p.toMont(new(natFromBig(params.A)))
	c.b = c.p.toMont(new(natFromBig(params.B)))
	c.b3 = c.p.add(&c.b, &c.b)
	c.b3 = c.p.add(&c.b3, &c.b)
	g, ok := c.affinePoint(params.X, params.Y)
	if !ok {
		return nil, errors.New("gost3410: base point is not on the curve")
	}
	if inf := c.scalarMult(&g, &c.q.m); !inf.z.isZero() {
		return nil, errors.New("gost3410: base point order is not q")
	}
	c.g = g
	return c, nil
}

// Order returns a copy of q, the order of the base point.
func (c *Curve) Order() *big.Int { return new(big.Int).Set(c.order) }

// affinePoint returns (x, y) for x and y below p, reporting whether it lies
// on the curve.
func (c *Curve) affinePoint(x, y *big.Int) (point, bool) {
	f := &c.p
	pt := point{x: f.toMont(new(natFromBig(x))), y: f.toMont(new(natFromBig(y))), z: f.one}
	// y² = (x² + a)·x + b
	lhs := f.montMul(&pt.y, &pt.y)
	rhs := f.montMul(&pt.x, &pt.x)
	rhs = f.add(&rhs, &c.a)
	rhs = f.montMul(&rhs, &pt.x)
	rhs = f.add(&rhs, &c.b)
	return pt, lhs == rhs
}

// affine returns the coordinates of a finite point in the ordinary domain.
func (c *Curve) affine(pt *point) (x, y nat) {
	f := &c.p
	zInv := f.inv(&pt.z)
	x = f.montMul(&pt.x, &zInv)
	y = f.montMul(&pt.y, &zInv)
	return f.fromMont(&x), f.fromMont(&y)
}

// add returns p1 + p2 by the complete formulas for any a of Renes, Costello
// and Batina, "Complete addition formulas for prime order elliptic curves",
// 2016, algorithm 1: they hold for doubling and the point at infinity too,
// so they take the same steps for every input in a group of odd order.
func (c *Curve) add(p1, p2 *point) point {
	f := &c.p
	x1, y1, z1 := &p1.x, &p1.y, &p1.z
	x2, y2, z2 := &p2.x, &p2.y, &p2.z

	t0 := f.montMul(x1, x2)
	t1 := f.montMul(y1, y2)
	t2 := f.montMul(z1, z2)
	t3 := f.add(x1, y1)
	t4 := f.add(x2, y2)
	t3 = f.montMul(&t3, &t4)
	t4 = f.add(&t0, &t1)
	t3 = f.sub(&t3, &t4)
	t4 = f.add(x1, z1)
	t5 := f.add(x2, z2)
	t4 = f.montMul(&t4, &t5)
	t5 = f.add(&t0, &t2)
	t4 = f.sub(&t4, &t5)
	t5 = f.add(y1, z1)
	x3 := f.add(y2, z2)
	t5 = f.montMul(&t5, &x3)
	x3 = f.add(&t1, &t2)
	t5 = f.sub(&t5, &x3)
	z3 := f.montMul(&c.a, &t4)
	x3 = f.montMul(&c.b3, &t2)
	z3 = f.add(&x3, &z3)
	x3 = f.sub(&t1, &z3)
	z3 = f.add(&t1, &z3)
	y3 := f.montMul(&x3, &z3)
	t1 = f.add(&t0, &t0)
	t1 = f.add(&t1, &t0)
	t2 = f.montMul(&c.a, &t2)
	t4 = f.montMul(&c.b3, &t4)
	t1 = f.add(&t1, &t2)
	t2 = f.sub(&t0, &t2)
	t2 = f.montMul(&c.a, &t2)
	t4 = f.add(&t4, &t2)
	t2 = f.montMul(&t1, &t4)
	y3 = f.add(&y3, &t2)
	t2 = f.montMul(&t5, &t4)
	x3 = f.montMul(&t3, &x3)
	x3 = f.sub(&x3, &t2)
	t2 = f.montMul(&t3, &t1)
	z3 = f.montMul(&t5, &z3)
	z3 = f.add(&z3, &t2)
	return point{x: x3, y: y3, z: z3}
}

// scalarMult returns k·pt by double-and-add-always over the bit length of q:
// the steps and memory accesses do not depend on k.
func (c *Curve) scalarMult(pt *point, k *nat) point {
	r := point{y: c.p.one} // the point at infinity
	for i := c.q.bits - 1; i >= 0; i-- {
		r = c.add(&r, &r)
		sum := c.add(&r, pt)
		b := k.bit(i)
		r = point{x: selectNat(b, &sum.x, &r.x), y: selectNat(b, &sum.y, &r.y), z: selectNat(b, &sum.z, &r.z)}
	}
	return r
}
