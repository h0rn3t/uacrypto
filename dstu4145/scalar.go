package dstu4145

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"
)

// scalar is an integer modulo the order n of a curve in little-endian limbs.
// The order methods neither branch nor index on scalar values: their loops
// depend only on the bit length of n, which is public.
type scalar [7]uint64

// order is the order n of a curve with its Montgomery constants for
// R = 2^(64·l), where l is the number of limbs n occupies.
type order struct {
	n     scalar
	nbits int
	n0inv uint64 // -n⁻¹ mod 2^64
	rr    scalar // R² mod n
}

func newOrder(n *big.Int) order {
	one := big.NewInt(1)
	r := new(big.Int).Lsh(one, uint(64*((n.BitLen()+63)/64)))
	inv := new(big.Int).ModInverse(n, new(big.Int).Lsh(one, 64))
	return order{
		n:     scalarFromBig(n),
		nbits: n.BitLen(),
		n0inv: -inv.Uint64(),
		rr:    scalarFromBig(r.Mul(r, r).Mod(r, n)),
	}
}

// scalarFromBig and big convert public values (r, s) and test operands.
func scalarFromBig(x *big.Int) scalar { return scalar(feFromBig(x)) }

func (k *scalar) big() *big.Int { return felem(*k).big() }

func (o *order) limbs() int { return (o.nbits + 63) / 64 }

func (o *order) isZero(k *scalar) bool { return felem(*k).isZero() }

// fromBytes reads a big-endian integer of any length; ok reports whether it
// is in [1, n-1].
func (o *order) fromBytes(be []byte) (k scalar, ok bool) {
	size := (o.nbits + 7) / 8
	var extra byte // bytes above the byte length of n must be zero
	if len(be) > size {
		for _, b := range be[:len(be)-size] {
			extra |= b
		}
		be = be[len(be)-size:]
	}
	var buf [8 * len(scalar{})]byte
	copy(buf[len(buf)-len(be):], be)
	for i := range k {
		k[i] = binary.BigEndian.Uint64(buf[len(buf)-8*(i+1):])
	}

	var acc, borrow uint64
	for i := range k {
		acc |= k[i]
		_, borrow = bits.Sub64(k[i], o.n[i], borrow) // borrows out iff k < n
	}
	nonzero := (acc | -acc) >> 63
	return k, nonzero&borrow == 1 && extra == 0
}

// bytes returns k big-endian, padded to the byte length of n.
func (o *order) bytes(k *scalar) []byte {
	var buf [8 * len(scalar{})]byte
	for i, w := range k {
		binary.BigEndian.PutUint64(buf[len(buf)-8*(i+1):], w)
	}
	return buf[len(buf)-(o.nbits+7)/8:]
}

// mulAdd returns (r·d + e) mod n for r, d, e below n.
func (o *order) mulAdd(r, d, e *scalar) scalar {
	x := o.montMul(r, d)     // r·d·R⁻¹
	x = o.montMul(&x, &o.rr) // r·d
	var carry uint64
	for i := range o.limbs() {
		x[i], carry = bits.Add64(x[i], e[i], carry)
	}
	return o.subtractN(&x, carry)
}

// montMul returns a·b·R⁻¹ mod n for a, b below n: coarsely integrated
// operand scanning, each step adding a·b[i] and the multiple of n that
// clears the lowest limb, then shifting a limb out.
func (o *order) montMul(a, b *scalar) scalar {
	l := o.limbs()
	var t [len(scalar{}) + 1]uint64 // t[l] is the top word; t stays below 2n
	for i := range l {
		var carry uint64
		for j := range l {
			t[j], carry = mulAddAdd(a[j], b[i], t[j], carry)
		}
		top, topCarry := bits.Add64(t[l], carry, 0)

		m := t[0] * o.n0inv
		_, carry = mulAddAdd(m, o.n[0], t[0], 0)
		for j := 1; j < l; j++ {
			t[j-1], carry = mulAddAdd(m, o.n[j], t[j], carry)
		}
		var c uint64
		t[l-1], c = bits.Add64(top, carry, 0) //nolint:gosec // G602: l ≥ 3, every order has over 160 bits
		t[l] = topCarry + c
	}
	hi := t[l]
	t[l] = 0
	return o.subtractN((*scalar)(t[:len(scalar{})]), hi)
}

// mulAddAdd returns x·y + a + b as a low limb and a carry limb; it cannot
// overflow 128 bits.
func mulAddAdd(x, y, a, b uint64) (lo, hi uint64) {
	hi, lo = bits.Mul64(x, y)
	var c uint64
	lo, c = bits.Add64(lo, a, 0)
	hi += c
	lo, c = bits.Add64(lo, b, 0)
	return lo, hi + c
}

// subtractN returns t + hi·R reduced by n once, for a value below 2n: the
// difference is kept by a mask when the subtraction does not borrow.
func (o *order) subtractN(t *scalar, hi uint64) scalar {
	var d scalar
	var borrow uint64
	for i := range o.limbs() {
		d[i], borrow = bits.Sub64(t[i], o.n[i], borrow)
	}
	_, borrow = bits.Sub64(hi, 0, borrow)
	keep := borrow - 1 // all ones when t + hi·R ≥ n
	for i := range d {
		d[i] = d[i]&keep | t[i]&^keep
	}
	return d
}

// fixedLength returns k + n or k + 2n for k below n, whichever has bit nbits
// set: either is k modulo n, and a ladder over it runs the same number of
// steps for every k. k + n < 2^nbits implies k + 2n < 2^(nbits+1), so the
// result fits in nbits + 1 ≤ 448 bits.
func (o *order) fixedLength(k *scalar) scalar {
	var t scalar
	var carry uint64
	for i := range t {
		t[i], carry = bits.Add64(k[i], o.n[i], carry)
	}
	addN := (t[o.nbits/64]>>(o.nbits%64))&1 - 1 // all ones when bit nbits is 0
	carry = 0
	for i := range t {
		t[i], carry = bits.Add64(t[i], o.n[i]&addN, carry)
	}
	return t
}

// randomScalar draws an integer uniformly from [1, n-1] by rejection: the
// number of attempts does not depend on the accepted value.
func randomScalar(c *Curve, random io.Reader) (scalar, error) {
	o := &c.ord
	buf := make([]byte, (o.nbits+7)/8)
	for {
		if _, err := io.ReadFull(random, buf); err != nil {
			return scalar{}, fmt.Errorf("dstu4145: read random: %w", err)
		}
		buf[0] &= 0xff >> (8*len(buf) - o.nbits)
		if k, ok := o.fromBytes(buf); ok {
			return k, nil
		}
	}
}
