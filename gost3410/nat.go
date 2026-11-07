package gost3410

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

// nat is an integer below 2^256 in little-endian limbs.
type nat [4]uint64

// modulus is an odd modulus m below 2^256 with its Montgomery constants for
// R = 2^256. Its methods take operands below m, return results below m, and
// neither branch nor index on operand values.
type modulus struct {
	m     nat
	bits  int
	m0inv uint64 // -m⁻¹ mod 2^64
	rr    nat    // R² mod m
	one   nat    // R mod m, 1 in Montgomery form
}

func newModulus(m *big.Int) modulus {
	one := big.NewInt(1)
	r := new(big.Int).Lsh(one, 256)
	inv := new(big.Int).ModInverse(m, new(big.Int).Lsh(one, 64))
	return modulus{
		m:     natFromBig(m),
		bits:  m.BitLen(),
		m0inv: -inv.Uint64(),
		rr:    natFromBig(new(big.Int).Mod(new(big.Int).Mul(r, r), m)),
		one:   natFromBig(new(big.Int).Mod(r, m)),
	}
}

// natFromBig converts a public value or a test operand below 2^256.
func natFromBig(x *big.Int) nat {
	var buf [32]byte
	x.FillBytes(buf[:])
	return natFromBE(&buf)
}

func natFromBE(buf *[32]byte) nat {
	var n nat
	for i := range n {
		n[i] = binary.BigEndian.Uint64(buf[32-8*(i+1):])
	}
	return n
}

func (x *nat) big() *big.Int {
	b := x.bytesBE()
	return new(big.Int).SetBytes(b[:])
}

func (x *nat) bytesBE() [32]byte {
	var buf [32]byte
	for i, w := range x {
		binary.BigEndian.PutUint64(buf[32-8*(i+1):], w)
	}
	return buf
}

func (x *nat) isZero() bool {
	return x[0]|x[1]|x[2]|x[3] == 0
}

func (x *nat) bit(i int) uint64 { return x[i/64] >> (i % 64) & 1 }

// selectNat returns a when c is 1 and b when c is 0.
func selectNat(c uint64, a, b *nat) nat {
	mask := -c
	var r nat
	for i := range r {
		r[i] = a[i]&mask | b[i]&^mask
	}
	return r
}

func (md *modulus) add(a, b *nat) nat {
	var s nat
	var carry uint64
	for i := range s {
		s[i], carry = bits.Add64(a[i], b[i], carry)
	}
	return md.reduceOnce(&s, carry)
}

func (md *modulus) sub(a, b *nat) nat {
	var d nat
	var borrow uint64
	for i := range d {
		d[i], borrow = bits.Sub64(a[i], b[i], borrow)
	}
	mask := -borrow // add m back when a < b
	var carry uint64
	for i := range d {
		d[i], carry = bits.Add64(d[i], md.m[i]&mask, carry)
	}
	return d
}

// reduceOnce returns t + hi·R reduced by m once, for a value below 2m.
func (md *modulus) reduceOnce(t *nat, hi uint64) nat {
	var d nat
	var borrow uint64
	for i := range d {
		d[i], borrow = bits.Sub64(t[i], md.m[i], borrow)
	}
	_, borrow = bits.Sub64(hi, 0, borrow)
	return selectNat(borrow, t, &d) // borrow: t + hi·R < m
}

// montMul returns a·b·R⁻¹ mod m for a below R and b below m: coarsely
// integrated operand scanning, each step adding a·b[i] and the multiple of m
// that clears the lowest limb, then shifting a limb out.
func (md *modulus) montMul(a, b *nat) nat {
	var t [5]uint64 // t[4] is the top word; t stays below 2m
	for i := range 4 {
		var carry uint64
		for j := range 4 {
			t[j], carry = mulAddAdd(a[j], b[i], t[j], carry)
		}
		top, topCarry := bits.Add64(t[4], carry, 0)

		q := t[0] * md.m0inv
		_, carry = mulAddAdd(q, md.m[0], t[0], 0)
		for j := 1; j < 4; j++ {
			t[j-1], carry = mulAddAdd(q, md.m[j], t[j], carry)
		}
		var c uint64
		t[3], c = bits.Add64(top, carry, 0)
		t[4] = topCarry + c
	}
	return md.reduceOnce((*nat)(t[:4]), t[4])
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

// toMont returns x·R mod m for any x below 2^256, so it also reduces x.
func (md *modulus) toMont(x *nat) nat { return md.montMul(x, &md.rr) }

func (md *modulus) fromMont(x *nat) nat { return md.montMul(x, &nat{1}) }

// mul returns a·b mod m for a and b in the ordinary domain.
func (md *modulus) mul(a, b *nat) nat {
	ab := md.montMul(a, b)
	return md.montMul(&ab, &md.rr)
}

// inv returns x⁻¹ in Montgomery form for x in Montgomery form, as x^(m-2):
// the exponent is public, so the steps do not depend on x. It needs a prime m.
func (md *modulus) inv(x *nat) nat {
	var e nat
	var borrow uint64
	e[0], borrow = bits.Sub64(md.m[0], 2, 0)
	for i := 1; i < 4; i++ {
		e[i], borrow = bits.Sub64(md.m[i], 0, borrow)
	}
	r := md.one
	for i := md.bits - 1; i >= 0; i-- {
		r = md.montMul(&r, &r)
		if e.bit(i) == 1 {
			r = md.montMul(&r, x)
		}
	}
	return r
}
