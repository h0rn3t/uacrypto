package dstu4145

import (
	"encoding/binary"
	"math/big"
	"math/bits"
	"slices"
)

// felem is an element of GF(2^m) in polynomial basis: bit i of the
// little-endian limbs is the coefficient of x^i. Seven limbs hold m ≤ 448;
// a reduced element is below 2^m.
type felem [7]uint64

// field is GF(2^m) with the reduction polynomial x^m + Σ x^k + 1. add, mul,
// sqr and inv neither branch nor index on element values: their loops depend
// only on m and ks, which are public.
type field struct {
	m  int
	ks []int // middle exponents, ascending
}

func newField(m int, ks ...int) field {
	ks = slices.Sorted(slices.Values(ks))
	for _, k := range ks {
		// reduce shifts by k within a limb and folds twice, enough while 2k ≤ m
		if k <= 0 || k >= 64 || 2*k > m {
			panic("dstu4145: unsupported reduction polynomial")
		}
	}
	return field{m: m, ks: ks}
}

func feFromBig(x *big.Int) felem {
	var buf [8 * len(felem{})]byte
	x.FillBytes(buf[:])
	var a felem
	for i := range a {
		a[i] = binary.BigEndian.Uint64(buf[len(buf)-8*(i+1):])
	}
	return a
}

func (a felem) big() *big.Int {
	var buf [8 * len(felem{})]byte
	for i, w := range a {
		binary.BigEndian.PutUint64(buf[len(buf)-8*(i+1):], w)
	}
	return new(big.Int).SetBytes(buf[:])
}

func (a felem) isZero() bool {
	var acc uint64
	for _, w := range a {
		acc |= w
	}
	return acc == 0
}

func (a felem) equal(b felem) bool {
	var acc uint64
	for i := range a {
		acc |= a[i] ^ b[i]
	}
	return acc == 0
}

func (f *field) add(a, b felem) felem {
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

// mul is schoolbook multiplication of the limbs in use, then reduction.
func (f *field) mul(a, b felem) felem {
	n := (f.m + 63) / 64
	var t [2 * len(felem{})]uint64
	for i := range n {
		for j := range n {
			hi, lo := clmul(a[i], b[j])
			t[i+j] ^= lo
			t[i+j+1] ^= hi
		}
	}
	return f.reduce(t)
}

// clmul is the carry-less product of a and b, adding a shifted copy of a
// under the mask of each bit of b.
func clmul(a, b uint64) (hi, lo uint64) {
	for i := range 64 {
		mask := -(b >> i & 1)
		lo ^= (a << i) & mask
		hi ^= (a >> (64 - i)) & mask // a >> 64 is 0 for i = 0
	}
	return hi, lo
}

// sqr spreads the bits of a apart: squaring in GF(2)[x] is x^i -> x^2i.
func (f *field) sqr(a felem) felem {
	var t [2 * len(felem{})]uint64
	for i := range (f.m + 63) / 64 {
		t[2*i] = spread(a[i])
		t[2*i+1] = spread(a[i] >> 32)
	}
	return f.reduce(t)
}

// spread moves bit i of the low half of x to bit 2i.
func spread(x uint64) uint64 {
	v := x & 0xffffffff
	v = (v | v<<16) & 0x0000ffff0000ffff
	v = (v | v<<8) & 0x00ff00ff00ff00ff
	v = (v | v<<4) & 0x0f0f0f0f0f0f0f0f
	v = (v | v<<2) & 0x3333333333333333
	v = (v | v<<1) & 0x5555555555555555
	return v
}

// reduce folds t below x^m. As x^m = 1 + Σ x^k, the part h of t from bit m
// up adds h·(1 + Σ x^k) to the low m bits. The first pass leaves fewer than
// m + max(k) bits, the second fewer than m because 2·max(k) ≤ m.
func (f *field) reduce(t [2 * len(felem{})]uint64) felem {
	w, b := f.m/64, uint(f.m%64)
	for range 2 {
		var h [len(t)]uint64
		for i := range len(t) - w {
			h[i] = t[i+w] >> b
			if i+w+1 < len(t) {
				h[i] |= t[i+w+1] << (64 - b) // 0 when b = 0
			}
		}
		t[w] &= 1<<b - 1
		clear(t[w+1:])
		for i := range t {
			t[i] ^= h[i]
		}
		for _, k := range f.ks {
			var carry uint64
			for i := range t {
				t[i] ^= h[i]<<k | carry
				carry = h[i] >> (64 - k)
			}
		}
	}
	return felem(t[:len(felem{})])
}

// inv is a^(2^m-2), which is 1/a for a ≠ 0 and 0 for a = 0, computed by
// Itoh–Tsujii: b_j = a^(2^j-1) gives b_(i+j) = b_i^(2^j)·b_j, built up along
// the bits of m-1.
func (f *field) inv(a felem) felem {
	e := uint(f.m - 1)
	b, j := a, 1
	for i := bits.Len(e) - 2; i >= 0; i-- {
		t := b
		for range j {
			t = f.sqr(t)
		}
		b, j = f.mul(t, b), 2*j
		if e>>i&1 == 1 {
			b, j = f.mul(f.sqr(b), a), j+1
		}
	}
	return f.sqr(b)
}

// trace is Tr(a) = a + a^2 + ... + a^(2^(m-1)), which is 0 or 1.
func (f *field) trace(a felem) uint64 {
	t := a
	for range f.m - 1 {
		t = f.add(f.sqr(t), a)
	}
	return t[0] & 1
}

// sqrt is a^(2^(m-1)), the unique square root in GF(2^m).
func (f *field) sqrt(a felem) felem {
	for range f.m - 1 {
		a = f.sqr(a)
	}
	return a
}

// solveQuadratic returns a z with z^2 + z = beta, or false when there is none.
// For odd m the half-trace is a solution whenever one exists.
func (f *field) solveQuadratic(beta felem) (felem, bool) {
	var z felem
	t := beta
	for range (f.m + 1) / 2 {
		z = f.add(z, t)
		t = f.sqr(f.sqr(t))
	}
	return z, f.add(f.sqr(z), z).equal(beta)
}
