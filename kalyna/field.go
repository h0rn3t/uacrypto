package kalyna

import (
	"encoding/binary"
	"slices"
)

// reductionPolynomial is the low part of the DSTU 7624 polynomial for a
// 16-, 32- or 64-byte block: x^128+x^7+x^2+x+1, x^256+x^10+x^5+x^2+1,
// x^512+x^8+x^5+x^2+1.
func reductionPolynomial(blockSize int) uint64 {
	switch blockSize {
	case 16:
		return 0x87
	case 32:
		return 0x425
	default:
		return 0x125
	}
}

// multiplyByX sets t to t·x. Bit i of the little-endian words is the
// coefficient of x^i; a carry out of the high word is reduced into word 0.
func multiplyByX(t []uint64, reduction uint64) {
	var carry uint64
	for i := range t {
		top := t[i] >> 63
		t[i] = (t[i] << 1) ^ carry
		carry = top
	}
	t[0] ^= reduction & -carry
}

// multiply returns a·b by Horner's rule from the top bit of b.
func multiply(a, b []uint64, reduction uint64) []uint64 {
	product := make([]uint64, len(a))
	for _, word := range slices.Backward(b) {
		for bit := 63; bit >= 0; bit-- {
			multiplyByX(product, reduction)
			mask := -((word >> uint(bit)) & 1)
			for j := range product {
				product[j] ^= a[j] & mask
			}
		}
	}
	return product
}

func wordsLE(block []byte) []uint64 {
	w := make([]uint64, len(block)/8)
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(block[i*8:])
	}
	return w
}

func putWordsLE(dst []byte, words []uint64) {
	for i, w := range words {
		binary.LittleEndian.PutUint64(dst[i*8:], w)
	}
}
