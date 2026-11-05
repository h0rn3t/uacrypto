package spn

import "testing"

func TestLookup(t *testing.T) {
	for i := range Sbox {
		for x := range 256 {
			if got, want := Lookup(&Sbox[i], byte(x)), Sbox[i][x]; got != want {
				t.Fatalf("Lookup(&Sbox[%d], %#02x) = %#02x, want %#02x", i, x, got, want)
			}
		}
	}
}

// refMul is the variable-time multiplication Mul replaced.
func refMul(a, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return p
}

func TestMul(t *testing.T) {
	for a := range 256 {
		for b := range 256 {
			if got, want := Mul(byte(a), byte(b)), refMul(byte(a), byte(b)); got != want {
				t.Fatalf("Mul(%#02x, %#02x) = %#02x, want %#02x", a, b, got, want)
			}
		}
	}
	if got := Mul(0x02, 0x80); got != 0x1d {
		t.Errorf("Mul(0x02, 0x80) = %#02x, want 0x1d", got)
	}
}
