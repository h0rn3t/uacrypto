// Package gost34311 implements the GOST 34.311-95 hash function, the
// Ukrainian adoption of GOST R 34.11-94, with ДКЕ №1 as the default S-box.
//
// The implementation is a port of GOST3411Digest from Bouncy Castle and
// produces the same digests as Bouncy Castle and the IIT library, and the
// examples of the standard with their own S-box. HMAC with GOST 34.311 is the
// HMAC of crypto/hmac over New.
package gost34311

import (
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/h0rn3t/uacrypto/gost28147"
)

const (
	// Size is the size of a GOST 34.311-95 digest in bytes.
	Size = 32
	// BlockSize is the block size of GOST 34.311-95 in bytes.
	BlockSize = 32
)

type digest struct {
	sbox gost28147.Sbox
	h    [32]byte // chaining value
	sum  [32]byte // control sum of all blocks, a 256-bit little-endian integer
	buf  [BlockSize]byte
	nbuf int
	n    uint64 // message length in bytes
}

// New returns a GOST 34.311-95 hash.Hash with ДКЕ №1.
func New() hash.Hash { return &digest{sbox: gost28147.DKE1()} }

// NewWithSbox returns a GOST 34.311-95 hash.Hash with the given S-box. It
// fails when the S-box is not a valid GOST 28147-89 table.
func NewWithSbox(sbox gost28147.Sbox) (hash.Hash, error) {
	if _, err := gost28147.NewCipher(make([]byte, gost28147.KeySize), sbox); err != nil {
		return nil, fmt.Errorf("gost34311: %w", err)
	}
	return &digest{sbox: sbox}, nil
}

// Sum returns the GOST 34.311-95 digest of data with ДКЕ №1.
func Sum(data []byte) [Size]byte {
	d := digest{sbox: gost28147.DKE1()}
	_, _ = d.Write(data) // never returns an error
	return d.checkSum()
}

func (d *digest) Size() int      { return Size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() { *d = digest{sbox: d.sbox} }

func (d *digest) Write(p []byte) (int, error) {
	written := len(p)
	d.n += uint64(len(p))
	if d.nbuf > 0 {
		k := copy(d.buf[d.nbuf:], p)
		d.nbuf += k
		p = p[k:]
		if d.nbuf < BlockSize {
			return written, nil
		}
		d.block(&d.buf)
		d.nbuf = 0
	}
	for len(p) >= BlockSize {
		d.block((*[BlockSize]byte)(p))
		p = p[BlockSize:]
	}
	d.nbuf = copy(d.buf[:], p)
	return written, nil
}

func (d *digest) Sum(b []byte) []byte {
	final := *d
	sum := final.checkSum()
	final = digest{} // the copy holds the buffered input, a password under PBKDF2
	return append(b, sum[:]...)
}

// checkSum finishes the digest: the last block padded with zeros, then the
// bit length and the control sum go through the compression function.
func (d *digest) checkSum() [Size]byte {
	bitLen := d.n * 8
	if d.nbuf > 0 {
		clear(d.buf[d.nbuf:])
		d.block(&d.buf)
	}
	var length [32]byte
	binary.LittleEndian.PutUint64(length[:], bitLen)
	d.compress(&length)
	sum := d.sum
	d.compress(&sum)
	clear(sum[:])
	return d.h
}

// block adds a message block to the control sum and compresses it.
func (d *digest) block(m *[BlockSize]byte) {
	var carry uint16
	for i := range d.sum {
		s := uint16(d.sum[i]) + uint16(m[i]) + carry
		d.sum[i] = byte(s & 0xff)
		carry = s >> 8
	}
	d.compress(m)
}

// c2 is the only non-zero key generation constant (C[2] in Bouncy Castle;
// C[1] and C[3] are zero), applied before the third encryption key.
var c2 = [32]byte{
	0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
	0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
	0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF,
	0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF,
}

// compress is the step hash function: four GOST 28147-89 encryptions of the
// chaining value under keys derived from it and the block, then the ψ mixing.
func (d *digest) compress(m *[32]byte) {
	var s [32]byte
	u, v := d.h, *m
	for i := range 4 {
		if i > 0 {
			u = a(u)
			if i == 2 {
				for j := range u {
					u[j] ^= c2[j]
				}
			}
			v = a(a(v))
		}
		var w [32]byte
		for j := range w {
			w[j] = u[j] ^ v[j]
		}
		key := p(w)
		block, err := gost28147.NewCipher(key[:], d.sbox)
		if err != nil {
			panic(err) // the S-box was checked by the constructor and the key is 32 bytes
		}
		block.Encrypt(s[8*i:], d.h[8*i:])
		// The keys come from the message, a password under PBKDF2.
		gost28147.Destroy(block)
		clear(key[:])
		clear(w[:])
	}
	clear(u[:])
	clear(v[:])
	for range 12 {
		s = psi(s)
	}
	for j := range s {
		s[j] ^= m[j]
	}
	s = psi(s)
	for j := range s {
		s[j] ^= d.h[j]
	}
	for range 61 {
		s = psi(s)
	}
	d.h = s
}

// p is the byte permutation φ that turns W into an encryption key.
func p(w [32]byte) [32]byte {
	var k [32]byte
	for i := range 8 {
		for r := range 4 {
			k[4*i+r] = w[8*r+i]
		}
	}
	return k
}

// a shifts the four 64-bit words left by one and appends the XOR of the first two.
func a(x [32]byte) [32]byte {
	var y [32]byte
	copy(y[:], x[8:])
	for j := range 8 {
		y[24+j] = x[j] ^ x[8+j]
	}
	return y
}

// psi is the linear feedback shift ψ over sixteen little-endian 16-bit words.
func psi(x [32]byte) [32]byte {
	word := func(i int) uint16 { return binary.LittleEndian.Uint16(x[2*i:]) }
	var y [32]byte
	copy(y[:], x[2:])
	binary.LittleEndian.PutUint16(y[30:], word(0)^word(1)^word(2)^word(3)^word(12)^word(15))
	return y
}
