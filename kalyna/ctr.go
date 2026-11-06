package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// NewCTR returns DSTU 7624 counter mode ("гамування") under iv, which is one
// block long. The counter starts at E(iv) and is incremented, little-endian,
// before each keystream block. A partial block uses the leading bytes of its
// keystream block, and the next XORKeyStream continues with the rest, so a
// message may be split anywhere. The same call decrypts.
func NewCTR(block cipher.Block, iv []byte) (cipher.Stream, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != n {
		return nil, fmt.Errorf("kalyna: CTR IV length %d, want %d", len(iv), n)
	}
	counter := make([]byte, n)
	block.Encrypt(counter, iv)
	return newCounter(block, counter), nil
}

// ctr is the DSTU 7624 counter keystream. CCM and GCM start it from their
// own encrypted nonce block.
type ctr struct {
	block   cipher.Block
	counter []byte
	gamma   []byte
	used    int // bytes of gamma already spent
}

// newCounter takes ownership of counter, the block before the first increment.
func newCounter(block cipher.Block, counter []byte) *ctr {
	return &ctr{block: block, counter: counter, gamma: make([]byte, len(counter)), used: len(counter)}
}

// XORKeyStream XORs src with the keystream into dst, which may be src itself.
func (c *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("kalyna: CTR output smaller than input")
	}
	for len(src) > 0 {
		if c.used == len(c.gamma) {
			incrementLE(c.counter)
			c.block.Encrypt(c.gamma, c.counter)
			c.used = 0
		}
		n := subtle.XORBytes(dst, src, c.gamma[c.used:])
		c.used += n
		dst, src = dst[n:], src[n:]
	}
}

// wipe clears the counter and the unspent keystream.
func (c *ctr) wipe() {
	clear(c.counter)
	clear(c.gamma)
}
