package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// GCM is DSTU 7624 GCM over a 16-, 32- or 64-byte block cipher. The nonce
// must be exactly one block. A partial final block of the additional data or
// the ciphertext is zero-padded inside GHASH; the standard has no example of
// one.
type GCM struct {
	block     cipher.Block
	h         []uint64
	reduction uint64
	tagSize   int
	bindNonce bool
}

// NewGCM returns GCM as DSTU 7624 defines it and as its examples, the
// certified cryptonite library and Bouncy Castle KGCMBlockCipher compute it,
// with a tag of tagSize bytes, 8 through the block size. block is already
// keyed.
//
// The standard leaves the nonce out of the tag: a tag still verifies under a
// different nonce, which only garbles the plaintext, and a message with no
// plaintext has the same tag under every nonce. Systems that talk only to
// themselves can use [NewGCMWithNonceAuth] instead.
func NewGCM(block cipher.Block, tagSize int) (*GCM, error) {
	return newGCM(block, tagSize, false)
}

// NewGCMWithNonceAuth returns GCM that also authenticates the nonce, as the
// first block of the additional data: its output is that of [NewGCM] given
// nonce || additionalData. It does not interoperate with DSTU 7624 GCM.
func NewGCMWithNonceAuth(block cipher.Block, tagSize int) (*GCM, error) {
	return newGCM(block, tagSize, true)
}

func newGCM(block cipher.Block, tagSize int, bindNonce bool) (*GCM, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if tagSize < 8 || tagSize > n {
		return nil, fmt.Errorf("kalyna: GCM tag size %d, want 8..%d", tagSize, n)
	}
	zero := make([]byte, n)
	block.Encrypt(zero, zero)
	h := wordsLE(zero)
	clear(zero)
	return &GCM{block: block, h: h, reduction: reductionPolynomial(n), tagSize: tagSize, bindNonce: bindNonce}, nil
}

// Seal encrypts plaintext and appends the tag. additionalData is
// authenticated and is not encrypted.
func (g *GCM) Seal(nonce, plaintext, additionalData []byte) ([]byte, error) {
	n := g.block.BlockSize()
	if err := nonceLen(len(nonce), n); err != nil {
		return nil, err
	}
	if err := fitsUint32(len(plaintext)); err != nil {
		return nil, err
	}
	if err := fitsUint32(len(additionalData)); err != nil {
		return nil, err
	}
	gamma := g.keystream(nonce)
	body := make([]byte, len(plaintext))
	gamma.XORKeyStream(body, plaintext)
	gamma.wipe()
	tag := g.tag(nonce, additionalData, body)
	out := make([]byte, len(body)+g.tagSize)
	copy(out, body)
	copy(out[len(body):], tag[:g.tagSize])
	clear(tag)
	return out, nil
}

// Open checks the tag of ciphertext and returns the plaintext.
// A mismatch returns ErrAuthentication and a nil plaintext; the plaintext is
// not produced until the tag matches.
func (g *GCM) Open(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	n := g.block.BlockSize()
	if err := nonceLen(len(nonce), n); err != nil {
		return nil, err
	}
	if len(ciphertext) < g.tagSize {
		return nil, ErrAuthentication
	}
	bodyLen := len(ciphertext) - g.tagSize
	if err := fitsUint32(bodyLen); err != nil {
		return nil, err
	}
	if err := fitsUint32(len(additionalData)); err != nil {
		return nil, err
	}
	body := ciphertext[:bodyLen]
	want := g.tag(nonce, additionalData, body)
	match := subtle.ConstantTimeCompare(want[:g.tagSize], ciphertext[bodyLen:])
	clear(want)
	if match != 1 {
		return nil, ErrAuthentication
	}
	gamma := g.keystream(nonce)
	plain := make([]byte, bodyLen)
	gamma.XORKeyStream(plain, body)
	gamma.wipe()
	return plain, nil
}

// keystream is the counter keystream from E(nonce).
func (g *GCM) keystream(nonce []byte) *ctr {
	counter := make([]byte, len(nonce))
	g.block.Encrypt(counter, nonce)
	return newCounter(g.block, counter)
}

// tag is E(GHASH(additionalData, ciphertext) ⊕ lengths): the bit length of
// the additional data in the low word, of the ciphertext in the middle one.
// With bindNonce the nonce is the first block of the additional data.
func (g *GCM) tag(nonce, additionalData, ciphertext []byte) []byte {
	acc := make([]uint64, g.block.BlockSize()/8)
	aadLen := uint64(len(additionalData))
	// On Apple M-series cores GHASH over all-zero data runs measurably
	// faster than over random data (internal/ctcheck); the flag removes it.
	subtle.WithDataIndependentTiming(func() {
		if g.bindNonce {
			g.absorb(acc, nonce)
			aadLen += uint64(len(nonce))
		}
		g.absorb(acc, additionalData)
		g.absorb(acc, ciphertext)
	})
	acc[0] ^= aadLen << 3
	acc[len(acc)/2] ^= uint64(len32(len(ciphertext))) << 3
	buf := make([]byte, g.block.BlockSize())
	putWordsLE(buf, acc)
	clear(acc)
	g.block.Encrypt(buf, buf)
	return buf
}

func (g *GCM) absorb(acc []uint64, data []byte) {
	n := g.block.BlockSize()
	block := make([]byte, n)
	for off := 0; off < len(data); off += n {
		end := min(off+n, len(data))
		clear(block)
		copy(block, data[off:end])
		for i := range acc {
			acc[i] ^= binary.LittleEndian.Uint64(block[i*8:])
		}
		copy(acc, multiply(acc, g.h, g.reduction))
	}
	clear(block)
}
