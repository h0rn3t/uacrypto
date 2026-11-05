package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// GCM is a nonce-authenticating profile of DSTU 7624 GCM over a 16-, 32- or
// 64-byte block cipher. The nonce must be exactly one block and is prepended
// to additionalData for authentication. For interoperability with Bouncy
// Castle KGCMBlockCipher, supply nonce || additionalData as its AAD.
// Tags differ from unmodified DSTU 7624 GCM. A partial final block is
// zero-padded inside GHASH.
type GCM struct {
	block     cipher.Block
	h         []uint64
	reduction uint64
	tagSize   int
}

// NewGCM returns GCM with a tag of tagSize bytes. tagSize is 8 through the
// block size. block is already keyed.
func NewGCM(block cipher.Block, tagSize int) (*GCM, error) {
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
	return &GCM{block: block, h: h, reduction: reductionPolynomial(n), tagSize: tagSize}, nil
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
	counter := g.counter(nonce)
	body := make([]byte, len(plaintext))
	xorGamma(g.block, counter, body, plaintext)
	clear(counter)
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
	counter := g.counter(nonce)
	plain := make([]byte, bodyLen)
	xorGamma(g.block, counter, plain, body)
	clear(counter)
	return plain, nil
}

func (g *GCM) counter(nonce []byte) []byte {
	n := g.block.BlockSize()
	iv := make([]byte, n)
	copy(iv[n-len(nonce):], nonce)
	g.block.Encrypt(iv, iv)
	return iv
}

// tag is E(GHASH) with the full-block nonce as the first block of AAD.
func (g *GCM) tag(nonce, additionalData, ciphertext []byte) []byte {
	acc := make([]uint64, g.block.BlockSize()/8)
	g.absorb(acc, nonce)
	g.absorb(acc, additionalData)
	g.absorb(acc, ciphertext)
	acc[0] ^= (uint64(len(nonce)) + uint64(len(additionalData))) << 3
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
