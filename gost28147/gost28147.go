// Package gost28147 implements the GOST 28147-89 block cipher with the S-box
// tables used in Ukraine (ДКЕ, «довгостроковий ключовий елемент») and its
// modes: simple replacement (the cipher.Block itself), gamma mode ([NewCTR]),
// cipher feedback and the MAC ([NewMAC]). The cipher feedback of GOST 28147-89
// is the CFB of crypto/cipher over the block.
//
// The block cipher is a port of GOST28147Engine from Bouncy Castle and
// produces the same output for the same key and S-box; the modes and the
// tables of [DKE1Appendix] and [GOST34311ExampleSbox] follow the certified
// cryptonite library and reproduce the examples of its tests.
package gost28147

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

const (
	// BlockSize is the GOST 28147-89 block size in bytes.
	BlockSize = 8
	// KeySize is the GOST 28147-89 key size in bytes.
	KeySize = 32
)

// Sbox is a GOST 28147-89 substitution table. Row i replaces the i-th 4-bit
// nibble of the round function input, counting from the least significant
// one; every value is in the range 0..15.
type Sbox [8][16]byte

// dke1 is ДКЕ №1, the default DKE of DSTU 4145-2002 in its packed 64-byte form
// (DSTU4145Params.getDefaultDKE in Bouncy Castle).
var dke1 = [64]byte{
	0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82,
	0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e, 0xad,
	0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d,
	0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca, 0x4e, 0x17,
	0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a,
	0x28, 0x97, 0x5f, 0x0b, 0xc1, 0xde, 0xa3, 0x64,
	0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0,
	0x12, 0x3e, 0x6d, 0xb8, 0xfa, 0xc5, 0x79, 0x04,
}

// DKE1 returns ДКЕ №1, the default S-box of DSTU 4145-2002 and GOST 34.311-95.
func DKE1() Sbox { return unpack(dke1) }

// UnpackDKE converts a DKE in its packed 64-byte form, as it appears in
// DSTU 4145 key parameters, into an Sbox. Each byte holds two table entries,
// the high nibble first.
func UnpackDKE(dke []byte) (Sbox, error) {
	if len(dke) != len(dke1) {
		return Sbox{}, fmt.Errorf("gost28147: DKE is %d bytes, want %d", len(dke), len(dke1))
	}
	return unpack([64]byte(dke)), nil
}

// PackDKE converts s into the packed 64-byte form of UnpackDKE.
func PackDKE(s Sbox) []byte {
	dke := make([]byte, len(dke1))
	for i := range dke {
		dke[i] = s[i/8][2*(i%8)]<<4 | s[i/8][2*(i%8)+1]&0xf
	}
	return dke
}

func unpack(dke [64]byte) Sbox {
	var s Sbox
	for i, b := range dke {
		s[i/8][2*(i%8)] = b >> 4
		s[i/8][2*(i%8)+1] = b & 0xf
	}
	return s
}

// Subkey order for the 32 rounds: three forward passes and one backward pass
// to encrypt, the reverse to decrypt.
var (
	encryptOrder = [32]uint8{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0}
	decryptOrder = [32]uint8{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0}
)

type gostCipher struct {
	key       [8]uint32
	sbox      Sbox
	destroyed bool
}

// Destroy overwrites the key held by v, a cipher.Block from [NewCipher] or a
// MAC from [NewMAC], and the partial block a MAC holds; v panics on any use
// afterwards, and so do the modes built over a destroyed block. Copies the Go
// runtime made earlier (a moved stack) are beyond its reach. Destroy panics if
// v is anything else.
func Destroy(v any) {
	switch v := v.(type) {
	case *gostCipher:
		v.key = [8]uint32{}
		v.destroyed = true
	case *mac:
		Destroy(v.c)
		v.Reset()
	default:
		panic(fmt.Sprintf("gost28147: Destroy of %T", v))
	}
}

// live panics after Destroy, so that a destroyed key never encrypts as zeros.
func (c *gostCipher) live() {
	if c.destroyed {
		panic("gost28147: use of a destroyed key")
	}
}

// NewCipher returns a GOST 28147-89 cipher.Block for a 32-byte key and an
// S-box. The key is read as eight little-endian 32-bit subkeys, as in
// Bouncy Castle.
func NewCipher(key []byte, sbox Sbox) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("gost28147: key is %d bytes, want %d", len(key), KeySize)
	}
	for _, row := range sbox {
		for _, v := range row {
			if v > 0xf {
				return nil, errors.New("gost28147: S-box value exceeds 4 bits")
			}
		}
	}
	c := &gostCipher{sbox: sbox}
	for i := range c.key {
		c.key[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	return c, nil
}

func (c *gostCipher) BlockSize() int { return BlockSize }

func (c *gostCipher) Encrypt(dst, src []byte) { c.crypt(dst, src, &encryptOrder) }

func (c *gostCipher) Decrypt(dst, src []byte) { c.crypt(dst, src, &decryptOrder) }

func (c *gostCipher) crypt(dst, src []byte, order *[32]uint8) {
	c.live()
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("gost28147: input or output not a full block")
	}
	n1 := binary.LittleEndian.Uint32(src)
	n2 := binary.LittleEndian.Uint32(src[4:])
	for _, k := range order[:31] {
		n1, n2 = n2^c.round(n1, c.key[k]), n1
	}
	n2 ^= c.round(n1, c.key[order[31]])
	binary.LittleEndian.PutUint32(dst, n1)
	binary.LittleEndian.PutUint32(dst[4:], n2)
}

// lookup16 returns row[x] for x < 16 by reading all 16 entries, so that neither
// the branches nor the memory accesses depend on x.
func lookup16(row *[16]byte, x uint32) uint32 {
	var r uint32
	for i, v := range row {
		r |= uint32(v) & -uint32(subtle.ConstantTimeEq(int32(i), int32(x))) //nolint:gosec // G115: i and x are below 16
	}
	return r
}

// round is the GOST round function: add the subkey, substitute each nibble, rotate left by 11.
func (c *gostCipher) round(n, subkey uint32) uint32 {
	sum := n + subkey
	var out uint32
	for i := range 8 {
		out |= lookup16(&c.sbox[i], sum>>(4*i)&0xf) << (4 * i)
	}
	return bits.RotateLeft32(out, 11)
}
