// Package strumok implements Strumok, the stream cipher of DSTU 8845:2019,
// with 256- and 512-bit keys.
//
// The standard works on 64-bit words; this package reads the key K0, K1, …
// and the IV IV0..IV3 as consecutive little-endian words and writes the
// keystream Z0, Z1, … as little-endian words, as C implementations on
// little-endian machines do. The word-level output matches the examples of
// annex D of the standard.
//
// The S-box lookups and multiplications in GF(2^8) read whole tables and
// take no secret-dependent branches, as in package kalyna.
package strumok

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/h0rn3t/uacrypto/internal/spn"
)

// Key and IV sizes in bytes.
const (
	KeySize256 = 32
	KeySize512 = 64
	IVSize     = 32
)

// The bytes by which the byte shifted out of a word is multiplied when the
// word is multiplied by α (alphaMul) or by α^-1 (alphaInvMul) in GF(2^64);
// they are the entries for 1 of the tables ALPHA_MUL and ALPHA_MUL_INV of
// @li0ard/strumok (see THIRD_PARTY_NOTICES.md), whose other entries are
// these bytes times the index in GF(2^8).
const (
	alphaMul    = 0xd73f04125e000004
	alphaInvMul = 0x47fcc6018a990000
)

// NewCipher returns the Strumok keystream for key, 32 or 64 bytes, and the
// 32-byte iv. A partial word of keystream is continued by the next
// XORKeyStream, so a message may be split anywhere. The same call decrypts.
func NewCipher(key, iv []byte) (cipher.Stream, error) {
	if len(key) != KeySize256 && len(key) != KeySize512 {
		return nil, fmt.Errorf("strumok: key is %d bytes, want %d or %d", len(key), KeySize256, KeySize512)
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("strumok: IV is %d bytes, want %d", len(iv), IVSize)
	}
	var k [8]uint64
	for i := range len(key) / 8 {
		k[i] = binary.LittleEndian.Uint64(key[8*i:])
	}
	var v [4]uint64
	for i := range v {
		v[i] = binary.LittleEndian.Uint64(iv[8*i:])
	}

	c := &stream{used: 8}
	if len(key) == KeySize256 {
		c.s = [16]uint64{
			k[3] ^ v[0], k[2], k[1] ^ v[1], k[0] ^ v[2],
			k[3], k[2] ^ v[3], ^k[1], ^k[0],
			k[3], k[2], ^k[1], k[0],
			k[3], ^k[2], k[1], ^k[0],
		}
	} else {
		c.s = [16]uint64{
			k[7] ^ v[0], k[6], k[5], k[4] ^ v[1],
			k[3], k[2] ^ v[2], k[1], ^k[0],
			k[4] ^ v[3], ^k[6], k[5], ^k[7],
			k[3], k[2], ^k[1], k[0],
		}
	}

	// Initialization: 32 clocks with the output of the FSM fed into the LFSR.
	for range 32 {
		out := (c.r1 + c.at(15)) ^ c.r2
		c.s[c.i] = alpha(c.s[c.i]) ^ c.at(13) ^ alphaInv(c.at(11)) ^ out
		c.r1, c.r2 = c.r2+c.at(13), transform(c.r1)
		c.i = (c.i + 1) % 16
	}
	return c, nil
}

// stream is the state: the LFSR s with s[i] its oldest word, the FSM
// registers r1 and r2, and the keystream word being spent.
type stream struct {
	s      [16]uint64
	i      int
	r1, r2 uint64
	word   [8]byte
	used   int // bytes of word already spent
}

// at returns the LFSR word n positions after the oldest.
func (c *stream) at(n int) uint64 { return c.s[(c.i+n)%16] }

func (c *stream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("strumok: output smaller than input")
	}
	for len(src) > 0 {
		if c.used == len(c.word) {
			binary.LittleEndian.PutUint64(c.word[:], c.next())
			c.used = 0
		}
		n := subtle.XORBytes(dst, src, c.word[c.used:])
		c.used += n
		dst, src = dst[n:], src[n:]
	}
}

// next clocks the generator once and returns the keystream word.
func (c *stream) next() uint64 {
	c.s[c.i] = alpha(c.s[c.i]) ^ c.at(13) ^ alphaInv(c.at(11))
	c.r1, c.r2 = c.r2+c.at(13), transform(c.r1)
	z := (c.r1 + c.s[c.i]) ^ c.r2 ^ c.at(1)
	c.i = (c.i + 1) % 16
	return z
}

// alpha multiplies w by α: the bytes move up one place and the byte shifted
// out comes back multiplied by the bytes of alphaMul.
func alpha(w uint64) uint64 { return w<<8 ^ mulBytes(byte(w>>56), alphaMul) }

// alphaInv multiplies w by α^-1, the inverse of alpha.
func alphaInv(w uint64) uint64 { return w>>8 ^ mulBytes(byte(w), alphaInvMul) } //nolint:gosec // G115: the low byte shifted out

// mulBytes multiplies each byte of c by b in GF(2^8).
func mulBytes(b byte, c uint64) uint64 {
	var p uint64
	for j := range 8 {
		p |= uint64(spn.Mul(b, byte(c>>(8*j)))) << (8 * j) //nolint:gosec // G115: takes byte j of c
	}
	return p
}

// transform is the nonlinear map T of the FSM: byte k goes through the
// Kalyna S-box π(k mod 4), and the column is multiplied by the Kalyna MDS
// matrix.
func transform(w uint64) uint64 {
	var col [8]byte
	binary.LittleEndian.PutUint64(col[:], w)
	for k := range col {
		col[k] = spn.Lookup(&spn.Sbox[k%4], col[k])
	}
	spn.MixColumn(&spn.MDS, &col)
	return binary.LittleEndian.Uint64(col[:])
}
