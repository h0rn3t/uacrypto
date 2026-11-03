// Package kalyna implements the Kalyna block cipher defined in
// DSTU 7624:2014 with 128-, 256- and 512-bit blocks.
//
// The implementation is a port of DSTU7624Engine from Bouncy Castle and
// produces the same output. Only the block transform is provided; use the
// modes of crypto/cipher (CTR, CBC, ...) on top of it. It is not
// constant-time.
package kalyna

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/h0rn3t/uacrypto/internal/spn"
)

// mdsInv is the first row of the inverse MixColumns matrix.
var mdsInv = [8]byte{0xad, 0x95, 0x76, 0xa8, 0x2f, 0x49, 0xd7, 0xca}

var sboxInv = func() (inv [4][256]byte) {
	for i, s := range spn.Sbox {
		for x, y := range s {
			inv[i][y] = byte(x)
		}
	}
	return inv
}()

// NewCipher128 returns Kalyna with a 16-byte block. The key must be 16 or 32
// bytes long.
func NewCipher128(key []byte) (cipher.Block, error) { return newCipher(16, key, 16, 32) }

// NewCipher256 returns Kalyna with a 32-byte block. The key must be 32 or 64
// bytes long.
func NewCipher256(key []byte) (cipher.Block, error) { return newCipher(32, key, 32, 64) }

// NewCipher512 returns Kalyna with a 64-byte block. The key must be 64 bytes
// long.
func NewCipher512(key []byte) (cipher.Block, error) { return newCipher(64, key, 64) }

// kalyna keeps the state as 8-byte columns, each a little-endian 64-bit word
// in Bouncy Castle; byte r of a column is row r.
type kalyna struct {
	blockSize int
	keys      [][]byte // round keys 0..rounds
}

func newCipher(blockSize int, key []byte, keySizes ...int) (cipher.Block, error) {
	if !slices.Contains(keySizes, len(key)) {
		return nil, fmt.Errorf("kalyna: %d-byte key for a %d-byte block, want one of %v bytes", len(key), blockSize, keySizes)
	}
	rounds := map[int]int{16: 10, 32: 14, 64: 18}[len(key)]
	return &kalyna{blockSize: blockSize, keys: expandKey(blockSize, key, rounds)}, nil
}

// expandKey is the key schedule of DSTU 7624: the intermediate key kt, the
// even round keys from it and the key, and odd round keys as rotations of
// the even ones.
func expandKey(blockSize int, key []byte, rounds int) [][]byte {
	kt := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(kt, uint64((blockSize+len(key))/8+1)) //nolint:gosec // G115: at most 17
	// k0 and k1 are the same block when the key is one block long
	k0, k1 := key[:blockSize], key[len(key)-blockSize:]
	add(kt, k0)
	round(kt)
	xor(kt, k1)
	round(kt)
	add(kt, k0)
	round(kt)

	keys := make([][]byte, rounds+1)
	words := len(key) / 8
	for i := 0; i <= rounds; i += 2 {
		step := i / 2
		// a two-block key yields two round keys before it rotates by a word
		shift, half := step, 0
		if len(key) != blockSize {
			shift, half = step/2, step%2
		}
		rotated := rotate(key, 8*(shift%words))
		tmv := make([]byte, blockSize)
		for c := 0; c < blockSize; c += 8 {
			binary.LittleEndian.PutUint64(tmv[c:], 0x0001000100010001<<step)
		}
		add(tmv, kt)

		rk := slices.Clone(rotated[half*blockSize : (half+1)*blockSize])
		add(rk, tmv)
		round(rk)
		xor(rk, tmv)
		round(rk)
		add(rk, tmv)
		keys[i] = rk
	}
	for i := 1; i < rounds; i += 2 {
		keys[i] = rotate(keys[i-1], blockSize/4+3)
	}
	return keys
}

func (k *kalyna) BlockSize() int { return k.blockSize }

func (k *kalyna) Encrypt(dst, src []byte) {
	if len(src) < k.blockSize || len(dst) < k.blockSize {
		panic("kalyna: input not full block")
	}
	rounds := len(k.keys) - 1
	var buf [64]byte
	s := buf[:k.blockSize]
	copy(s, src)
	add(s, k.keys[0])
	for i := 1; i < rounds; i++ {
		round(s)
		xor(s, k.keys[i])
	}
	round(s)
	add(s, k.keys[rounds])
	copy(dst, s)
}

func (k *kalyna) Decrypt(dst, src []byte) {
	if len(src) < k.blockSize || len(dst) < k.blockSize {
		panic("kalyna: input not full block")
	}
	rounds := len(k.keys) - 1
	var buf [64]byte
	s := buf[:k.blockSize]
	copy(s, src)
	sub(s, k.keys[rounds])
	for i := rounds - 1; i > 0; i-- {
		invRound(s)
		xor(s, k.keys[i])
	}
	invRound(s)
	sub(s, k.keys[0])
	copy(dst, s)
}

// round applies SubBytes, ShiftRows and MixColumns.
func round(s []byte) {
	n := len(s) / 8
	var shifted [64]byte
	for c := range n {
		for r := range 8 {
			// row r moves r*n/8 columns, r*blockBits/512 in the standard
			shifted[8*((c+r*n/8)%n)+r] = spn.Sbox[r%4][s[8*c+r]]
		}
	}
	for c := range n {
		col := (*[8]byte)(shifted[8*c:])
		spn.MixColumn(&spn.MDS, col)
		copy(s[8*c:], col[:])
	}
}

// invRound undoes round.
func invRound(s []byte) {
	n := len(s) / 8
	for c := range n {
		spn.MixColumn(&mdsInv, (*[8]byte)(s[8*c:]))
	}
	var shifted [64]byte
	for c := range n {
		for r := range 8 {
			shifted[8*c+r] = sboxInv[r%4][s[8*((c+r*n/8)%n)+r]]
		}
	}
	copy(s, shifted[:len(s)])
}

// add adds k to s column by column modulo 2^64.
func add(s, k []byte) {
	for c := 0; c < len(s); c += 8 {
		binary.LittleEndian.PutUint64(s[c:], binary.LittleEndian.Uint64(s[c:])+binary.LittleEndian.Uint64(k[c:]))
	}
}

// sub subtracts k from s column by column modulo 2^64.
func sub(s, k []byte) {
	for c := 0; c < len(s); c += 8 {
		binary.LittleEndian.PutUint64(s[c:], binary.LittleEndian.Uint64(s[c:])-binary.LittleEndian.Uint64(k[c:]))
	}
}

func xor(s, k []byte) {
	for i := range s {
		s[i] ^= k[i]
	}
}

// rotate returns b rotated left by n bytes.
func rotate(b []byte, n int) []byte {
	return append(slices.Clone(b[n:]), b[:n]...)
}
