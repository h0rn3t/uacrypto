package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Wrap wraps key, of any length, under the key already set on block. A key
// that is not a whole number of blocks is followed by its length in bits,
// little-endian over half a block, and then by 80 00... up to the block, as
// the examples of DSTU 7624 and the certified cryptonite library do. A zero
// integrity block is appended before wrapping, so the result is one block
// longer than the padded key. An empty key wraps to one block.
func Wrap(block cipher.Block, key []byte) ([]byte, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	padded := len(key)
	if len(key)%n != 0 {
		padded = (len(key) + n/2 + n - 1) / n * n
	}
	steps, err := wrapSteps(2 * (1 + padded/n))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, padded+n)
	defer clear(buf)
	copy(buf, key)
	if padded != len(key) {
		copy(buf[len(key):], keyTrailer(len(key), padded, n))
	}
	return wrapBlocks(block, buf, steps, true), nil
}

// keyTrailer is what follows a key of keyLen bytes up to padded: its bit
// length over half a block, then 80 00... when the block is not yet full.
func keyTrailer(keyLen, padded, n int) []byte {
	trailer := make([]byte, padded-keyLen)
	binary.LittleEndian.PutUint64(trailer, uint64(keyLen)*8) //nolint:gosec // G115: a slice length is not negative
	if len(trailer) > n/2 {
		trailer[n/2] = 0x80
	}
	return trailer
}

// Unwrap unwraps wrapped under the key already set on block, checks the zero
// integrity block and removes the padding Wrap adds to a key that is not a
// whole number of blocks. wrapped must be a positive multiple of the block.
// A checksum mismatch returns ErrAuthentication and a nil key. As in the
// standard's format, a whole-block key whose last bytes happen to form such a
// padding is read as the shorter key.
func Unwrap(block cipher.Block, wrapped []byte) ([]byte, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) == 0 || len(wrapped)%n != 0 {
		return nil, fmt.Errorf("kalyna: unwrap length %d is not a positive multiple of the %d-byte block", len(wrapped), n)
	}
	steps, err := wrapSteps(2 * (len(wrapped) / n))
	if err != nil {
		return nil, err
	}
	out := wrapBlocks(block, wrapped, steps, false)
	if subtle.ConstantTimeCompare(out[len(out)-n:], make([]byte, n)) != 1 {
		clear(out)
		return nil, ErrAuthentication
	}
	body := out[:len(out)-n]
	key := make([]byte, keyLength(body, n))
	copy(key, body)
	clear(out)
	return key, nil
}

// keyLength returns the length of the key in body, the unwrapped blocks
// before the integrity block. Every possible padding is compared in full, so
// the time does not depend on the key bytes.
func keyLength(body []byte, n int) int {
	keyLen := len(body)
	for pad := range n {
		l := len(body) - pad - n/2
		if l < 0 || l%n == 0 {
			continue
		}
		trailer := keyTrailer(l, len(body), n)
		keyLen = subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(body[l:], trailer), l, keyLen)
	}
	return keyLen
}

func wrapSteps(halves int) (int, error) {
	if halves < 2 || uint64(halves-1) > min(uint64(math.MaxUint32), uint64(math.MaxInt))/6 {
		return 0, errors.New("kalyna: wrap input longer than the 32-bit step counter")
	}
	return (halves - 1) * 6, nil
}

// wrapBlocks runs the DSTU 7624 wrap permutation. encrypt selects wrapping;
// unwrapping walks the steps backward and decrypts. The step counter is a
// little-endian uint32, XORed into the first four bytes of the second half.
func wrapBlocks(block cipher.Block, data []byte, steps int, encrypt bool) []byte {
	half := block.BlockSize() / 2
	b, halves := splitHalves(data, half)
	buf := make([]byte, half*2)
	for j := range steps {
		if encrypt {
			copy(buf[:half], b)
			copy(buf[half:], halves[0])
			block.Encrypt(buf, buf)
			xorStep(buf[half:], j+1)
			copy(b, buf[half:])
			shiftLeft(halves, buf[:half])
			continue
		}
		copy(buf[:half], halves[len(halves)-1])
		copy(buf[half:], b)
		xorStep(buf[half:], steps-j)
		block.Decrypt(buf, buf)
		copy(b, buf[:half])
		shiftRight(halves, buf[half:])
	}
	clear(buf)
	out := joinHalves(b, halves)
	clear(b)
	for _, h := range halves {
		clear(h)
	}
	return out
}

func splitHalves(data []byte, half int) ([]byte, [][]byte) {
	b := make([]byte, half)
	copy(b, data[:half])
	halves := make([][]byte, len(data)/half-1)
	for i := range halves {
		halves[i] = make([]byte, half)
		copy(halves[i], data[(i+1)*half:(i+2)*half])
	}
	return b, halves
}

func joinHalves(b []byte, halves [][]byte) []byte {
	out := make([]byte, len(b)*(len(halves)+1))
	copy(out, b)
	for i, h := range halves {
		copy(out[(i+1)*len(b):], h)
	}
	return out
}

func shiftLeft(halves [][]byte, fill []byte) {
	reused := halves[0]
	copy(halves, halves[1:])
	halves[len(halves)-1] = reused
	copy(reused, fill)
}

func shiftRight(halves [][]byte, fill []byte) {
	reused := halves[len(halves)-1]
	for i := len(halves) - 1; i > 0; i-- {
		halves[i] = halves[i-1]
	}
	halves[0] = reused
	copy(reused, fill)
}

func xorStep(dst []byte, step int) {
	var counter [4]byte
	binary.LittleEndian.PutUint32(counter[:], len32(step))
	subtle.XORBytes(dst[:4], dst[:4], counter[:])
}
