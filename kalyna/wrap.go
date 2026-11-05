package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Wrap wraps key under the key already set on block. key must be a whole
// number of blocks. An empty key is accepted and wraps to one block. The
// result is one block longer than key; that block is a zero integrity check.
func Wrap(block cipher.Block, key []byte) ([]byte, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if len(key)%n != 0 {
		return nil, fmt.Errorf("kalyna: wrap length %d is not a multiple of the %d-byte block", len(key), n)
	}
	steps, err := wrapSteps(2 * (1 + len(key)/n))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(key)+n)
	copy(buf, key)
	return wrapBlocks(block, buf, steps, true), nil
}

// Unwrap unwraps wrapped under the key already set on block and checks the
// zero integrity block. wrapped must be a positive multiple of the block.
// A checksum mismatch returns ErrAuthentication and a nil key.
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
	key := make([]byte, len(out)-n)
	copy(key, out)
	clear(out)
	return key, nil
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
	return joinHalves(b, halves)
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
