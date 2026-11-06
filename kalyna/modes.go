package kalyna

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"math"
)

// ErrAuthentication is returned when a GCM tag, a CCM tag or a wrapped-key
// checksum does not match. Open and Unwrap then return a nil message. Open
// also returns it when the ciphertext is shorter than the tag.
var ErrAuthentication = errors.New("kalyna: authentication failed")

func blockBytes(block cipher.Block) (int, error) {
	if block == nil {
		return 0, errors.New("kalyna: nil block cipher")
	}
	n := block.BlockSize()
	if n != 16 && n != 32 && n != 64 {
		return 0, fmt.Errorf("kalyna: block size %d, want 16, 32 or 64", n)
	}
	return n, nil
}

func nonceLen(n, blockSize int) error {
	if n != blockSize {
		return fmt.Errorf("kalyna: nonce length %d, want %d", n, blockSize)
	}
	return nil
}

func fitsUint32(n int) error {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return errors.New("kalyna: input longer than 2^32-1 bytes")
	}
	return nil
}

func len32(n int) uint32 {
	return uint32(n) //nolint:gosec // G115: fitsUint32 rejected a longer input
}

// incrementLE adds one to the little-endian counter, wrapping to zero. It
// walks every byte, so its time does not depend on where the carry stops.
func incrementLE(counter []byte) {
	carry := uint16(1)
	for i := range counter {
		sum := uint16(counter[i]) + carry
		counter[i] = byte(sum & 0xff)
		carry = sum >> 8
	}
}
