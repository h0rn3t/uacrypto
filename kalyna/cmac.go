package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// CMAC returns the DSTU 7624 CBC-MAC of data, truncated to macSize bytes.
// data must be a whole number of blocks; macSize is 1 through the block
// size. An empty message is accepted and has the same tag as one all-zero
// block: the zero block is masked with E(0) and encrypted.
func CMAC(block cipher.Block, data []byte, macSize int) ([]byte, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if macSize < 1 || macSize > n {
		return nil, fmt.Errorf("kalyna: MAC size %d, want 1..%d", macSize, n)
	}
	if len(data)%n != 0 {
		return nil, fmt.Errorf("kalyna: CMAC length %d is not a multiple of the %d-byte block", len(data), n)
	}

	delta := make([]byte, n)
	block.Encrypt(delta, delta)
	mac := make([]byte, n)
	if len(data) == 0 {
		subtle.XORBytes(mac, mac, delta)
		block.Encrypt(mac, mac)
	} else {
		blocks := len(data) / n
		for i := range blocks {
			subtle.XORBytes(mac, mac, data[i*n:(i+1)*n])
			if i+1 == blocks {
				subtle.XORBytes(mac, mac, delta)
			}
			block.Encrypt(mac, mac)
		}
	}
	clear(delta)
	out := make([]byte, macSize)
	copy(out, mac)
	clear(mac)
	return out, nil
}
