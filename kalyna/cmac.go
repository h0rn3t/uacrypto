package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// CMAC returns the DSTU 7624 MAC ("вироблення імітовставки") of data,
// truncated to macSize bytes, 1 through the block size. data is chained
// through the cipher as in CBC; the last block is masked with E(0) before it
// is encrypted. A partial last block is padded with 80 00... and masked with
// E(01 00...) instead, as the examples of the standard, the certified
// cryptonite library and IIT compute it. An empty message has the MAC of one
// all-zero block.
func CMAC(block cipher.Block, data []byte, macSize int) ([]byte, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if macSize < 1 || macSize > n {
		return nil, fmt.Errorf("kalyna: MAC size %d, want 1..%d", macSize, n)
	}

	padded := len(data)%n != 0
	mask := make([]byte, n)
	if padded {
		mask[0] = 1
	}
	block.Encrypt(mask, mask)
	mac := make([]byte, n)
	last := make([]byte, n)
	for off := 0; ; off += n {
		end := min(off+n, len(data))
		if end < len(data) {
			subtle.XORBytes(mac, mac, data[off:end])
			block.Encrypt(mac, mac)
			continue
		}
		copy(last, data[off:end])
		if padded {
			last[end-off] = 0x80
		}
		subtle.XORBytes(mac, mac, last)
		subtle.XORBytes(mac, mac, mask)
		block.Encrypt(mac, mac)
		break
	}
	clear(mask)
	clear(last)
	out := make([]byte, macSize)
	copy(out, mac)
	clear(mac)
	return out, nil
}

// GMAC returns the DSTU 7624 GMAC of data, macSize bytes long, 8 through the
// block size: the GCM tag of data as additional data with no ciphertext.
func GMAC(block cipher.Block, data []byte, macSize int) ([]byte, error) {
	g, err := NewGCM(block, macSize)
	if err != nil {
		return nil, err
	}
	if err := fitsUint32(len(data)); err != nil {
		return nil, err
	}
	return g.tag(nil, data, nil)[:macSize], nil
}
