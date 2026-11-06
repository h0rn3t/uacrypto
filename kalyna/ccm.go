package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// CCM is DSTU 7624 CCM over a 16-, 32- or 64-byte block cipher.
// The nonce must be exactly one block.
// Nb is 4, 6 or 8. The tag is 8, 16, 32, 48 or 64 bytes and at most one
// block. A partial final block is zero-padded inside the MAC.
type CCM struct {
	block   cipher.Block
	nb      int
	tagSize int
}

// NewCCM returns CCM with the length parameter Nb and a tag of tagSize bytes.
// block is already keyed.
func NewCCM(block cipher.Block, nb, tagSize int) (*CCM, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if nb != 4 && nb != 6 && nb != 8 {
		return nil, fmt.Errorf("kalyna: CCM Nb %d, want 4, 6 or 8", nb)
	}
	switch tagSize {
	case 8, 16, 32, 48, 64:
	default:
		return nil, fmt.Errorf("kalyna: CCM tag size %d, want 8, 16, 32, 48 or 64 bytes and at most the %d-byte block", tagSize, n)
	}
	if tagSize > n {
		return nil, fmt.Errorf("kalyna: CCM tag size %d, want 8, 16, 32, 48 or 64 bytes and at most the %d-byte block", tagSize, n)
	}
	return &CCM{block: block, nb: nb, tagSize: tagSize}, nil
}

// Seal encrypts plaintext and appends the tag. additionalData is
// authenticated and is not encrypted.
func (c *CCM) Seal(nonce, plaintext, additionalData []byte) ([]byte, error) {
	n := c.block.BlockSize()
	if err := nonceLen(len(nonce), n); err != nil {
		return nil, err
	}
	if err := fitsUint32(len(plaintext)); err != nil {
		return nil, err
	}
	if err := fitsUint32(len(additionalData)); err != nil {
		return nil, err
	}
	nonceBlock := leftAlign(nonce, n)
	mac := c.sum(nonceBlock, additionalData, plaintext)
	// The tag is encrypted with the keystream that follows the plaintext,
	// not from a fresh block.
	gamma := c.keystream(nonceBlock)
	out := make([]byte, len(plaintext)+c.tagSize)
	gamma.XORKeyStream(out, plaintext)
	gamma.XORKeyStream(out[len(plaintext):], mac[:c.tagSize])
	gamma.wipe()
	clear(mac)
	return out, nil
}

// Open checks the tag of ciphertext and returns the plaintext.
// A mismatch returns ErrAuthentication and a nil plaintext. The recovered
// plaintext is discarded when the tag does not match.
func (c *CCM) Open(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	n := c.block.BlockSize()
	if err := nonceLen(len(nonce), n); err != nil {
		return nil, err
	}
	if len(ciphertext) < c.tagSize {
		return nil, ErrAuthentication
	}
	bodyLen := len(ciphertext) - c.tagSize
	if err := fitsUint32(bodyLen); err != nil {
		return nil, err
	}
	if err := fitsUint32(len(additionalData)); err != nil {
		return nil, err
	}
	nonceBlock := leftAlign(nonce, n)
	gamma := c.keystream(nonceBlock)
	plain := make([]byte, bodyLen)
	gamma.XORKeyStream(plain, ciphertext[:bodyLen])
	got := make([]byte, c.tagSize)
	gamma.XORKeyStream(got, ciphertext[bodyLen:])
	gamma.wipe()
	want := c.sum(nonceBlock, additionalData, plain)
	match := subtle.ConstantTimeCompare(want[:c.tagSize], got)
	clear(want)
	clear(got)
	if match != 1 {
		clear(plain)
		return nil, ErrAuthentication
	}
	return plain, nil
}

// keystream is the counter keystream from E(nonce block). It runs over the
// plaintext and then over the tag.
func (c *CCM) keystream(nonceBlock []byte) *ctr {
	counter := make([]byte, len(nonceBlock))
	c.block.Encrypt(counter, nonceBlock)
	return newCounter(c.block, counter)
}

// sum is the CBC-MAC over G1 (nonce, plaintext length, flags), the
// associated data and the plaintext. Associated data longer than one block
// minus Nb is authenticated in full after the length block.
func (c *CCM) sum(nonceBlock, additionalData, plaintext []byte) []byte {
	n := c.block.BlockSize()
	mac := make([]byte, n)
	off := n - c.nb - 1
	copy(mac[:off], nonceBlock[:off])
	binary.LittleEndian.PutUint32(mac[off:], len32(len(plaintext)))
	mac[n-1] = ccmFlag(len(additionalData) > 0, c.tagSize, c.nb)
	c.block.Encrypt(mac, mac)
	if len(additionalData) > 0 {
		g2 := make([]byte, n)
		binary.LittleEndian.PutUint32(g2, len32(len(additionalData)))
		if len(additionalData) <= n-c.nb {
			subtle.XORBytes(g2[c.nb:c.nb+len(additionalData)], g2[c.nb:c.nb+len(additionalData)], additionalData)
			subtle.XORBytes(mac, mac, g2)
			c.block.Encrypt(mac, mac)
		} else {
			subtle.XORBytes(mac, mac, g2)
			c.block.Encrypt(mac, mac)
			cbcMAC(c.block, mac, additionalData, 0)
		}
		clear(g2)
	}
	cbcMAC(c.block, mac, plaintext, 0x80)
	return mac
}

func ccmFlag(associatedData bool, tagSize, nb int) byte {
	var code byte
	switch tagSize {
	case 8:
		code = 2
	case 16:
		code = 3
	case 32:
		code = 4
	case 48:
		code = 5
	default:
		code = 6
	}
	var low byte
	switch nb {
	case 4:
		low = 3
	case 6:
		low = 5
	default:
		low = 7
	}
	flag := (code << 4) | low
	if associatedData {
		flag |= 0x80
	}
	return flag
}

// cbcMAC chains data into mac. A partial last block is padded with pad and
// then zeros: 0 for the associated data, 0x80 for the plaintext, as the
// examples of the standard and cryptonite pad it.
func cbcMAC(block cipher.Block, mac, data []byte, pad byte) {
	n := len(mac)
	for off := 0; off < len(data); off += n {
		end := min(off+n, len(data))
		subtle.XORBytes(mac[:end-off], mac[:end-off], data[off:end])
		if end-off < n {
			mac[end-off] ^= pad
		}
		block.Encrypt(mac, mac)
	}
}

func leftAlign(nonce []byte, n int) []byte {
	block := make([]byte, n)
	copy(block, nonce)
	return block
}
