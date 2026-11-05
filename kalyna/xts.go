package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// XTS is DSTU 7624 XTS. One key encrypts the tweak and the data. The IV is
// one block. Input is a whole number of blocks; an empty input encrypts to
// an empty output. There is no ciphertext stealing. The tweak E(IV) is
// multiplied by x before every block, including the first.
type XTS struct {
	block     cipher.Block
	reduction uint64
}

// NewXTS returns XTS over block. block is already keyed.
func NewXTS(block cipher.Block) (*XTS, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	return &XTS{block: block, reduction: reductionPolynomial(n)}, nil
}

// Encrypt encrypts plaintext under iv.
func (x *XTS) Encrypt(iv, plaintext []byte) ([]byte, error) {
	return x.transform(iv, plaintext, x.block.Encrypt)
}

// Decrypt decrypts ciphertext under iv.
func (x *XTS) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	return x.transform(iv, ciphertext, x.block.Decrypt)
}

func (x *XTS) transform(iv, data []byte, crypt func(dst, src []byte)) ([]byte, error) {
	n := x.block.BlockSize()
	if len(iv) != n {
		return nil, fmt.Errorf("kalyna: XTS IV length %d, want %d", len(iv), n)
	}
	if len(data)%n != 0 {
		return nil, fmt.Errorf("kalyna: XTS length %d is not a multiple of the %d-byte block", len(data), n)
	}
	tweakBytes := make([]byte, n)
	x.block.Encrypt(tweakBytes, iv)
	tweak := wordsLE(tweakBytes)
	out := make([]byte, len(data))
	for off := 0; off < len(data); off += n {
		multiplyByX(tweak, x.reduction)
		putWordsLE(tweakBytes, tweak)
		block := out[off : off+n]
		copy(block, data[off:off+n])
		subtle.XORBytes(block, block, tweakBytes)
		crypt(block, block)
		subtle.XORBytes(block, block, tweakBytes)
	}
	clear(tweakBytes)
	clear(tweak)
	return out, nil
}
