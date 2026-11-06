package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// XTS is DSTU 7624 XTS. One key encrypts the tweak and the data. The IV is
// one block. The tweak E(IV) is multiplied by x before every block, including
// the first. Input of at least one block may end in a partial block, which
// steals the end of the previous ciphertext block, as the examples of the
// standard and the certified cryptonite library do; an empty input encrypts
// to an empty output.
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
	return x.transform(iv, plaintext, false)
}

// Decrypt decrypts ciphertext under iv.
func (x *XTS) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	return x.transform(iv, ciphertext, true)
}

func (x *XTS) transform(iv, data []byte, decrypt bool) ([]byte, error) {
	n := x.block.BlockSize()
	if len(iv) != n {
		return nil, fmt.Errorf("kalyna: XTS IV length %d, want %d", len(iv), n)
	}
	if len(data) > 0 && len(data) < n {
		return nil, fmt.Errorf("kalyna: XTS length %d is shorter than the %d-byte block", len(data), n)
	}
	crypt := x.block.Encrypt
	if decrypt {
		crypt = x.block.Decrypt
	}
	apply := func(dst, src, tweak []byte) {
		subtle.XORBytes(dst, src, tweak)
		crypt(dst, dst)
		subtle.XORBytes(dst, dst, tweak)
	}

	tweakBytes := make([]byte, n)
	x.block.Encrypt(tweakBytes, iv)
	tweak := wordsLE(tweakBytes)
	nextTweak := func() {
		multiplyByX(tweak, x.reduction)
		putWordsLE(tweakBytes, tweak)
	}
	defer clear(tweak)
	defer clear(tweakBytes)

	out := make([]byte, len(data))
	r := len(data) % n
	full := len(data) - r // end of the whole blocks
	plain := full         // end of the blocks outside the stealing
	if r != 0 {
		plain -= n
	}
	for off := 0; off < plain; off += n {
		nextTweak()
		apply(out[off:off+n], data[off:off+n], tweakBytes)
	}
	if r == 0 {
		return out, nil
	}

	// The last whole block takes tweak m and the stolen block tweak m+1;
	// decryption undoes them in the opposite order.
	nextTweak()
	tweakM := make([]byte, n)
	copy(tweakM, tweakBytes)
	defer clear(tweakM)
	nextTweak()
	first, second := tweakM, tweakBytes
	if decrypt {
		first, second = tweakBytes, tweakM
	}
	whole := out[plain:full]
	apply(whole, data[plain:full], first)
	stolen := make([]byte, n)
	copy(stolen, data[full:])
	copy(stolen[r:], whole[r:])
	copy(out[full:], whole[:r])
	apply(whole, stolen, second)
	clear(stolen)
	return out, nil
}
