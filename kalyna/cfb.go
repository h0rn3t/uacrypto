package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// CFB is DSTU 7624 cipher feedback ("гамування зі зворотним зв'язком за
// шифрограмою") with a segment of 1 through block-size bytes, as the examples
// of the standard, the certified cryptonite library and IIT compute it. Each
// segment is XORed with the last bytes of its keystream block; the next
// keystream block encrypts that block with its last segment bytes replaced by
// the ciphertext. A partial last segment uses the last bytes of its keystream
// block. Bouncy Castle and the CFB of crypto/cipher take the leading bytes, so
// they agree only on whole blocks with a segment of one block.
type CFB struct {
	block   cipher.Block
	segment int
}

// NewCFB returns CFB with a segment of segment bytes over block, which is
// already keyed.
func NewCFB(block cipher.Block, segment int) (*CFB, error) {
	n, err := blockBytes(block)
	if err != nil {
		return nil, err
	}
	if segment < 1 || segment > n {
		return nil, fmt.Errorf("kalyna: CFB segment %d, want 1..%d", segment, n)
	}
	return &CFB{block: block, segment: segment}, nil
}

// Encrypt encrypts plaintext of any length under iv, which is one block long.
func (c *CFB) Encrypt(iv, plaintext []byte) ([]byte, error) {
	return c.transform(iv, plaintext, true)
}

// Decrypt decrypts ciphertext of any length under iv, which is one block long.
func (c *CFB) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	return c.transform(iv, ciphertext, false)
}

func (c *CFB) transform(iv, src []byte, encrypt bool) ([]byte, error) {
	n := c.block.BlockSize()
	if len(iv) != n {
		return nil, fmt.Errorf("kalyna: CFB IV length %d, want %d", len(iv), n)
	}
	gamma := make([]byte, n)
	c.block.Encrypt(gamma, iv)
	dst := make([]byte, len(src))
	off := n - c.segment
	i := 0
	for ; len(src)-i >= c.segment; i += c.segment {
		out := dst[i : i+c.segment]
		subtle.XORBytes(out, src[i:i+c.segment], gamma[off:])
		ciphertext := out
		if !encrypt {
			ciphertext = src[i : i+c.segment]
		}
		copy(gamma[off:], ciphertext)
		c.block.Encrypt(gamma, gamma)
	}
	subtle.XORBytes(dst[i:], src[i:], gamma[n-(len(src)-i):])
	clear(gamma)
	return dst, nil
}
