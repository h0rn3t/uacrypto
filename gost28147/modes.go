package gost28147

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/bits"
)

// The constants GOST 28147-89 adds to the counter halves in gamma mode.
const (
	ctrC1 = 0x01010101 // to the low word, modulo 2^32
	ctrC2 = 0x01010104 // to the high word, modulo 2^32-1
)

// NewCTR returns GOST 28147-89 gamma mode ("гамування") over block, an
// 8-byte block cipher such as the one NewCipher returns, under the 8-byte iv.
// The counter starts at E(iv); before each keystream block 0x01010101 is added
// to its low word modulo 2^32 and 0x01010104 to its high word modulo 2^32-1,
// as the certified cryptonite library computes it. A partial block uses the
// leading bytes of its keystream block, and the next XORKeyStream continues
// with the rest, so a message may be split anywhere. The same call decrypts.
func NewCTR(block cipher.Block, iv []byte) (cipher.Stream, error) {
	if block == nil || block.BlockSize() != BlockSize {
		return nil, errors.New("gost28147: CTR needs an 8-byte block cipher")
	}
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("gost28147: CTR IV is %d bytes, want %d", len(iv), BlockSize)
	}
	c := &ctr{block: block, used: BlockSize}
	block.Encrypt(c.counter[:], iv)
	return c, nil
}

type ctr struct {
	block   cipher.Block
	counter [BlockSize]byte
	gamma   [BlockSize]byte
	used    int // bytes of gamma already spent
}

func (c *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost28147: CTR output smaller than input")
	}
	for len(src) > 0 {
		if c.used == BlockSize {
			c.next()
		}
		n := subtle.XORBytes(dst, src, c.gamma[c.used:])
		c.used += n
		dst, src = dst[n:], src[n:]
	}
}

// next advances the counter and encrypts it into the next keystream block.
// The carry of the high word is added back without a branch.
func (c *ctr) next() {
	low := binary.LittleEndian.Uint32(c.counter[:4]) + ctrC1
	high, carry := bits.Add32(binary.LittleEndian.Uint32(c.counter[4:]), ctrC2, 0)
	binary.LittleEndian.PutUint32(c.counter[:4], low)
	binary.LittleEndian.PutUint32(c.counter[4:], high+carry)
	c.block.Encrypt(c.gamma[:], c.counter[:])
	c.used = 0
}

// NewMAC returns the GOST 28147-89 MAC ("імітовставка") under key and sbox as
// a hash.Hash whose Sum is size bytes long, 1 through 8; 4 is usual, and
// cryptonite and IIT offer 4 and 8. Each 8-byte block of the message is XORed
// into the state, which then goes through the first 16 rounds of the cipher;
// a partial last block is zero-padded. The MAC is the leading bytes of the
// state, and an empty message has an all-zero MAC.
func NewMAC(key []byte, sbox Sbox, size int) (hash.Hash, error) {
	if size < 1 || size > BlockSize {
		return nil, fmt.Errorf("gost28147: MAC size %d, want 1..%d", size, BlockSize)
	}
	b, err := NewCipher(key, sbox)
	if err != nil {
		return nil, err
	}
	return &mac{c: b.(*gostCipher), size: size}, nil
}

type mac struct {
	c     *gostCipher
	size  int
	state [BlockSize]byte
	n     int // bytes of the current block already absorbed
}

func (m *mac) Write(p []byte) (int, error) {
	m.c.live()
	for _, b := range p {
		m.state[m.n] ^= b
		m.n++
		if m.n == BlockSize {
			m.c.macRounds(&m.state)
			m.n = 0
		}
	}
	return len(p), nil
}

func (m *mac) Sum(b []byte) []byte {
	m.c.live()
	state := m.state
	if m.n != 0 {
		m.c.macRounds(&state)
	}
	return append(b, state[:m.size]...)
}

func (m *mac) Reset() {
	clear(m.state[:])
	m.n = 0
}

func (m *mac) Size() int      { return m.size }
func (m *mac) BlockSize() int { return BlockSize }

// macRounds runs the first 16 rounds of encryption, without the final swap.
func (c *gostCipher) macRounds(block *[BlockSize]byte) {
	n1 := binary.LittleEndian.Uint32(block[:4])
	n2 := binary.LittleEndian.Uint32(block[4:])
	for _, k := range encryptOrder[:16] {
		n1, n2 = n2^c.round(n1, c.key[k]), n1
	}
	binary.LittleEndian.PutUint32(block[:4], n1)
	binary.LittleEndian.PutUint32(block[4:], n2)
}
