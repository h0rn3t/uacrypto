package kupyna

import (
	"fmt"
	"hash"
)

// NewMAC returns the DSTU 7564 MAC ("код автентифікації повідомлення") under
// key as a hash.Hash of size bytes, 32, 48 or 64: Kupyna of
// PAD(K) || PAD(M) || ~K, where PAD is the Kupyna padding of the key and of the
// message on their own and ~K is the key with every bit inverted, as the
// certified cryptonite library computes it.
func NewMAC(key []byte, size int) (hash.Hash, error) {
	if size != Size256 && size != Size384 && size != Size512 {
		return nil, fmt.Errorf("kupyna: MAC size %d, want %d, %d or %d", size, Size256, Size384, Size512)
	}
	d := newDigest(size)
	_, _ = d.Write(key) // digest.Write never fails
	_, _ = d.Write(padding(uint64(len(key)), d.BlockSize()))
	notKey := make([]byte, len(key))
	for i, b := range key {
		notKey[i] = ^b
	}
	return &mac{d: *d, start: *d, notKey: notKey}, nil
}

type mac struct {
	d      digest // after PAD(K) and the message so far
	start  digest // after PAD(K), for Reset
	notKey []byte
	n      uint64 // message length in bytes
}

func (m *mac) Write(p []byte) (int, error) {
	m.n += uint64(len(p))
	return m.d.Write(p)
}

func (m *mac) Sum(b []byte) []byte {
	final := m.d
	_, _ = final.Write(padding(m.n, final.BlockSize()))
	_, _ = final.Write(m.notKey)
	return append(b, final.finish()...)
}

func (m *mac) Reset() {
	m.d = m.start
	m.n = 0
}

func (m *mac) Size() int      { return m.d.Size() }
func (m *mac) BlockSize() int { return m.d.BlockSize() }
