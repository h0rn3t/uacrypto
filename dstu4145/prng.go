package dstu4145

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
)

// SeedSize is the length of the seed NewPRNG takes: a 32-byte GOST 28147-89
// key and an 8-byte initial state.
const SeedSize = 40

var (
	errPRNGLooped    = errors.New("dstu4145: PRNG returned to its initial state")
	errPRNGDestroyed = errors.New("dstu4145: PRNG destroyed")
)

// A PRNG is the pseudorandom generator the certified cryptonite library
// requires for DSTU 4145 key generation and signing (PRNG_MODE_DSTU), with
// the same output for the same seed and clock. It is GOST 28147-89 with
// ДКЕ №1 in simple replacement mode: each output bit is the low bit of the
// state after the state, mixed with the encrypted seeding time, is
// encrypted; a second encryption advances the state. Bytes are filled from
// the least significant bit.
//
// The time is the Unix time in seconds, as cryptonite takes it outside
// Windows. A PRNG is an io.Reader for GenerateKey and Sign. It is not safe
// for concurrent use; Destroy erases its key and state.
type PRNG struct {
	block cipher.Block
	state [8]byte
	start [8]byte // state after seeding; reaching it again is an error
	t     [8]byte // seeding time, encrypted
	now   func() time.Time
}

// NewPRNG returns a generator keyed by a seed of SeedSize bytes from a source
// of true randomness, normally crypto/rand: the first 32 bytes are the
// GOST 28147-89 key, the last 8 the initial state.
func NewPRNG(seed []byte) (*PRNG, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("dstu4145: PRNG seed is %d bytes, want %d", len(seed), SeedSize)
	}
	return newPRNG(seed, time.Now), nil
}

func newPRNG(seed []byte, now func() time.Time) *PRNG {
	g := &PRNG{now: now}
	g.rekey(seed[:32], seed[32:SeedSize])
	return g
}

// rekey sets the key and the state and encrypts the current time.
func (g *PRNG) rekey(key, state []byte) {
	if g.block != nil {
		gost28147.Destroy(g.block)
	}
	g.block, _ = gost28147.NewCipher(key, gost28147.DKE1()) // a 32-byte key is always accepted
	copy(g.state[:], state)
	g.start = g.state
	binary.BigEndian.PutUint64(g.t[:], uint64(g.now().Unix())) //nolint:gosec // G115: two's complement, as cryptonite's (uint64_t)time(NULL)
	g.block.Encrypt(g.t[:], g.t[:])
}

// Seed mixes data into the generator, as cryptonite's prng_seed does: with
// h1 = GOST34311(data || state || time) and h2 = GOST34311(h1 || data ||
// state || time), h1 becomes the key and the first 8 bytes of h2 the state,
// and the current time is encrypted anew.
func (g *PRNG) Seed(data []byte) {
	if g.block == nil {
		return // destroyed: Read keeps failing
	}
	h := gost34311.New()
	h.Write(data)
	h.Write(g.state[:])
	h.Write(g.t[:])
	h1 := h.Sum(nil)
	h.Reset()
	h.Write(h1)
	h.Write(data)
	h.Write(g.state[:])
	h.Write(g.t[:])
	h2 := h.Sum(nil)
	g.rekey(h1, h2[:8])
	clear(h1)
	clear(h2)
}

// Read fills p with pseudorandom bytes. It fails only if the state returns to
// its value after seeding, which cryptonite treats as a broken generator (p
// then holds n good bytes), or after Destroy.
func (g *PRNG) Read(p []byte) (n int, err error) {
	if g.block == nil {
		return 0, errPRNGDestroyed
	}
	for i := range p {
		var b byte
		for bit := range 8 {
			subtle.XORBytes(g.state[:], g.state[:], g.t[:])
			g.block.Encrypt(g.state[:], g.state[:])
			b |= (g.state[0] & 1) << bit
			subtle.XORBytes(g.state[:], g.state[:], g.t[:])
			g.block.Encrypt(g.state[:], g.state[:])
			if g.state == g.start {
				return i, errPRNGLooped
			}
		}
		p[i] = b
	}
	return len(p), nil
}

// Destroy overwrites the key and the state with zeros. Afterwards Read fails
// and Seed does nothing. Copies the Go runtime made earlier (a moved stack)
// are beyond its reach.
func (g *PRNG) Destroy() {
	if g.block != nil {
		gost28147.Destroy(g.block)
		g.block = nil
	}
	g.state, g.start, g.t = [8]byte{}, [8]byte{}, [8]byte{}
}
