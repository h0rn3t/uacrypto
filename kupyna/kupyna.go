// Package kupyna implements the Kupyna hash function defined in
// DSTU 7564:2014 with 256-, 384- and 512-bit digests.
//
// The implementation is a port of DSTU7564Digest from Bouncy Castle and
// produces the same digests.
package kupyna

import (
	"encoding/binary"
	"hash"

	"github.com/h0rn3t/uacrypto/internal/spn"
)

// Digest sizes in bytes.
const (
	Size256 = 32
	Size384 = 48
	Size512 = 64
)

// digest keeps the state as columns of 8 bytes (little-endian words in Bouncy
// Castle): 8 columns and 10 rounds for Kupyna-256, 16 columns and 14 rounds
// for longer digests.
type digest struct {
	size    int // digest size in bytes
	columns int
	rounds  int
	state   [16][8]byte
	buf     [128]byte
	nbuf    int
	n       uint64 // message length in bytes
}

func newDigest(size int) *digest {
	d := &digest{size: size}
	d.Reset()
	return d
}

// New256 returns a Kupyna-256 hash.Hash.
func New256() hash.Hash { return newDigest(Size256) }

// New384 returns a Kupyna-384 hash.Hash.
func New384() hash.Hash { return newDigest(Size384) }

// New512 returns a Kupyna-512 hash.Hash.
func New512() hash.Hash { return newDigest(Size512) }

// Sum256 returns the Kupyna-256 digest of data.
func Sum256(data []byte) [Size256]byte { return [Size256]byte(sum(Size256, data)) }

// Sum384 returns the Kupyna-384 digest of data.
func Sum384(data []byte) [Size384]byte { return [Size384]byte(sum(Size384, data)) }

// Sum512 returns the Kupyna-512 digest of data.
func Sum512(data []byte) [Size512]byte { return [Size512]byte(sum(Size512, data)) }

func sum(size int, data []byte) []byte {
	d := newDigest(size)
	_, _ = d.Write(data) // never returns an error
	return d.finish()
}

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return d.columns * 8 }

func (d *digest) Reset() {
	columns, rounds := 8, 10
	if d.size > Size256 {
		columns, rounds = 16, 14
	}
	*d = digest{size: d.size, columns: columns, rounds: rounds}
	d.state[0][0] = byte(columns * 8)
}

func (d *digest) Write(p []byte) (int, error) {
	written := len(p)
	bs := d.BlockSize()
	d.n += uint64(len(p))
	if d.nbuf > 0 {
		k := copy(d.buf[d.nbuf:bs], p)
		d.nbuf += k
		p = p[k:]
		if d.nbuf < bs {
			return written, nil
		}
		d.block(d.buf[:bs])
		d.nbuf = 0
	}
	for len(p) >= bs {
		d.block(p[:bs])
		p = p[bs:]
	}
	d.nbuf = copy(d.buf[:], p)
	return written, nil
}

func (d *digest) Sum(b []byte) []byte {
	final := *d
	return append(b, final.finish()...)
}

// finish pads the message (0x80, zeros, the 96-bit little-endian bit length),
// processes the last blocks and applies the output transformation
// state ⊕ P(state). The digest is the last size bytes of the result.
func (d *digest) finish() []byte {
	bs := d.BlockSize()
	tail := append(d.buf[:d.nbuf:d.nbuf], 0x80)
	for (len(tail)+12)%bs != 0 {
		tail = append(tail, 0)
	}
	tail = binary.LittleEndian.AppendUint64(tail, d.n*8)
	tail = append(tail, 0, 0, 0, 0)
	for off := 0; off < len(tail); off += bs {
		d.block(tail[off : off+bs])
	}

	t := d.state
	permuteP(t[:d.columns], d.rounds)
	out := make([]byte, 0, bs)
	for c := range d.columns {
		for r := range 8 {
			out = append(out, d.state[c][r]^t[c][r])
		}
	}
	return out[bs-d.size:]
}

// block is the compression function: state ⊕ P(state ⊕ m) ⊕ Q(m).
func (d *digest) block(m []byte) {
	var msg, mixed [16][8]byte
	for c := range d.columns {
		copy(msg[c][:], m[8*c:])
		for r := range 8 {
			mixed[c][r] = d.state[c][r] ^ msg[c][r]
		}
	}
	permuteP(mixed[:d.columns], d.rounds)
	permuteQ(msg[:d.columns], d.rounds)
	for c := range d.columns {
		for r := range 8 {
			d.state[c][r] ^= mixed[c][r] ^ msg[c][r]
		}
	}
}

// permuteP is the permutation T⊕: round constants are XORed into the first row.
func permuteP(s [][8]byte, rounds int) {
	for round := range rounds {
		for c := range s {
			s[c][0] ^= byte(c<<4 ^ round) //nolint:gosec // G115: c < 16 and round < 14, the value fits a byte
		}
		mixRound(s)
	}
}

// permuteQ is the permutation T+: round constants are added to each column modulo 2^64.
func permuteQ(s [][8]byte, rounds int) {
	n := len(s)
	for round := range rounds {
		for c := range s {
			rc := uint64((n-1-c)<<4^round)<<56 | 0x00F0F0F0F0F0F0F3 //nolint:gosec // G115: c < n <= 16 and round < 14, the value is non-negative
			binary.LittleEndian.PutUint64(s[c][:], binary.LittleEndian.Uint64(s[c][:])+rc)
		}
		mixRound(s)
	}
}

// mixRound applies SubBytes, ShiftBytes and MixColumns of one round.
func mixRound(s [][8]byte) {
	n := len(s)
	var shifted [16][8]byte
	for r := range 8 {
		shift := r
		if r == 7 && n == 16 {
			shift = 11
		}
		for c := range n {
			shifted[(c+shift)%n][r] = spn.Sbox[r%4][s[c][r]]
		}
	}
	for c := range n {
		spn.MixColumn(&spn.MDS, &shifted[c])
		s[c] = shifted[c]
	}
}
