// Package gost3410 implements the elliptic curve digital signature of
// cryptonite's gost3410 module: the algorithm of GOST R 34.10-2001 and of the
// interstate GOST 34.310-2004 over a prime-field curve y² = x³ + ax + b with
// p and q below 2^256.
//
// It is not the older GOST 34.310-95, whose signature works in a subgroup of
// the multiplicative group modulo a prime: cryptonite does not implement
// that one. cryptonite ships no Ukrainian parameter set for this algorithm
// (its five built-in sets are the GOST R 34.10-2001 test curve, the three
// CryptoPro curves of RFC 4357 and NIST P-256), so the package has none
// either: NewCurve takes the parameters from the caller.
//
// As in cryptonite, the digest is read as a little-endian integer, public key
// coordinates are little-endian, and a signature is the pair (r, s).
//
// GenerateKey, NewPrivateKey, PrivateKey.Bytes and Sign handle the private key
// and the per-signature secret with fixed 64-bit limbs, Montgomery arithmetic
// without secret-dependent branches or memory accesses, and complete addition
// formulas in a double-and-add-always loop. Unlike dstu4145 this is not
// checked by a timing test. Verify, ParsePublicKey, DecompressPublicKey and
// NewCurve handle public data. The package has not been audited.
package gost3410

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"slices"
)

// A PublicKey is a public key Q = dP on a curve.
type PublicKey struct {
	curve *Curve
	q     point // Z = 1 in Montgomery form
}

// A PrivateKey is a private key d with its public key.
type PrivateKey struct {
	pub PublicKey
	d   nat
}

// GenerateKey returns a new key on curve c with d drawn uniformly from
// [1, q-1] using random, normally crypto/rand.Reader.
func GenerateKey(c *Curve, random io.Reader) (*PrivateKey, error) {
	d, err := randomScalar(c, random)
	if err != nil {
		return nil, err
	}
	return newPrivateKey(c, d), nil
}

// NewPrivateKey returns the key on curve c with the big-endian scalar d,
// which must be in [1, q-1].
func NewPrivateKey(c *Curve, d []byte) (*PrivateKey, error) {
	k, ok := scalarFromBytes(c, d)
	if !ok {
		return nil, errors.New("gost3410: private key out of range [1, q-1]")
	}
	return newPrivateKey(c, k), nil
}

func newPrivateKey(c *Curve, d nat) *PrivateKey {
	q := c.scalarMult(&c.g, &d)
	x, y := c.affine(&q)
	pub := point{x: c.p.toMont(&x), y: c.p.toMont(&y), z: c.p.one}
	return &PrivateKey{pub: PublicKey{curve: c, q: pub}, d: d}
}

// Public returns the public key of k.
func (k *PrivateKey) Public() *PublicKey { return &k.pub }

// Bytes returns d as a big-endian integer padded to the byte length of q,
// the form NewPrivateKey accepts.
func (k *PrivateKey) Bytes() []byte {
	b := k.d.bytesBE()
	return b[32-(k.pub.curve.q.bits+7)/8:]
}

// Curve returns the curve of k.
func (k *PublicKey) Curve() *Curve { return k.curve }

// Bytes returns x||y, each coordinate little-endian and padded to the byte
// length of p: the form of cryptonite's gost3410_get_pubkey and of the
// GOST R 34.10-2001 public key in RFC 4491 certificates.
func (k *PublicKey) Bytes() []byte {
	x, y := k.coordinates()
	return append(x, y...)
}

// Compress returns x little-endian, as in Bytes, and the lowest bit of y:
// the compressed form of cryptonite's gost3410_compress_pubkey.
func (k *PublicKey) Compress() (x []byte, yBit uint) {
	x, y := k.coordinates()
	return x, uint(y[0] & 1)
}

func (k *PublicKey) coordinates() (x, y []byte) {
	f := &k.curve.p
	size := (f.bits + 7) / 8
	xn, yn := f.fromMont(&k.q.x), f.fromMont(&k.q.y)
	return leBytes(&xn, size), leBytes(&yn, size)
}

// ParsePublicKey decodes x||y in the form of PublicKey.Bytes. It fails unless
// the point lies on curve c in the subgroup of order q.
func ParsePublicKey(c *Curve, data []byte) (*PublicKey, error) {
	size := (c.p.bits + 7) / 8
	if len(data) != 2*size {
		return nil, fmt.Errorf("gost3410: public key is %d bytes, want %d", len(data), 2*size)
	}
	return newPublicKey(c, leInt(data[:size]), leInt(data[size:]))
}

// DecompressPublicKey restores the public key from x little-endian and the
// lowest bit of y, as PublicKey.Compress returns them.
func DecompressPublicKey(c *Curve, x []byte, yBit uint) (*PublicKey, error) {
	if yBit > 1 {
		return nil, fmt.Errorf("gost3410: y bit is %d, want 0 or 1", yBit)
	}
	if size := (c.p.bits + 7) / 8; len(x) != size {
		return nil, fmt.Errorf("gost3410: compressed public key is %d bytes, want %d", len(x), size)
	}
	p := c.p.m.big()
	xInt := leInt(x)
	if xInt.Cmp(p) >= 0 {
		return nil, errors.New("gost3410: public key x is outside the field")
	}
	a, b := c.p.fromMont(&c.a), c.p.fromMont(&c.b)
	// y² = (x² + a)·x + b
	y2 := new(big.Int).Mul(xInt, xInt)
	y2.Add(y2, a.big()).Mul(y2, xInt).Add(y2, b.big()).Mod(y2, p)
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil, errors.New("gost3410: public key is not a point on the curve")
	}
	if y.Bit(0) != yBit {
		y.Sub(p, y)
	}
	return newPublicKey(c, xInt, y)
}

func newPublicKey(c *Curve, x, y *big.Int) (*PublicKey, error) {
	p := c.p.m.big()
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, errors.New("gost3410: public key coordinate is outside the field")
	}
	q, ok := c.affinePoint(x, y)
	if !ok {
		return nil, errors.New("gost3410: public key is not a point on the curve")
	}
	if inf := c.scalarMult(&q, &c.q.m); !inf.z.isZero() {
		return nil, errors.New("gost3410: public key is not in the subgroup of order q")
	}
	return &PublicKey{curve: c, q: q}, nil
}

// Sign signs hash with k using random, normally crypto/rand.Reader, for the
// per-signature secret. The hash is read as a little-endian integer and
// reduced modulo q, a zero result becoming 1; r and s are in [1, q-1].
func Sign(random io.Reader, k *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	c := k.pub.curve
	e := natFromBig(c.hashToScalar(hash))
	for {
		secret, err := randomScalar(c, random)
		if err != nil {
			return nil, nil, err
		}
		pt := c.scalarMult(&c.g, &secret)
		x, _ := c.affine(&pt)
		xr := c.q.toMont(&x) // reduces x modulo q
		xr = c.q.fromMont(&xr)
		if xr.isZero() {
			continue
		}
		rd := c.q.mul(&xr, &k.d)
		ke := c.q.mul(&secret, &e)
		sn := c.q.add(&rd, &ke)
		if !sn.isZero() {
			return xr.big(), sn.big(), nil
		}
	}
}

// Verify reports whether (r, s) is a valid signature of hash by k.
func Verify(k *PublicKey, hash []byte, r, s *big.Int) bool {
	c := k.curve
	q := c.order
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(q) >= 0 || s.Cmp(q) >= 0 {
		return false
	}
	v := new(big.Int).ModInverse(c.hashToScalar(hash), q)
	z1 := natFromBig(new(big.Int).Mod(new(big.Int).Mul(s, v), q))
	z2 := natFromBig(new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(r, v)), q))
	sg := c.scalarMult(&c.g, &z1)
	sq := c.scalarMult(&k.q, &z2)
	pt := c.add(&sg, &sq)
	if pt.z.isZero() {
		return false
	}
	x, _ := c.affine(&pt)
	return new(big.Int).Mod(x.big(), q).Cmp(r) == 0
}

// hashToScalar reads the hash as a little-endian integer modulo q; a zero
// result becomes 1.
func (c *Curve) hashToScalar(hash []byte) *big.Int {
	e := leInt(hash)
	if e.Mod(e, c.order).Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

// scalarFromBytes reads a big-endian integer of any length; ok reports
// whether it is in [1, q-1]. Neither the time nor the memory accesses depend
// on the value.
func scalarFromBytes(c *Curve, be []byte) (k nat, ok bool) {
	size := (c.q.bits + 7) / 8
	var extra byte // bytes above the byte length of q must be zero
	if len(be) > size {
		for _, b := range be[:len(be)-size] {
			extra |= b
		}
		be = be[len(be)-size:]
	}
	var buf [32]byte
	copy(buf[32-len(be):], be)
	k = natFromBE(&buf)

	var acc, borrow uint64
	for i := range k {
		acc |= k[i]
		_, borrow = bits.Sub64(k[i], c.q.m[i], borrow) // borrows out iff k < q
	}
	nonzero := (acc | -acc) >> 63
	return k, nonzero&borrow == 1 && extra == 0
}

// randomScalar draws an integer uniformly from [1, q-1] by rejection: the
// number of attempts does not depend on the accepted value.
func randomScalar(c *Curve, random io.Reader) (nat, error) {
	buf := make([]byte, (c.q.bits+7)/8)
	for {
		if _, err := io.ReadFull(random, buf); err != nil {
			return nat{}, fmt.Errorf("gost3410: read random: %w", err)
		}
		buf[0] &= 0xff >> (8*len(buf) - c.q.bits)
		if k, ok := scalarFromBytes(c, buf); ok {
			return k, nil
		}
	}
}

func leInt(le []byte) *big.Int {
	be := slices.Clone(le)
	slices.Reverse(be)
	return new(big.Int).SetBytes(be)
}

func leBytes(x *nat, size int) []byte {
	be := x.bytesBE()
	out := slices.Clone(be[32-size:])
	slices.Reverse(out)
	return out
}
