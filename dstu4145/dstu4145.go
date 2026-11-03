// Package dstu4145 implements the DSTU 4145-2002 elliptic curve digital
// signature over the ten named binary curves of the standard.
//
// The arithmetic, the point compression and the signature follow
// DSTU4145Signer and DSTU4145PointEncoder of Bouncy Castle, and the results
// interoperate with Bouncy Castle and the IIT library. The package works with
// signature values (r, s) and the compressed public key only; how they are
// packed into certificates and CMS (for example r||s little-endian) is left to
// the caller.
//
// The implementation uses math/big and is not constant-time: timing may leak
// private keys. It is meant for testing and interoperability, not for
// production keys.
package dstu4145

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
)

// A PublicKey is a DSTU 4145 public key Q = -dG on a named curve.
type PublicKey struct {
	curve *Curve
	q     point
}

// A PrivateKey is a DSTU 4145 private key d with its public key.
type PrivateKey struct {
	pub PublicKey
	d   *big.Int
}

// GenerateKey returns a new key on curve c with d drawn uniformly from
// [1, n-1] using random, normally crypto/rand.Reader.
func GenerateKey(c *Curve, random io.Reader) (*PrivateKey, error) {
	d, err := randomScalar(c, random)
	if err != nil {
		return nil, err
	}
	return newPrivateKey(c, d), nil
}

// NewPrivateKey returns the key on curve c with the big-endian scalar d,
// which must be in [1, n-1].
func NewPrivateKey(c *Curve, d []byte) (*PrivateKey, error) {
	k := new(big.Int).SetBytes(d)
	if k.Sign() == 0 || k.Cmp(c.n) >= 0 {
		return nil, errors.New("dstu4145: private key out of range [1, n-1]")
	}
	return newPrivateKey(c, k), nil
}

func newPrivateKey(c *Curve, d *big.Int) *PrivateKey {
	return &PrivateKey{pub: PublicKey{curve: c, q: c.neg(c.scalarMult(c.g, d))}, d: d}
}

// randomScalar draws an integer uniformly from [1, n-1].
func randomScalar(c *Curve, random io.Reader) (*big.Int, error) {
	k, err := rand.Int(random, new(big.Int).Sub(c.n, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("dstu4145: read random: %w", err)
	}
	return k.Add(k, big.NewInt(1)), nil
}

// Public returns the public key of k.
func (k *PrivateKey) Public() *PublicKey { return &k.pub }

// Bytes returns d as a big-endian integer padded to the byte length of n,
// the form NewPrivateKey accepts.
func (k *PrivateKey) Bytes() []byte {
	return k.d.FillBytes(make([]byte, (k.pub.curve.n.BitLen()+7)/8))
}

// Bytes returns the compressed point in the DSTU 4145 encoding: x as a
// big-endian field element whose lowest bit is replaced by Tr(y/x).
func (k *PublicKey) Bytes() []byte {
	f := k.curve.f
	out := k.q.x.FillBytes(make([]byte, (f.m+7)/8))
	if k.q.x.Sign() == 0 {
		return out
	}
	out[len(out)-1] &^= 1
	if f.trace(f.mul(k.q.y, f.inv(k.q.x))) == 1 {
		out[len(out)-1] |= 1
	}
	return out
}

// ParsePublicKey decodes a compressed point in the DSTU 4145 encoding (see
// PublicKey.Bytes). It fails unless the point lies on curve c in the subgroup
// of order n.
func ParsePublicKey(c *Curve, data []byte) (*PublicKey, error) {
	f := c.f
	if size := (f.m + 7) / 8; len(data) != size {
		return nil, fmt.Errorf("dstu4145: public key is %d bytes, want %d", len(data), size)
	}
	x := new(big.Int).SetBytes(data)
	if x.BitLen() > f.m {
		return nil, errors.New("dstu4145: public key x is outside the field")
	}
	yTrace := uint(data[len(data)-1] & 1)
	// the lowest bit carried Tr(y/x); restore it from Tr(x) = Tr(a), which holds for subgroup points
	if f.trace(x) != c.a.Bit(0) {
		x = f.addOne(x)
	}

	var y *big.Int
	if x.Sign() == 0 {
		y = f.sqrt(c.b)
	} else {
		xInv := f.inv(x)
		beta := f.add(f.add(f.mul(f.sqr(xInv), c.b), c.a), x)
		z, ok := f.solveQuadratic(beta)
		if !ok {
			return nil, errors.New("dstu4145: public key is not a point on the curve")
		}
		if f.trace(z) != yTrace {
			z = f.addOne(z)
		}
		y = f.mul(x, z)
	}

	q := point{x, y}
	if !c.isOnCurve(q) || !c.scalarMult(q, c.n).isInfinity() {
		return nil, errors.New("dstu4145: public key is not in the subgroup of order n")
	}
	return &PublicKey{curve: c, q: q}, nil
}

// Sign signs hash with k using random, normally crypto/rand.Reader, for the
// per-signature secret. The hash is read as a little-endian integer, as
// DSTU 4145 prescribes for GOST 34.311 digests; r and s are in [1, n-1].
func Sign(random io.Reader, k *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	c := k.pub.curve
	h := c.hashToField(hash)
	for {
		e, err := randomScalar(c, random)
		if err != nil {
			return nil, nil, err
		}
		fe := c.scalarMult(c.g, e).x
		if fe.Sign() == 0 {
			continue
		}
		r = truncate(c.f.mul(h, fe), c.n.BitLen()-1)
		if r.Sign() == 0 {
			continue
		}
		s = new(big.Int).Mul(r, k.d)
		s.Add(s, e).Mod(s, c.n)
		if s.Sign() != 0 {
			return r, s, nil
		}
	}
}

// Verify reports whether (r, s) is a valid signature of hash by k.
func Verify(k *PublicKey, hash []byte, r, s *big.Int) bool {
	c := k.curve
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(c.n) >= 0 || s.Cmp(c.n) >= 0 {
		return false
	}
	R := c.add(c.scalarMult(c.g, s), c.scalarMult(k.q, r))
	if R.isInfinity() {
		return false
	}
	return truncate(c.f.mul(c.hashToField(hash), R.x), c.n.BitLen()-1).Cmp(r) == 0
}

// hashToField reads the hash as a little-endian integer truncated to m bits;
// a zero result becomes 1.
func (c *Curve) hashToField(hash []byte) *big.Int {
	be := slices.Clone(hash)
	slices.Reverse(be)
	h := truncate(new(big.Int).SetBytes(be), c.f.m)
	if h.Sign() == 0 {
		h.SetInt64(1)
	}
	return h
}

// truncate keeps the low bits of x.
func truncate(x *big.Int, bits int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return mask.Sub(mask, big.NewInt(1)).And(mask, x)
}
