// Package dstu4145 implements the DSTU 4145-2002 elliptic curve digital
// signature over the ten named binary curves of the standard.
//
// The arithmetic, the point compression and the signature follow
// DSTU4145Signer and DSTU4145PointEncoder of Bouncy Castle, and the results
// interoperate with Bouncy Castle and the IIT library. Signatures are the
// values (r, s); MarshalSignature and ParseSignature convert them to and from
// r||s little-endian, the form of certificates, OCSP and CMS.
//
// The implementation uses math/big and is not constant-time: timing may leak
// private keys. It is meant for testing and interoperability, not for
// production keys.
package dstu4145

import (
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
	d   scalar
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
	k, ok := c.ord.fromBytes(d)
	if !ok {
		return nil, errors.New("dstu4145: private key out of range [1, n-1]")
	}
	return newPrivateKey(c, k), nil
}

func newPrivateKey(c *Curve, d scalar) *PrivateKey {
	return &PrivateKey{pub: PublicKey{curve: c, q: c.neg(c.scalarMult(c.g, &d))}, d: d}
}

// Curve returns the curve of k.
func (k *PublicKey) Curve() *Curve { return k.curve }

// Public returns the public key of k.
func (k *PrivateKey) Public() *PublicKey { return &k.pub }

// Bytes returns d as a big-endian integer padded to the byte length of n,
// the form NewPrivateKey accepts.
func (k *PrivateKey) Bytes() []byte {
	return k.pub.curve.ord.bytes(&k.d)
}

// Bytes returns the compressed point in the DSTU 4145 encoding: x as a
// big-endian field element whose lowest bit is replaced by Tr(y/x).
func (k *PublicKey) Bytes() []byte {
	f := &k.curve.f
	out := k.q.x.big().FillBytes(make([]byte, (f.m+7)/8))
	if k.q.x.isZero() {
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
	f := &c.f
	if size := (f.m + 7) / 8; len(data) != size {
		return nil, fmt.Errorf("dstu4145: public key is %d bytes, want %d", len(data), size)
	}
	xInt := new(big.Int).SetBytes(data)
	if xInt.BitLen() > f.m {
		return nil, errors.New("dstu4145: public key x is outside the field")
	}
	x := feFromBig(xInt)
	yTrace := uint64(data[len(data)-1] & 1)
	// the lowest bit carried Tr(y/x); restore it from Tr(x) = Tr(a), which holds for subgroup points
	if f.trace(x) != c.a {
		x = f.add(x, felem{1})
	}

	var y felem
	if x.isZero() {
		y = f.sqrt(c.b)
	} else {
		xInv := f.inv(x)
		beta := f.add(f.add(f.mul(f.sqr(xInv), c.b), felem{c.a}), x)
		z, ok := f.solveQuadratic(beta)
		if !ok {
			return nil, errors.New("dstu4145: public key is not a point on the curve")
		}
		if f.trace(z) != yTrace {
			z = f.add(z, felem{1})
		}
		y = f.mul(x, z)
	}

	q := point{x: x, y: y}
	if !c.isOnCurve(q) || !c.scalarMultVartime(q, c.n).inf {
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
		fe := c.scalarMult(c.g, &e).x
		if fe.isZero() {
			continue
		}
		r = truncate(c.f.mul(h, fe).big(), c.n.BitLen()-1) // below n, so a valid mulAdd operand
		if r.Sign() == 0 {
			continue
		}
		rs := scalarFromBig(r)
		ss := c.ord.mulAdd(&rs, &k.d, &e)
		if !c.ord.isZero(&ss) {
			return r, ss.big(), nil
		}
	}
}

// Verify reports whether (r, s) is a valid signature of hash by k.
func Verify(k *PublicKey, hash []byte, r, s *big.Int) bool {
	c := k.curve
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(c.n) >= 0 || s.Cmp(c.n) >= 0 {
		return false
	}
	R := c.add(c.scalarMultVartime(c.g, s), c.scalarMultVartime(k.q, r))
	if R.inf {
		return false
	}
	return truncate(c.f.mul(c.hashToField(hash), R.x).big(), c.n.BitLen()-1).Cmp(r) == 0
}

// MarshalSignature encodes (r, s) from Sign on curve c as r||s, each a
// little-endian integer padded to the byte length of the order n: the form
// Ukrainian CAs and the IIT library use in certificates, OCSP and CMS
// (64 bytes on M257). It panics if r or s does not fit that length.
func MarshalSignature(c *Curve, r, s *big.Int) []byte {
	size := (c.n.BitLen() + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	slices.Reverse(sig[:size])
	slices.Reverse(sig[size:])
	return sig
}

// ParseSignature decodes r||s little-endian (see MarshalSignature). It takes
// any non-empty even length and splits it in halves, so it also reads the
// signatures of the Bouncy Castle JCA provider, whose halves can carry an
// extra zero byte. Range checks are left to Verify.
func ParseSignature(sig []byte) (r, s *big.Int, err error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, nil, fmt.Errorf("dstu4145: signature is %d bytes, want an even non-zero length", len(sig))
	}
	be := slices.Clone(sig)
	slices.Reverse(be) // now s||r big-endian
	half := len(be) / 2
	return new(big.Int).SetBytes(be[half:]), new(big.Int).SetBytes(be[:half]), nil
}

// hashToField reads the hash as a little-endian integer truncated to m bits;
// a zero result becomes 1.
func (c *Curve) hashToField(hash []byte) felem {
	be := slices.Clone(hash)
	slices.Reverse(be)
	h := truncate(new(big.Int).SetBytes(be), c.f.m)
	if h.Sign() == 0 {
		h.SetInt64(1)
	}
	return feFromBig(h)
}

// truncate keeps the low bits of x.
func truncate(x *big.Int, bits int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return mask.Sub(mask, big.NewInt(1)).And(mask, x)
}
