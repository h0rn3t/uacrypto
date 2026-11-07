// Package dstu4145 implements the DSTU 4145-2002 elliptic curve digital
// signature over the ten named binary curves of the standard.
//
// The arithmetic, the point compression and the signature follow
// DSTU4145Signer and DSTU4145PointEncoder of Bouncy Castle, and the results
// interoperate with Bouncy Castle and the IIT library. Signatures are the
// values (r, s); MarshalSignature and ParseSignature convert them to and from
// r||s little-endian, the form of certificates, OCSP and CMS.
// PrivateKey.ECDH is the cofactor Diffie–Hellman key agreement of Ukrainian
// CMS enveloped data.
//
// GenerateKey, NewPrivateKey, PrivateKey.Bytes, Sign and ECDH run in constant time
// with respect to the private key and the per-signature secret on 64-bit
// platforms: the field arithmetic uses fixed 64-bit limbs, secret scalars go
// through a Montgomery ladder, and arithmetic modulo n has no secret-dependent
// branches or memory accesses. This is checked by a statistical timing test
// (internal/ctcheck) on linux/amd64; 32-bit builds are correct but make no
// such claim. Verify, ParsePublicKey, PublicKey.Bytes and CurveFromParams
// handle public data only and are not constant-time. Power and fault attacks
// are out of scope, and the package has not been audited.
//
// PrivateKey.Destroy overwrites the private scalar. Copies the Go runtime made
// earlier (a moved stack, a value copy of the key) are beyond its reach; built
// with GOEXPERIMENT=runtimesecret, GenerateKey, NewPrivateKey, Sign and ECDH
// run under runtime/secret, which erases their registers, stack and temporary
// allocations on linux/amd64 and linux/arm64.
//
// NewPRNG is the pseudorandom generator of the certified cryptonite library,
// built on GOST 28147-89, for callers that must use it instead of
// crypto/rand.Reader.
package dstu4145

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/h0rn3t/uacrypto/internal/erase"
)

// A PublicKey is a DSTU 4145 public key Q = -dG on a named curve.
type PublicKey struct {
	curve *Curve
	q     point
}

// ErrKeyDestroyed is returned by Sign and ECDH for a key after Destroy.
var ErrKeyDestroyed = errors.New("dstu4145: private key destroyed")

// A PrivateKey is a DSTU 4145 private key d with its public key.
type PrivateKey struct {
	pub PublicKey
	d   scalar
}

// GenerateKey returns a new key on curve c with d drawn uniformly from
// [1, n-1] using random, normally crypto/rand.Reader.
func GenerateKey(c *Curve, random io.Reader) (k *PrivateKey, err error) {
	erase.Do(func() {
		var d scalar
		if d, err = randomScalar(c, random); err == nil {
			k = newPrivateKey(c, d)
		}
	})
	return k, err
}

// NewPrivateKey returns the key on curve c with the big-endian scalar d,
// which must be in [1, n-1].
func NewPrivateKey(c *Curve, d []byte) (k *PrivateKey, err error) {
	erase.Do(func() {
		s, ok := c.ord.fromBytes(d)
		if !ok {
			err = errors.New("dstu4145: private key out of range [1, n-1]")
			return
		}
		k = newPrivateKey(c, s)
	})
	return k, err
}

func newPrivateKey(c *Curve, d scalar) *PrivateKey {
	return &PrivateKey{pub: PublicKey{curve: c, q: c.neg(c.scalarMult(c.g, &d))}, d: d}
}

// Curve returns the curve of k.
func (k *PublicKey) Curve() *Curve { return k.curve }

// Public returns the public key of k.
func (k *PrivateKey) Public() *PublicKey { return &k.pub }

// Bytes returns d as a big-endian integer padded to the byte length of n,
// the form NewPrivateKey accepts. It panics after Destroy.
func (k *PrivateKey) Bytes() []byte {
	if k.destroyed() {
		panic(ErrKeyDestroyed)
	}
	return k.pub.curve.ord.bytes(&k.d)
}

// Destroy overwrites the private scalar d with zeros. Afterwards Sign and ECDH
// return ErrKeyDestroyed, Bytes panics, and Public still works. It does not
// reach copies of the key: a PrivateKey copied by value, the bytes Bytes
// returned, or a key file the key came from.
func (k *PrivateKey) Destroy() { clear(k.d[:]) }

// destroyed reports whether Destroy was called: a valid d is never zero.
func (k *PrivateKey) destroyed() bool { return k.d == scalar{} }

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
	if k.destroyed() {
		return nil, nil, ErrKeyDestroyed
	}
	erase.Do(func() { r, s, err = sign(random, k, hash) })
	return r, s, err
}

func sign(random io.Reader, k *PrivateKey, hash []byte) (r, s *big.Int, err error) {
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
