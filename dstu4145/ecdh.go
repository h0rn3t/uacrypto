package dstu4145

import (
	"errors"
	"math/big"

	"github.com/h0rn3t/uacrypto/internal/erase"
)

// ECDH returns the x coordinate of h·d·Q, the cofactor Diffie–Hellman shared
// secret of k and remote, big-endian over the byte length of the field: the
// key agreement of Ukrainian CMS enveloped data
// (dhSinglePass-cofactorDH-gost34311kdf), as the certified cryptonite library
// computes it. Both keys must be on the same curve; remote is in the subgroup
// of order n, as ParsePublicKey and GenerateKey guarantee, so the result is
// never the point at infinity.
func (k *PrivateKey) ECDH(remote *PublicKey) (secret []byte, err error) {
	c := k.pub.curve
	if remote == nil || remote.curve != c {
		return nil, errors.New("dstu4145: ECDH with a key on another curve")
	}
	if k.destroyed() {
		return nil, ErrKeyDestroyed
	}
	erase.Do(func() { secret = k.ecdh(remote) })
	return secret, nil
}

func (k *PrivateKey) ecdh(remote *PublicKey) []byte {
	c := k.pub.curve
	// h·d mod n is in [1, n-1]: n is prime and larger than h, and d is not 0.
	h := scalarFromBig(c.cofactor())
	var zero scalar
	hd := c.ord.mulAdd(&h, &k.d, &zero)
	z := c.scalarMult(remote.q, &hd)
	clear(hd[:])
	return z.x.bytes((c.f.m + 7) / 8)
}

// bytes returns a big-endian over n bytes straight from the limbs, without
// math/big, whose allocations depend on the value.
func (a felem) bytes(n int) []byte {
	out := make([]byte, n)
	for i := range n {
		bit := 8 * (n - 1 - i)
		out[i] = byte(a[bit/64] >> (bit % 64)) //nolint:gosec // G115: keeps the low byte by design
	}
	return out
}

// cofactor returns h = #E/n, which for the curves of DSTU 4145 is the nearest
// integer to 2^m/n: |#E - 2^m - 1| ≤ 2·2^(m/2) is far below n/2.
func (c *Curve) cofactor() *big.Int {
	twoM := new(big.Int).Lsh(big.NewInt(1), uint(c.f.m))
	twoM.Add(twoM, new(big.Int).Rsh(c.n, 1))
	return twoM.Quo(twoM, c.n)
}
