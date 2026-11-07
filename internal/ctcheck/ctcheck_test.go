//go:build ctcheck

package ctcheck

import (
	"crypto/cipher"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/kalyna"
	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/strumok"
)

// samples per test; Task 6 tunes it so the package fits about five minutes
// on ubuntu-latest.
const samples = 100_000

func check(t *testing.T, r Result) {
	t.Helper()
	t.Logf("|t| = %.2f, samples = %d, batch = %d", r.T, r.Samples, r.Batch)
	if r.T > Threshold {
		t.Fatalf("timing leak: |t| = %.2f > %d", r.T, Threshold)
	}
}

// secret returns n bytes: zeros for class 0, random for class 1.
func secret(class, n int) []byte {
	b := make([]byte, n)
	if class == 1 {
		rand.Read(b)
	}
	return b
}

// fixedReader yields the same bytes on every read of its length, so that
// dstu4145.Sign draws the same nonce e in every call of a batch.
type fixedReader []byte

func (r fixedReader) Read(p []byte) (int, error) { return copy(p, r), nil }

// m257 returns the curve M257 and the byte length of its order n.
func m257(t *testing.T) (*dstu4145.Curve, int) {
	t.Helper()
	c, err := dstu4145.NamedCurve(dstu4145.M257)
	if err != nil {
		t.Fatalf("NamedCurve(M257) error = %v", err)
	}
	return c, (c.Order().BitLen() + 7) / 8
}

// scalar returns a big-endian scalar of size bytes: 1 for class 0, uniform
// in [1, n-1] for class 1.
func scalar(c *dstu4145.Curve, size, class int) []byte {
	if class == 0 {
		return new(big.Int).SetInt64(1).FillBytes(make([]byte, size))
	}
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(c.Order(), big.NewInt(1)))
	if err != nil {
		panic(err)
	}
	return k.Add(k, big.NewInt(1)).FillBytes(make([]byte, size))
}

func privateKey(c *dstu4145.Curve, d []byte) *dstu4145.PrivateKey {
	k, err := dstu4145.NewPrivateKey(c, d)
	if err != nil {
		panic(err)
	}
	return k
}

func TestNegativeControl(t *testing.T) {
	mod := new(big.Int).SetBytes(secret(1, 32))
	mod.SetBit(mod, 255, 1).SetBit(mod, 0, 1)
	base := new(big.Int).SetBytes(secret(1, 32))
	base.Mod(base, mod)
	r := Run(samples,
		func(class int) *big.Int {
			if class == 0 {
				return big.NewInt(1)
			}
			return new(big.Int).SetBytes(secret(1, 32))
		},
		func(k *big.Int) { new(big.Int).Exp(base, k, mod) })
	t.Logf("|t| = %.2f, samples = %d, batch = %d", r.T, r.Samples, r.Batch)
	if r.T <= Threshold {
		t.Fatalf("harness insensitive on this machine: |t| = %.1f", r.T)
	}
}

func TestDSTU4145NewPrivateKey(t *testing.T) {
	c, size := m257(t)
	check(t, Run(samples,
		func(class int) []byte { return scalar(c, size, class) },
		func(d []byte) {
			if _, err := dstu4145.NewPrivateKey(c, d); err != nil {
				panic(err)
			}
		}))
}

func TestDSTU4145SignKey(t *testing.T) {
	c, size := m257(t)
	hash := secret(1, 32)
	check(t, Run(samples,
		func(class int) *dstu4145.PrivateKey { return privateKey(c, scalar(c, size, class)) },
		func(k *dstu4145.PrivateKey) {
			if _, _, err := dstu4145.Sign(rand.Reader, k, hash); err != nil {
				panic(err)
			}
		}))
}

func TestDSTU4145SignNonce(t *testing.T) {
	c, size := m257(t)
	k := privateKey(c, scalar(c, size, 1))
	hash := secret(1, 32)
	check(t, Run(samples,
		func(class int) fixedReader { return scalar(c, size, class) },
		func(e fixedReader) {
			if _, _, err := dstu4145.Sign(e, k, hash); err != nil {
				panic(err)
			}
		}))
}

type blockInput struct {
	b        cipher.Block
	src, dst []byte
}

func kalyna128(class int) blockInput {
	b, err := kalyna.NewCipher128(secret(class, 16))
	if err != nil {
		panic(err)
	}
	return blockInput{b: b, src: secret(class, 16), dst: make([]byte, 16)}
}

func TestKalyna128Encrypt(t *testing.T) {
	check(t, Run(samples, kalyna128, func(in blockInput) { in.b.Encrypt(in.dst, in.src) }))
}

func TestKalyna128Decrypt(t *testing.T) {
	check(t, Run(samples, kalyna128, func(in blockInput) { in.b.Decrypt(in.dst, in.src) }))
}

func TestKalyna128KeySchedule(t *testing.T) {
	check(t, Run(samples,
		func(class int) []byte { return secret(class, 16) },
		func(key []byte) {
			if _, err := kalyna.NewCipher128(key); err != nil {
				panic(err)
			}
		}))
}

func TestKupyna256(t *testing.T) {
	check(t, Run(samples,
		func(class int) []byte { return secret(class, 64) },
		func(data []byte) { kupyna.Sum256(data) }))
}

func TestGOST28147Encrypt(t *testing.T) {
	sbox := gost28147.DKE1()
	check(t, Run(samples,
		func(class int) blockInput {
			b, err := gost28147.NewCipher(secret(class, gost28147.KeySize), sbox)
			if err != nil {
				panic(err)
			}
			return blockInput{b: b, src: secret(class, gost28147.BlockSize), dst: make([]byte, gost28147.BlockSize)}
		},
		func(in blockInput) { in.b.Encrypt(in.dst, in.src) }))
}

// TestStrumok256 times the key setup and the first two keystream blocks of
// the generator under a secret key.
func TestStrumok256(t *testing.T) {
	iv, buf := make([]byte, strumok.IVSize), make([]byte, 256)
	check(t, Run(samples,
		func(class int) []byte { return secret(class, strumok.KeySize256) },
		func(key []byte) {
			s, err := strumok.NewCipher(key, iv)
			if err != nil {
				panic(err)
			}
			s.XORKeyStream(buf, buf)
		}))
}

// kalynaMode is a keyed Kalyna-128 with a secret message for the mode tests.
type kalynaMode struct {
	b    cipher.Block
	data []byte
}

func kalyna128Mode(class int) kalynaMode {
	return kalynaMode{b: kalyna128(class).b, data: secret(class, 64)}
}

// TestKalyna128GMAC times the multiplications in GF(2^128) by the secret H.
func TestKalyna128GMAC(t *testing.T) {
	check(t, Run(samples, kalyna128Mode, func(in kalynaMode) {
		if _, err := kalyna.GMAC(in.b, in.data, 16); err != nil {
			panic(err)
		}
	}))
}

func TestKalyna128CMAC(t *testing.T) {
	check(t, Run(samples, kalyna128Mode, func(in kalynaMode) {
		if _, err := kalyna.CMAC(in.b, in.data, 16); err != nil {
			panic(err)
		}
	}))
}

// TestKalyna128XTS times the tweak doubling under a secret key and tweak.
func TestKalyna128XTS(t *testing.T) {
	check(t, Run(samples, kalyna128Mode, func(in kalynaMode) {
		x, err := kalyna.NewXTS(in.b)
		if err != nil {
			panic(err)
		}
		if _, err := x.Encrypt(in.data[:16], in.data); err != nil {
			panic(err)
		}
	}))
}

// TestKalyna128GCMOpenForgery times rejecting a tag wrong in its first byte
// against one wrong in its last byte.
func TestKalyna128GCMOpenForgery(t *testing.T) {
	g, err := kalyna.NewGCM(kalyna128(1).b, 16)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 16)
	sealed, err := g.Seal(nonce, make([]byte, 64), nil)
	if err != nil {
		panic(err)
	}
	check(t, Run(samples,
		func(class int) []byte {
			forged := append([]byte(nil), sealed...)
			forged[len(forged)-16+class*15] ^= 1
			return forged
		},
		func(forged []byte) {
			if _, err := g.Open(nonce, forged, nil); err == nil {
				panic("forged tag accepted")
			}
		}))
}

// TestKalyna128Unwrap times unwrapping a secret 32-byte key, whose last
// bytes Unwrap compares against every padding.
func TestKalyna128Unwrap(t *testing.T) {
	b := kalyna128(1).b
	check(t, Run(samples,
		func(class int) []byte {
			wrapped, err := kalyna.Wrap(b, secret(class, 32))
			if err != nil {
				panic(err)
			}
			return wrapped
		},
		func(wrapped []byte) {
			if _, err := kalyna.Unwrap(b, wrapped); err != nil {
				panic(err)
			}
		}))
}

func TestKalyna128CCM(t *testing.T) {
	check(t, Run(samples, kalyna128Mode, func(in kalynaMode) {
		c, err := kalyna.NewCCM(in.b, 8, 16)
		if err != nil {
			panic(err)
		}
		if _, err := c.Seal(in.data[:16], in.data, in.data[16:32]); err != nil {
			panic(err)
		}
	}))
}
