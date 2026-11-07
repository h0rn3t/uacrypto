package gost3410

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"
)

func mustInt(t testing.TB, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("SetString(%q, 16) failed", s)
	}
	return v
}

// le returns the big-endian hex s as little-endian bytes.
func le(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", s, err)
	}
	slices.Reverse(b)
	return b
}

// testParams are GOST3410_PARAMS_ID_1 of cryptonite: the test curve of
// GOST R 34.10-2001, appendix A (RFC 5832, section 7.1).
func testParams(t testing.TB) CurveParams {
	return CurveParams{
		P: mustInt(t, "8000000000000000000000000000000000000000000000000000000000000431"),
		A: big.NewInt(7),
		B: mustInt(t, "5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e"),
		Q: mustInt(t, "8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3"),
		X: big.NewInt(2),
		Y: mustInt(t, "08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"),
	}
}

// cryptoProAParams are GOST3410_PARAMS_ID_2 of cryptonite (the CryptoPro-A
// curve of RFC 4357), used only because cryptonite's vectors are on it.
func cryptoProAParams(t testing.TB) CurveParams {
	return CurveParams{
		P: mustInt(t, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"),
		A: mustInt(t, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"),
		B: big.NewInt(0xa6),
		Q: mustInt(t, "ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"),
		X: big.NewInt(1),
		Y: mustInt(t, "8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"),
	}
}

func mustCurve(t testing.TB, p CurveParams) *Curve {
	t.Helper()
	c, err := NewCurve(p)
	if err != nil {
		t.Fatalf("NewCurve() error = %v", err)
	}
	return c
}

// Appendix A of GOST R 34.10-2001 (RFC 5832, section 7.1); cryptonite's
// utest_get_pubkey and utest_verify use the same key, digest and signature.
const (
	exampleD  = "7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28"
	exampleQx = "7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b"
	exampleQy = "26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da"
	exampleE  = "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5"
	exampleK  = "77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3"
	exampleR  = "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
	exampleS  = "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40"
)

func TestStandardExample(t *testing.T) {
	c := mustCurve(t, testParams(t))
	priv, err := NewPrivateKey(c, mustInt(t, exampleD).Bytes())
	if err != nil {
		t.Fatalf("NewPrivateKey(%s) error = %v", exampleD, err)
	}
	wantQ := append(le(t, exampleQx), le(t, exampleQy)...)
	if got := priv.Public().Bytes(); !bytes.Equal(got, wantQ) {
		t.Errorf("Public().Bytes() = %x, want %x", got, wantQ)
	}

	// The digest is the integer e of the example; Sign and Verify read it
	// little-endian, as cryptonite does.
	hash := le(t, exampleE)
	r, s, err := Sign(bytes.NewReader(mustInt(t, exampleK).Bytes()), priv, hash)
	if err != nil {
		t.Fatalf("Sign(k = %s) error = %v", exampleK, err)
	}
	if want := mustInt(t, exampleR); r.Cmp(want) != 0 {
		t.Errorf("Sign(k = %s) r = %x, want %x", exampleK, r, want)
	}
	if want := mustInt(t, exampleS); s.Cmp(want) != 0 {
		t.Errorf("Sign(k = %s) s = %x, want %x", exampleK, s, want)
	}

	pub, err := ParsePublicKey(c, wantQ)
	if err != nil {
		t.Fatalf("ParsePublicKey(%x) error = %v", wantQ, err)
	}
	r, s = mustInt(t, exampleR), mustInt(t, exampleS)
	if !Verify(pub, hash, r, s) {
		t.Errorf("Verify(example) = false, want true")
	}

	q := c.Order()
	for _, tt := range []struct {
		name string
		hash []byte
		r, s *big.Int
	}{
		{"other hash", le(t, exampleD), r, s},
		{"r+1", hash, new(big.Int).Add(r, big.NewInt(1)), s},
		{"s+1", hash, r, new(big.Int).Add(s, big.NewInt(1))},
		{"r = 0", hash, new(big.Int), s},
		{"s = 0", hash, r, new(big.Int)},
		{"r + q", hash, new(big.Int).Add(r, q), s},
		{"s + q", hash, r, new(big.Int).Add(s, q)},
	} {
		if Verify(pub, tt.hash, tt.r, tt.s) {
			t.Errorf("Verify(%s) = true, want false", tt.name)
		}
	}
}

// cryptoniteD and the expected point come from utest_compress_decompress_pubkey
// of cryptonite on GOST3410_PARAMS_ID_2.
const (
	cryptoniteD  = "066e675eb37ae3c5736ce765824d6a8b6caa5a489f4eea270767a54d62c971"
	cryptoniteQx = "fd34f62c82383114eac490934633e176c95eeda0b810cf952a38c831a58fb7bb"
	cryptoniteQy = "b433a27a21b327f666a398e270f79d0706413c895851c6bb00eb383e18c38c77"
	// cryptoniteHash is the digest of utest_sign_verify, given there as
	// little-endian hex 719BD041…AA97 5F.
	cryptoniteHash = "5f97afaa2449f81c681d95d966927168929bda0a50f9e7ca338ab69441d09b71"
)

func TestCryptoniteKeyAndCompression(t *testing.T) {
	c := mustCurve(t, cryptoProAParams(t))
	priv, err := NewPrivateKey(c, mustInt(t, cryptoniteD).Bytes())
	if err != nil {
		t.Fatalf("NewPrivateKey(%s) error = %v", cryptoniteD, err)
	}
	wantQ := append(le(t, cryptoniteQx), le(t, cryptoniteQy)...)
	if got := priv.Public().Bytes(); !bytes.Equal(got, wantQ) {
		t.Errorf("Public().Bytes() = %x, want %x", got, wantQ)
	}

	x, yBit := priv.Public().Compress()
	if want := le(t, cryptoniteQx); !bytes.Equal(x, want) || yBit != 1 {
		t.Errorf("Compress() = %x, %d, want %x, 1", x, yBit, want)
	}
	pub, err := DecompressPublicKey(c, x, yBit)
	if err != nil {
		t.Fatalf("DecompressPublicKey(%x, %d) error = %v", x, yBit, err)
	}
	if got := pub.Bytes(); !bytes.Equal(got, wantQ) {
		t.Errorf("DecompressPublicKey(%x, %d).Bytes() = %x, want %x", x, yBit, got, wantQ)
	}
	other, err := DecompressPublicKey(c, x, 0)
	if err != nil {
		t.Fatalf("DecompressPublicKey(%x, 0) error = %v", x, err)
	}
	if bytes.Equal(other.Bytes(), wantQ) {
		t.Errorf("DecompressPublicKey(%x, 0) = DecompressPublicKey(%x, 1), want the negated point", x, x)
	}
	if _, err := DecompressPublicKey(c, x, 2); err == nil {
		t.Errorf("DecompressPublicKey(%x, 2) error = nil, want an error", x)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	c := mustCurve(t, cryptoProAParams(t))
	priv, err := NewPrivateKey(c, mustInt(t, cryptoniteD).Bytes())
	if err != nil {
		t.Fatalf("NewPrivateKey(%s) error = %v", cryptoniteD, err)
	}
	hash := le(t, cryptoniteHash)
	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	pub, err := ParsePublicKey(c, priv.Public().Bytes())
	if err != nil {
		t.Fatalf("ParsePublicKey(Public().Bytes()) error = %v", err)
	}
	if !Verify(pub, hash, r, s) {
		t.Errorf("Verify(Sign()) = false, want true")
	}

	gen, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if Verify(gen.Public(), hash, r, s) {
		t.Errorf("Verify(another key) = true, want false")
	}
	again, err := NewPrivateKey(c, gen.Bytes())
	if err != nil {
		t.Fatalf("NewPrivateKey(GenerateKey().Bytes()) error = %v", err)
	}
	if !bytes.Equal(again.Public().Bytes(), gen.Public().Bytes()) {
		t.Errorf("NewPrivateKey(k.Bytes()).Public() differs from k.Public()")
	}
}

func TestZeroHash(t *testing.T) {
	// A digest that is 0 modulo q signs as e = 1 (GOST R 34.10-2001, 6.1 step 2).
	c := mustCurve(t, testParams(t))
	priv, err := NewPrivateKey(c, mustInt(t, exampleD).Bytes())
	if err != nil {
		t.Fatalf("NewPrivateKey(%s) error = %v", exampleD, err)
	}
	r, s, err := Sign(rand.Reader, priv, make([]byte, 32))
	if err != nil {
		t.Fatalf("Sign(zero hash) error = %v", err)
	}
	if !Verify(priv.Public(), []byte{1}, r, s) {
		t.Errorf("Verify(hash 1, Sign(zero hash)) = false, want true")
	}
}

func TestNewPrivateKeyRange(t *testing.T) {
	c := mustCurve(t, testParams(t))
	q := c.Order()
	for _, d := range [][]byte{
		nil,
		{0},
		q.Bytes(),
		new(big.Int).Add(q, big.NewInt(1)).Bytes(),
		append([]byte{1}, make([]byte, 32)...),
	} {
		if _, err := NewPrivateKey(c, d); err == nil {
			t.Errorf("NewPrivateKey(%x) error = nil, want an error", d)
		}
	}
	d := new(big.Int).Sub(q, big.NewInt(1)).Bytes()
	if _, err := NewPrivateKey(c, d); err != nil {
		t.Errorf("NewPrivateKey(q-1) error = %v, want nil", err)
	}
}

func TestParsePublicKeyRejects(t *testing.T) {
	c := mustCurve(t, testParams(t))
	good := append(le(t, exampleQx), le(t, exampleQy)...)
	offCurve := slices.Clone(good)
	offCurve[0] ^= 1
	pLE := le(t, "8000000000000000000000000000000000000000000000000000000000000431")
	outside := append(slices.Clone(pLE), good[32:]...)
	for name, data := range map[string][]byte{
		"short":     good[:63],
		"long":      append(slices.Clone(good), 0),
		"off curve": offCurve,
		"x = p":     outside,
		"zero":      make([]byte, 64),
	} {
		if _, err := ParsePublicKey(c, data); err == nil {
			t.Errorf("ParsePublicKey(%s) error = nil, want an error", name)
		}
	}
}

func TestNewCurveRejects(t *testing.T) {
	for name, edit := range map[string]func(*CurveParams){
		"base point off curve": func(p *CurveParams) { p.Y = big.NewInt(1) },
		"wrong order":          func(p *CurveParams) { p.Q = new(big.Int).Add(p.Q, big.NewInt(2)) },
		"composite p":          func(p *CurveParams) { p.P = new(big.Int).Add(p.P, big.NewInt(2)) },
		"p over 256 bits":      func(p *CurveParams) { p.P = new(big.Int).Lsh(p.P, 1) },
		"nil b":                func(p *CurveParams) { p.B = nil },
	} {
		p := testParams(t)
		edit(&p)
		if _, err := NewCurve(p); err == nil {
			t.Errorf("NewCurve(%s) error = nil, want an error", name)
		}
	}
}
