package dstu4145

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"slices"
	"strconv"
	"testing"

	"github.com/h0rn3t/uacrypto/gost34311"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", s, err)
	}
	return b
}

func mustInt(t testing.TB, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("SetString(%q, 16) failed", s)
	}
	return v
}

func mustCurve(t testing.TB, id int) *Curve {
	t.Helper()
	c, err := NamedCurve(id)
	if err != nil {
		t.Fatalf("NamedCurve(%d) error = %v", id, err)
	}
	return c
}

// bcHash is GOST 34.311-95 of "abc"; it is longer than the field of curves 0..5,
// so those vectors also pin the truncation of the hash to the field size.
const bcHash = "a34a53504d8ba070cb73a583146167a0a3c226d793440d9cea24465fe02251f2"

// bcVectors come from Bouncy Castle 1.86: Q = -dG encoded with DSTU4145PointEncoder,
// (r, s) from DSTU4145Signer over bcHash.
var bcVectors = []struct {
	curve      int
	d, q, r, s string
}{
	{0, "10ac288b90ede2e311b02376bca7c702fb62a27bb", "032aa6658233f4971ddacd8d98382d1772beb5096a", "28f4de65f55dc83187b8b503c2984175279c9f724", "27d942ef846ec8d57987e429cb377259cbbd85f5c"},
	{1, "c11e1dbe57eaf77b1212cf30e4fef9470f96fa7", "15c9bff9fe7179fe6e95a43e7114d8da06e4cd3556", "979adfba838d0c3ad7dc104bb62f7fba8ccd152be", "13669370c0d02ad40dbb65314610ee5b2bcb521055"},
	{2, "52bd745088a8ff006e90b03a3b5c2b7325c757ca8d5", "1de5c8e61d81321882cdc264fade34cb581866c6aff7", "6e354b0dbb3ffa15a867e99e8964443fc12dd3f209b", "7452ca2afd75a9e7c24d55bc3e119252d892004e6ee"},
	{3, "fe68e1b24170dec61aef19998d83adf835e60625e0da", "078084efd6f8c27454af714b86c0f78f927950412a0241", "db85853062e1fcce84f9215bd67c06d9531f9b214780", "172c40ac9d9ea3a3ba7e9e2fbbfa5023e1bc17f905a55"},
	{4, "28cc0d5b97af98dda3e7c044d8f2ba34a101c80784f4f06e", "4cd0f1f9e694dadd7b429c5151ea105b860cb6ca18ae9cf6", "1cefcd5c27d36f64179bb51bf46d5a5ce27629508dea39ba", "31994e31cb5360c24c7d3b956a1901953f547e92724b1586"},
	{5, "b0fe29c22c7a027885f59f735ad1ec929aaf227e41743787299c67770a", "0059c46b0dff8fc828b97472f4ce30dfbd8b60136105ee76a56f5217cab5", "e2e25a2a443068ae4fe09aced4fa7798d36a6cd09db2ed25a59d4e4aa5", "10aa85a182b53d1811acc0f9f1de7c263b61517a46ac914796fa5250de"},
	{6, "24107926854fddcd4dbb7bc5ff787a6b82ee4d2f0722a4e3cdfca0cbffc45eaf", "004e8a31153932ff21578612dcdbc9f8bf2cf88563cfb3ff5ab24489ab12404548", "631d311414b2a3a1a65426a7a393fa0a086b4ff467b54994c7b9c5fc4c576e7b", "60ad20787a864683bd971bf5f8bb0d7394a6a1cd2d950c074f9c8937828e05be"},
	{7, "1b42a09f6c50b2afd469e7588e7c9656a39fb8bc38ea94b42ad2cf476c9a8398456024ebc3a80", "05520665494f07c9505bac3a6f93125e55c00766d062487aaa83860793410b5713a1bbfd4b4e10", "d1634bf75e26d3fd6bc9fb23ab78d7be63d51863df4579c81b9b2df01dd7e8d154ad6efc2c51", "19dab25df736aa5f2db7d34dbf5fff560d52612dcd983195abd2f24f5a96640c5549d4abc7f07"},
	{8, "157cb693eee237ca955e9eaddf870de63975d1c4f04858a99c07215217c09ddb5bc35ef5161037679ecc7847547f", "048fc1c14593a136a638e314415838c2ccc08ba1627f3ccb3b495453495feef2de1f41b081d721dd50613939415a", "366f9a25e073418297c8034d710e2d77374c8e7f4a82a429a8a17945e59ec08d2aa056106f6d3ab7ee3929d5f7e8", "2b52aa578b1d56f71bef1d0f7bf6131c40720c55d2b4672c1dc8c9b88913c0bc88f0b52a13e59fef999e5da85aca"},
	{9, "1f82ee0dbfea3c6edc15e2c6f1c0b0f56e15f22de66ed7a935b775a23962b04e53cd44ee50bd08b47a2375aa71c1a3635f9be8d7f84d", "65213b762ea0ec02ed3f0fca7ea92b8f302715addd04b295016c37a538b6cbe81b4dfa571f4e1e0a5dcac503900272db08caef5f2020", "dc0751c5d09e4075b01f6cbb8263c4733e05c189363e6efe620bd7de15cae2d3ada77621871ff26489af302139f7841a97a23db454a", "3b710fe85d1719ad211657e62ce052bcf0f32c881df691ba79ce899be253561c8e49db4f21e621833e34dda46bd807236e2678ed0f8c"},
}

func TestBouncyCastleVectors(t *testing.T) {
	for _, tt := range bcVectors {
		t.Run("curve"+strconv.Itoa(tt.curve), func(t *testing.T) {
			t.Parallel()
			c := mustCurve(t, tt.curve)
			priv, err := NewPrivateKey(c, mustInt(t, tt.d).Bytes())
			if err != nil {
				t.Fatalf("NewPrivateKey(curve %d, %s) error = %v", tt.curve, tt.d, err)
			}
			if got := hex.EncodeToString(priv.Public().Bytes()); got != tt.q {
				t.Errorf("curve %d: Public().Bytes() = %s, want %s", tt.curve, got, tt.q)
			}
			pub, err := ParsePublicKey(c, mustHex(t, tt.q))
			if err != nil {
				t.Fatalf("ParsePublicKey(curve %d, %s) error = %v", tt.curve, tt.q, err)
			}
			hash, r, s := mustHex(t, bcHash), mustInt(t, tt.r), mustInt(t, tt.s)
			if !Verify(pub, hash, r, s) {
				t.Errorf("curve %d: Verify(BC signature) = false, want true", tt.curve)
			}
			if Verify(pub, hash, new(big.Int).Add(r, big.NewInt(1)), s) {
				t.Errorf("curve %d: Verify(r+1) = true, want false", tt.curve)
			}
			if Verify(pub, mustHex(t, "00"+bcHash[2:]), r, s) {
				t.Errorf("curve %d: Verify(other hash) = true, want false", tt.curve)
			}
		})
	}
}

// The key and signature of the test-ca root, produced by ca.java (Bouncy Castle) and
// accepted by the IIT library: the point is the big-endian key from the certificate,
// the signature is r||s, each 32 bytes little-endian, over GOST 34.311 of "abc".
func TestIITSignature(t *testing.T) {
	pub, err := ParsePublicKey(mustCurve(t, 6), mustHex(t, "018354bf05c8a16dcd3c2b4ccd342a6d758a781136993097561f64741b102c7a5d"))
	if err != nil {
		t.Fatalf("ParsePublicKey(test-ca root) error = %v", err)
	}
	sig := mustHex(t, "de1250f94969f045f2c27fba909d8b550224f197ea71bff97f1820f97779c97ddc0c4b30b64a598262bed03a76c988eff2c716fc679a104ff7c785e856a9f52d")
	littleEndian := func(b []byte) *big.Int {
		b = slices.Clone(b)
		slices.Reverse(b)
		return new(big.Int).SetBytes(b)
	}
	hash := gost34311.Sum([]byte("abc"))
	if !Verify(pub, hash[:], littleEndian(sig[:32]), littleEndian(sig[32:])) {
		t.Error("Verify(test-ca root signature) = false, want true")
	}
}

func TestSignVerify(t *testing.T) {
	hashes := map[string][]byte{
		"gost":     mustHex(t, bcHash),
		"one byte": {0x5a},
		"zero":     make([]byte, 32), // the hash maps to 0, which DSTU 4145 replaces with 1
		"64 bytes": bytes.Repeat([]byte{0xa5}, 64),
	}
	for id := range 10 {
		t.Run("curve"+strconv.Itoa(id), func(t *testing.T) {
			t.Parallel()
			c := mustCurve(t, id)
			priv, err := GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey(curve %d) error = %v", id, err)
			}
			other, err := GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey(curve %d) error = %v", id, err)
			}
			for name, hash := range hashes {
				r, s, err := Sign(rand.Reader, priv, hash)
				if err != nil {
					t.Fatalf("curve %d: Sign(%s) error = %v", id, name, err)
				}
				if !Verify(priv.Public(), hash, r, s) {
					t.Errorf("curve %d: Verify(Sign(%s)) = false, want true", id, name)
				}
				if Verify(other.Public(), hash, r, s) {
					t.Errorf("curve %d: Verify(other key, Sign(%s)) = true, want false", id, name)
				}
			}

			restored, err := NewPrivateKey(c, priv.Bytes())
			if err != nil {
				t.Fatalf("NewPrivateKey(curve %d, Bytes()) error = %v", id, err)
			}
			if !bytes.Equal(restored.Public().Bytes(), priv.Public().Bytes()) {
				t.Errorf("curve %d: NewPrivateKey(Bytes()).Public() = %x, want %x", id, restored.Public().Bytes(), priv.Public().Bytes())
			}
			if got, want := len(priv.Bytes()), (c.Order().BitLen()+7)/8; got != want {
				t.Errorf("curve %d: len(PrivateKey.Bytes()) = %d, want %d", id, got, want)
			}
		})
	}
}

func TestVerifyRejectsOutOfRange(t *testing.T) {
	c := mustCurve(t, 6)
	tt := bcVectors[6]
	pub, err := ParsePublicKey(c, mustHex(t, tt.q))
	if err != nil {
		t.Fatalf("ParsePublicKey error = %v", err)
	}
	r, s, n := mustInt(t, tt.r), mustInt(t, tt.s), c.Order()
	cases := []struct {
		name string
		r, s *big.Int
	}{
		{"r zero", big.NewInt(0), s},
		{"s zero", r, big.NewInt(0)},
		{"r negative", new(big.Int).Neg(r), s},
		{"r equals n", n, s},
		{"s equals n", r, n},
		{"s plus n", r, new(big.Int).Add(s, n)},
	}
	for _, tc := range cases {
		if Verify(pub, mustHex(t, bcHash), tc.r, tc.s) {
			t.Errorf("Verify(%s) = true, want false", tc.name)
		}
	}
}

func TestParsePublicKeyRejects(t *testing.T) {
	valid := mustHex(t, bcVectors[6].q) // 33 bytes for the 257-bit field
	beyondField := slices.Clone(valid)
	beyondField[0] |= 0x02 // bit 257 is outside GF(2^257)
	cases := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"short", valid[1:]},
		{"long", append(slices.Clone(valid), 0)},
		{"beyond field", beyondField},
		// x = 0 decodes to the point (0, √b) of order 2, outside the subgroup of order n
		{"order two point", make([]byte, len(valid))},
	}
	c := mustCurve(t, 6)
	for _, tc := range cases {
		if _, err := ParsePublicKey(c, tc.data); err == nil {
			t.Errorf("ParsePublicKey(%s %x) error = nil, want error", tc.name, tc.data)
		}
	}
}

func TestNewPrivateKeyRejects(t *testing.T) {
	c := mustCurve(t, 0)
	n := c.Order()
	for name, d := range map[string][]byte{
		"nil":         nil,
		"zero":        {0},
		"order":       n.Bytes(),
		"above order": new(big.Int).Add(n, big.NewInt(1)).Bytes(),
	} {
		if _, err := NewPrivateKey(c, d); err == nil {
			t.Errorf("NewPrivateKey(curve 0, %s) error = nil, want error", name)
		}
	}
}

func TestNamedCurve(t *testing.T) {
	for _, id := range []int{-1, 10} {
		if _, err := NamedCurve(id); err == nil {
			t.Errorf("NamedCurve(%d) error = nil, want error", id)
		}
	}
	want := "800000000000000000000000000000006759213AF182E987D3E17714907D470D"
	if got := mustCurve(t, 6).Order(); got.Cmp(mustInt(t, want)) != 0 {
		t.Errorf("NamedCurve(6).Order() = %X, want %s", got, want)
	}
	// Order returns a copy: changing it must not change the curve.
	mustCurve(t, 6).Order().SetInt64(1)
	if got := mustCurve(t, 6).Order(); got.Cmp(mustInt(t, want)) != 0 {
		t.Errorf("NamedCurve(6).Order() after mutation = %X, want %s", got, want)
	}
}

// Any encoding ParsePublicKey accepts encodes back to the same bytes.
func FuzzParsePublicKey(f *testing.F) {
	for _, v := range []int{0, 6} {
		f.Add(v, mustHex(f, bcVectors[v].q))
	}
	f.Add(6, make([]byte, 33))
	f.Fuzz(func(t *testing.T, id int, data []byte) {
		c, err := NamedCurve(((id % 10) + 10) % 10)
		if err != nil {
			t.Fatalf("NamedCurve error = %v", err)
		}
		pub, err := ParsePublicKey(c, data)
		if err != nil {
			return
		}
		if got := pub.Bytes(); !bytes.Equal(got, data) {
			t.Errorf("ParsePublicKey(%x).Bytes() = %x, want the input", data, got)
		}
	})
}
