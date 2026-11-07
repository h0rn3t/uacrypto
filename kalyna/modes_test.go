package kalyna_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/h0rn3t/uacrypto/kalyna"
)

// Vectors are the output of Bouncy Castle 1.86 (DSTU7624Mac, KGCMBlockCipher,
// KCCMBlockCipher, KXTSBlockCipher, DSTU7624WrapEngine). The key is
// sequence(0, keyLen); other inputs are named on the case. TestGCM checks
// NewGCMWithNonceAuth: KGCMBlockCipher was given nonce || additionalData as
// its AAD.

func mustCipher(t *testing.T, block, key int) cipher.Block {
	t.Helper()
	var (
		c   cipher.Block
		err error
	)
	k := sequence(0, key)
	switch block {
	case 16:
		c, err = kalyna.NewCipher128(k)
	case 32:
		c, err = kalyna.NewCipher256(k)
	default:
		c, err = kalyna.NewCipher512(k)
	}
	if err != nil {
		t.Fatalf("NewCipher(%d, %d) error = %v", block, key, err)
	}
	return c
}

func equalHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s = %x, want %s", name, got, want)
	}
}

func TestCMAC(t *testing.T) {
	tests := []struct {
		name       string
		block, key int
		full, one  string
		empty      string
	}{
		{"128/128", 16, 16, "7bf17cd2ece829408bf9458025509d80", "90", "44d2a5dc279e8a560c52f5a19cc55717"},
		{"128/256", 16, 32, "f3bf54c132278424b7a70703b97fceca", "07", "435ad5fd07e26dbf7b1da3ee8931090f"},
		{"256/256", 32, 32, "3fe6913ff069f06b7a99aeb234f795d7dd3357f6f6aa6b0e22da203479039714", "eb", "9146931b30c77ce9ffc7e38523b25c13f19542de3cd61e5b8896fd37d0a5ce4c"},
		{"256/512", 32, 64, "b5c7d224d5a38247bc6ea0d5a3821f0d4a464567e6bc098e5ca562cff5c56c8e", "e3", "66d3bdb863d793e56cf7bbb7b8f48f0dfdeffc103e43446ed17a62ec155a166a"},
		{"512/512", 64, 64, "a6d44e26168f612abe95e76143a6c7b59f8d1354193f36ccfa058398a867203962243101172d643454e2c5949166dbe6ce7e509fbfb35b96ad0fbd926c9536ca", "72", "adc0f289fa6b7a83690321b53e89991d8f9241c3a3467cc19888d5bcdea1029055199da742bc285075fec94a9d1ce1f61b5d515bcc3091bb1a2672155f4ace9b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := mustCipher(t, tt.block, tt.key)
			got, err := kalyna.CMAC(b, sequence(tt.key, tt.block), tt.block)
			if err != nil {
				t.Fatalf("CMAC(one block) error = %v", err)
			}
			equalHex(t, "CMAC(one block)", got, tt.full)
			got, err = kalyna.CMAC(b, sequence(tt.key, 2*tt.block), 1)
			if err != nil {
				t.Fatalf("CMAC(two blocks) error = %v", err)
			}
			equalHex(t, "CMAC(two blocks, 1 byte)", got, tt.one)
			got, err = kalyna.CMAC(b, nil, tt.block)
			if err != nil {
				t.Fatalf("CMAC(nil) error = %v", err)
			}
			equalHex(t, "CMAC(nil)", got, tt.empty)
		})
	}
}

func TestGCM(t *testing.T) {
	tests := []struct {
		name       string
		block, key int
		partial    string
		empty      string
		whole      string
	}{
		{"128/128", 16, 16,
			"8caef3ae345139248808d29865ac38161f6323caabcce2dd4273e9f27c0b4ffab9ed1a",
			"cd79dba790e289ad",
			"f62766272545c8445c514b2d303566b357faa190592c3af91d1d9dc64d6d3723"},
		{"128/256", 16, 32,
			"24015d78887e98d77b369ce16c0b596ed9c022bd09bdb1f2e07c14f5d223d2813132e3",
			"47d199a2b94290e6",
			"5962da87e64f9e82c39943a0eb64f8a775a4254bdeab50ddaaef66d347a21663"},
		{"256/256", 32, 32,
			"100894228abbb46ad4ecd5ee1958a3804313f3ec3ed84cb0b87ae23a2e20c1fafed5b79ee9bd0fbd08df972c557e2e5d2368db",
			"e67734b929531dc4",
			"e2d0928965be6f50cdf7be223292d4d03a43c3d0517e847899d0caf8fc2c47f27ced770d87e8283b57275927c99e1fa7951908e8b380ccc679e38eb7c8c9782d"},
		{"256/512", 32, 64,
			"8e93d247fe342f5a3ec2dc1bbb43c04337ae8daebc6852f671b03d3200c4e75d7e80004e3fc8f497171c4782b841022bead70e",
			"3d40f078a0be6ad3",
			"55e2df3386ba3ea4e9210b74b6a440e796360955c30ed6b6243144421098b4c206d1de76dfc41ddfad16b6b23d82c4d462272a31e8d16fcd5575786589a6dc4d"},
		{"512/512", 64, 64,
			"d1b16da2303e32761119b2b64a548c873cd2545b91706f3e0a12dd2f6b2f0ecd27f44c1f079dc7c1cf33166b987a88fc6af22ea4a876777b45fdc1fdee40510254b60cae33bff358e4cfb1b00a4fefe3b00e98",
			"f95064e9c5f2c982",
			"9f37873c5c7db996e59b3f9bed5f81aa99dde63ac597112335abac59d5fe2be5f7189d974c2dbd9f1649f7104a13c1fbe4076783d1937cd48f115276e83581346d95eae6e62d847b3ace51dbc104417129c3991abc2a45e53573c16b7a5a5b973b5881d37c6e9bd93ce6f683f09147c6096ff5934040c45f0b6e60821dc2f80a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := mustCipher(t, tt.block, tt.key)
			g, err := kalyna.NewGCMWithNonceAuth(b, 16)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, tt.block)
			copy(nonce[tt.block-7:], sequence(1, 7))
			sealed, err := g.Seal(nonce, sequence(20, tt.block+3), sequence(9, 5))
			if err != nil {
				t.Fatalf("Seal(partial) error = %v", err)
			}
			equalHex(t, "Seal(partial)", sealed, tt.partial)
			opened, err := g.Open(nonce, sealed, sequence(9, 5))
			if err != nil {
				t.Fatalf("Open(partial) error = %v", err)
			}
			if !bytes.Equal(opened, sequence(20, tt.block+3)) {
				t.Errorf("Open(partial) = %x, want plaintext", opened)
			}

			whole, err := kalyna.NewGCMWithNonceAuth(b, tt.block)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err = whole.Seal(sequence(2, tt.block), sequence(4, tt.block), sequence(3, 2*tt.block))
			if err != nil {
				t.Fatalf("Seal(whole) error = %v", err)
			}
			equalHex(t, "Seal(whole)", sealed, tt.whole)

			short, err := kalyna.NewGCMWithNonceAuth(b, 8)
			if err != nil {
				t.Fatal(err)
			}
			zeroNonce := make([]byte, tt.block)
			sealed, err = short.Seal(zeroNonce, nil, nil)
			if err != nil {
				t.Fatalf("Seal(nil) error = %v", err)
			}
			equalHex(t, "Seal(nil)", sealed, tt.empty)
			other, err := short.Seal(nonce, nil, nil)
			if err != nil {
				t.Fatalf("Seal(other nonce, nil plaintext) error = %v", err)
			}
			if bytes.Equal(other, sealed) {
				t.Errorf("Seal(empty plaintext, different nonces) = %x and %x; want different tags", sealed, other)
			}
			opened, err = short.Open(zeroNonce, sealed, nil)
			if err != nil || len(opened) != 0 {
				t.Errorf("Open(nil) = %x, %v; want empty, nil", opened, err)
			}
		})
	}
}

func TestCCM(t *testing.T) {
	noAAD := []struct {
		name       string
		block, key int
		want       string
	}{
		{"128/128", 16, 16, "ce9f4a4ae2d02b1d92aa87d48d93744cec7eac85cc1e2624"},
		{"128/256", 16, 32, "754c48de4ead94e4da7d4361a93b4c115a9d2407e9e735e2"},
		{"256/256", 32, 32, "494034470e8edf31ffd548fbf93319f6af1f5576443af01a07843b1b9c50ddac8bc06363678eaa96"},
		{"256/512", 32, 64, "8b5a3e9def1050d3e58580c2d5ea470049431270f3015dcd2ab04fc59303a8a9256937df2a2bfc80"},
		{"512/512", 64, 64, "9d61737c3e0ac5725dd036be2bea9979f4affa88b49ce2820ae7f709eb28953c3300796059d0f2b39b65ea778f421917b24e003f558e7a2ef2eddfaab31a8485cf31c5e6f4b5ed15"},
	}
	for _, tt := range noAAD {
		t.Run("no AAD "+tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := kalyna.NewCCM(mustCipher(t, tt.block, tt.key), 4, 8)
			if err != nil {
				t.Fatal(err)
			}
			pt := sequence(8, tt.block)
			nonce := make([]byte, tt.block)
			copy(nonce, sequence(1, tt.block-1))
			sealed, err := c.Seal(nonce, pt, nil)
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			equalHex(t, "Seal()", sealed, tt.want)
			opened, err := c.Open(nonce, sealed, nil)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if !bytes.Equal(opened, pt) {
				t.Errorf("Open() = %x, want plaintext", opened)
			}
		})
	}

	// Bouncy Castle KCCMBlockCipher zero-pads a partial plaintext block and
	// starts the tag keystream on a fresh block; the examples of DSTU 7624
	// (TestStandardCCM) pad with 80 00... and continue the keystream, so its
	// partial-block vectors are not kept here.

	t.Run("Nb 8 empty plaintext", func(t *testing.T) {
		t.Parallel()
		c, err := kalyna.NewCCM(mustCipher(t, 64, 64), 8, 16)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 64)
		copy(nonce, sequence(1, 4))
		sealed, err := c.Seal(nonce, nil, sequence(2, 1))
		if err != nil {
			t.Fatalf("Seal() error = %v", err)
		}
		equalHex(t, "Seal()", sealed, "34911d353884fba1b9ba4f805472cfd4")
		opened, err := c.Open(nonce, sealed, sequence(2, 1))
		if err != nil || len(opened) != 0 {
			t.Errorf("Open() = %x, %v; want empty, nil", opened, err)
		}
	})
}

func TestXTS(t *testing.T) {
	tests := []struct {
		name       string
		block, key int
		want       string
	}{
		{"128/128", 16, 16, "6a40cd9cd10496ec3e16285ef4ec7cb177f89917c05056f2d3440441ad8b0f8d"},
		{"128/256", 16, 32, "c357e660b58851ba3dc4ea67399e39d87c2caa675809bb5a59941296be1a38be"},
		{"256/256", 32, 32, "c71a09197f4e7262766293008d8ecc61c4945d2ec177a8a621679d453d0f6a4f0f1d7171bc4c5d0a9d24f751792c95d7f6ed1da6add688b3407407c1a8b4c67c"},
		{"256/512", 32, 64, "31f1aa4a3d67ee5be4dd8df354fa6975f95f930a78d259d4fcca8bd8e3675662fe99db4dc2fd1a3ea8d3f0d0354ac56168d2859aa5329c5139f6ac0130d617f1"},
		{"512/512", 64, 64, "9780ea037736f8d822c3ee00a32fb1eb9af3f2ada9681ff26df68e98e3a20d43df2a40dff4fa061b4e070a5ee0eb6285e6ac5fa58e2906cf81127b53e48ed200a58f2d7cd3e7949df05151f1c628a1fca1db0ab0df300c2687b878e0b88e7f2dac3e692b836a5ec8200525aa17e4352cdd1de9424148d518e2733866a55ac0e3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			x, err := kalyna.NewXTS(mustCipher(t, tt.block, tt.key))
			if err != nil {
				t.Fatal(err)
			}
			pt := sequence(1, 2*tt.block)
			iv := sequence(9, tt.block)
			sealed, err := x.Encrypt(iv, pt)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}
			equalHex(t, "Encrypt()", sealed, tt.want)
			opened, err := x.Decrypt(iv, sealed)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !bytes.Equal(opened, pt) {
				t.Errorf("Decrypt() = %x, want plaintext", opened)
			}
			empty, err := x.Encrypt(iv, nil)
			if err != nil || len(empty) != 0 {
				t.Errorf("Encrypt(nil) = %x, %v; want empty, nil", empty, err)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name       string
		block, key int
		blocks     int
		want       string
	}{
		{"128/128 one", 16, 16, 1, "1dc91dc6e52575f6dbed25adda95a1b6ad3e15056e489738972c199fb9ee2913"},
		{"128/128 two", 16, 16, 2, "20b07fb36283d8c318d61651c94a129b141fac81c18034aaf0426b381272ca426a4efbf60d40ba3efb8d479379e46ded"},
		{"128/256 one", 16, 32, 1, "18d206896a0d0ea045908f7e03963cad80ccde59b478c73f8a5decd73632f623"},
		{"128/256 two", 16, 32, 2, "ee4de9fc64553db85aadc40277946cf05adab1cf63976640feb6341aa307d2494aa9ff3ad7db325cbbebd8c62a83389d"},
		{"256/256 one", 32, 32, 1, "c329f3f55dcbf62869260666c2623aff44dcf03b5f379f89fc15ef36a2c144f13952341bcfcb757e2f759bb5c197b5b7f049dea625992ec5f588aa6bf8544220"},
		{"256/256 two", 32, 32, 2, "b2f8d9fff78429c11ae0879e33920be3c252c51b6a7ac2e8c93c33bb24ec99fe3ef9cbc4b3478490d47e5b818fb28dbf4c376cb52aeaaac84477274ab5c1a817e6b3b97549dcbf33fbba2277a09d037abebc3c5593050bc7f2ad1a006503850a"},
		{"256/512 one", 32, 64, 1, "b52c5f09f98a0bcfa6e8f9045098589c360df2d4b59dbd988096f89c392f7eb1f9fe0f4acaff2bf014d7145c1889d9113cd74d743fc8a8c7444d84e04615208a"},
		{"256/512 two", 32, 64, 2, "aa44ef920e30d1ceebc09e8230480cfce4c93178c02c9364af2aad03954e50f5deb7a8f8748f242206935830809e9e2a61731d3f15ba709464f15e6c46bcfad39f829489b33d69fb2903c586005f539b855eaf7f1eb4a230c5fe53d2407125dc"},
		{"512/512 one", 64, 64, 1, "f40809fe6050ff3eb6b4c08ee0cdf9b1d01f61c94f7488829f231dbfd4ad85a62331a4c4713571ae92a7f59b226ae4949cd5ff06766cac21790ed95b801fc0072c381aea7efd0a2937a42b09473953a04ae773072587c8a5885efd8ec9f4170dba554c238561bbcc47d26a07be779abb8125e6385a63b8c6b786ba671a01b912"},
		{"512/512 two", 64, 64, 2, "9618ae6065069d5054464040f17337d58beb51ae92391d740bdf7abb239709c46270832039ff045bcf7878e7da9c3b4cf89326ca8b4d29db8680eeae1b5a18463284713a323a69aebf33cfc4b11283c7c8041ffc97668edf727823411c9559816c108c11ec401643765527860d8da0ed7254792c21db775deb1d6971c924cc83eb626173d894694943b1828abde8f9495bceba9ac3a4a03592c085aa29cc9a0c65786e631a702d589b819c89e79eeff29c4ec312c8860bb68f02272ea770fb8d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := mustCipher(t, tt.block, tt.key)
			key := sequence(tt.key, tt.blocks*tt.block)
			wrapped, err := kalyna.Wrap(b, key)
			if err != nil {
				t.Fatalf("Wrap() error = %v", err)
			}
			equalHex(t, "Wrap()", wrapped, tt.want)
			opened, err := kalyna.Unwrap(b, wrapped)
			if err != nil {
				t.Fatalf("Unwrap() error = %v", err)
			}
			if !bytes.Equal(opened, key) {
				t.Errorf("Unwrap() = %x, want key", opened)
			}
		})
	}

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		b := mustCipher(t, 16, 16)
		wrapped, err := kalyna.Wrap(b, nil)
		if err != nil {
			t.Fatalf("Wrap(nil) error = %v", err)
		}
		equalHex(t, "Wrap(nil)", wrapped, "2dc391baecc7a3d236063f9a621b3877")
		opened, err := kalyna.Unwrap(b, wrapped)
		if err != nil || len(opened) != 0 {
			t.Errorf("Unwrap(empty) = %x, %v; want empty, nil", opened, err)
		}
	})
}

func TestModeAuthentication(t *testing.T) {
	t.Parallel()
	b := mustCipher(t, 16, 16)
	g, err := kalyna.NewGCM(b, 16)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := g.Seal(sequence(1, 16), sequence(20, 19), sequence(9, 5))
	if err != nil {
		t.Fatal(err)
	}
	sealed[0] ^= 1
	got, err := g.Open(sequence(1, 16), sealed, sequence(9, 5))
	if !errors.Is(err, kalyna.ErrAuthentication) || got != nil {
		t.Errorf("Open(tampered) = %x, %v; want nil, ErrAuthentication", got, err)
	}
	sealed[0] ^= 1
	got, err = g.Open(sequence(1, 16), sealed[:15], sequence(9, 5))
	if !errors.Is(err, kalyna.ErrAuthentication) || got != nil {
		t.Errorf("Open(short) = %x, %v; want nil, ErrAuthentication", got, err)
	}

	c, err := kalyna.NewCCM(b, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = c.Seal(sequence(1, 16), sequence(8, 16), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	got, err = c.Open(sequence(1, 16), sealed, nil)
	if !errors.Is(err, kalyna.ErrAuthentication) || got != nil {
		t.Errorf("CCM Open(tampered) = %x, %v; want nil, ErrAuthentication", got, err)
	}

	wrapped, err := kalyna.Wrap(b, sequence(16, 16))
	if err != nil {
		t.Fatal(err)
	}
	wrapped[0] ^= 1
	got, err = kalyna.Unwrap(b, wrapped)
	if !errors.Is(err, kalyna.ErrAuthentication) || got != nil {
		t.Errorf("Unwrap(tampered) = %x, %v; want nil, ErrAuthentication", got, err)
	}
}

type sizeBlock int

func (s sizeBlock) BlockSize() int          { return int(s) }
func (s sizeBlock) Encrypt(dst, src []byte) {}
func (s sizeBlock) Decrypt(dst, src []byte) {}

func TestModeParameters(t *testing.T) {
	b := mustCipher(t, 16, 16)
	tests := []struct {
		name string
		fn   func() error
	}{
		{"nil CMAC", func() error { _, err := kalyna.CMAC(nil, nil, 16); return err }},
		{"CMAC size", func() error { _, err := kalyna.CMAC(b, nil, 0); return err }},
		{"block size", func() error { _, err := kalyna.NewGCM(sizeBlock(8), 8); return err }},
		{"GCM tag", func() error { _, err := kalyna.NewGCM(b, 7); return err }},
		{"GCM nonce", func() error {
			g, err := kalyna.NewGCM(b, 8)
			if err != nil {
				return err
			}
			_, err = g.Seal(sequence(0, 17), nil, nil)
			return err
		}},
		{"CCM Nb", func() error { _, err := kalyna.NewCCM(b, 5, 8); return err }},
		{"CCM tag", func() error { _, err := kalyna.NewCCM(b, 4, 24); return err }},
		{"CCM tag past block", func() error { _, err := kalyna.NewCCM(b, 4, 32); return err }},
		{"XTS IV", func() error {
			x, err := kalyna.NewXTS(b)
			if err != nil {
				return err
			}
			_, err = x.Encrypt(sequence(0, 8), nil)
			return err
		}},
		{"XTS partial", func() error {
			x, err := kalyna.NewXTS(b)
			if err != nil {
				return err
			}
			_, err = x.Encrypt(sequence(0, 16), sequence(1, 15))
			return err
		}},
		{"unwrap partial", func() error { _, err := kalyna.Unwrap(b, sequence(0, 47)); return err }},
		{"unwrap empty", func() error { _, err := kalyna.Unwrap(b, nil); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.fn()
			if err == nil || errors.Is(err, kalyna.ErrAuthentication) {
				t.Errorf("error = %v, want a parameter error", err)
			}
		})
	}
}

func FuzzGCMRoundTrip(f *testing.F) {
	f.Add(sequence(1, 16), []byte{9, 10, 11, 12, 13}, []byte{20, 21, 22})
	f.Fuzz(func(t *testing.T, nonce, aad, pt []byte) {
		if len(nonce) != 16 || len(aad) > 48 || len(pt) > 48 {
			return
		}
		g, err := kalyna.NewGCM(mustCipher(t, 16, 16), 8)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := g.Seal(nonce, pt, aad)
		if err != nil {
			t.Fatalf("Seal() error = %v", err)
		}
		opened, err := g.Open(nonce, sealed, aad)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if !bytes.Equal(opened, pt) {
			t.Errorf("Open(Seal()) = %x, want %x", opened, pt)
		}
	})
}

// A CTR stream may be split anywhere: the next call continues the keystream.
func TestCTRSplit(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		b := mustCipher(t, n, n)
		msg := sequence(7, 3*n+n/2)
		whole, err := kalyna.NewCTR(b, sequence(1, n))
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, len(msg))
		whole.XORKeyStream(want, msg)
		for _, cut := range []int{1, n - 1, n, n + 1, 2*n + 3} {
			s, _ := kalyna.NewCTR(b, sequence(1, n))
			got := make([]byte, len(msg))
			s.XORKeyStream(got[:cut], msg[:cut])
			s.XORKeyStream(got[cut:], msg[cut:])
			if !bytes.Equal(got, want) {
				t.Errorf("Kalyna-%d CTR split at %d = %x, want %x", n*8, cut, got, want)
			}
		}
		back := make([]byte, len(want))
		s, _ := kalyna.NewCTR(b, sequence(1, n))
		s.XORKeyStream(back, want)
		if !bytes.Equal(back, msg) {
			t.Errorf("Kalyna-%d CTR decrypt = %x, want %x", n*8, back, msg)
		}
	}
}

// Encrypting then decrypting gives the plaintext back for every length a mode
// accepts, through the partial-block paths of CFB, XTS and key wrapping.
func TestModeRoundTrip(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		b := mustCipher(t, n, n)
		iv := sequence(3, n)
		for _, size := range []int{0, 1, n/2 - 1, n / 2, n/2 + 1, n - 1, n, n + 1, 2*n - 1, 2 * n, 2*n + n/2, 3*n + 1} {
			msg := sequence(size, size)
			for _, segment := range []int{1, 8, n / 2, n} {
				c, err := kalyna.NewCFB(b, segment)
				if err != nil {
					t.Fatal(err)
				}
				ct, err := c.Encrypt(iv, msg)
				if err != nil || len(ct) != size {
					t.Fatalf("CFB-%d Encrypt(%d bytes) = %d bytes, %v", segment*8, size, len(ct), err)
				}
				if pt, err := c.Decrypt(iv, ct); err != nil || !bytes.Equal(pt, msg) {
					t.Errorf("Kalyna-%d CFB-%d Decrypt(Encrypt(%x)) = %x, %v", n*8, segment*8, msg, pt, err)
				}
			}
			if size == 0 || size >= n {
				x, _ := kalyna.NewXTS(b)
				ct, err := x.Encrypt(iv, msg)
				if err != nil || len(ct) != size {
					t.Fatalf("XTS Encrypt(%d bytes) = %d bytes, %v", size, len(ct), err)
				}
				if pt, err := x.Decrypt(iv, ct); err != nil || !bytes.Equal(pt, msg) {
					t.Errorf("Kalyna-%d XTS Decrypt(Encrypt(%x)) = %x, %v", n*8, msg, pt, err)
				}
			}
			wrapped, err := kalyna.Wrap(b, msg)
			if err != nil {
				t.Fatalf("Wrap(%d bytes) error = %v", size, err)
			}
			if key, err := kalyna.Unwrap(b, wrapped); err != nil || !bytes.Equal(key, msg) {
				t.Errorf("Kalyna-%d Unwrap(Wrap(%x)) = %x, %v", n*8, msg, key, err)
			}
		}
	}
}

func TestNewModeParameters(t *testing.T) {
	b := mustCipher(t, 32, 32)
	tests := []struct {
		name string
		fn   func() error
	}{
		{"CFB nil block", func() error { _, err := kalyna.NewCFB(nil, 16); return err }},
		{"CFB segment 0", func() error { _, err := kalyna.NewCFB(b, 0); return err }},
		{"CFB segment past block", func() error { _, err := kalyna.NewCFB(b, 33); return err }},
		{"CFB IV", func() error {
			c, err := kalyna.NewCFB(b, 32)
			if err != nil {
				return err
			}
			_, err = c.Encrypt(sequence(0, 16), nil)
			return err
		}},
		{"CTR IV", func() error { _, err := kalyna.NewCTR(b, sequence(0, 16)); return err }},
		{"CTR nil block", func() error { _, err := kalyna.NewCTR(nil, nil); return err }},
		{"GMAC size", func() error { _, err := kalyna.GMAC(b, nil, 7); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Errorf("error = nil, want a parameter error")
			}
		})
	}
}

func TestCTRShortDst(t *testing.T) {
	s, err := kalyna.NewCTR(mustCipher(t, 16, 16), sequence(0, 16))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("XORKeyStream(3-byte dst, 4-byte src) did not panic, want a panic")
		}
	}()
	s.XORKeyStream(make([]byte, 3), make([]byte, 4))
}
