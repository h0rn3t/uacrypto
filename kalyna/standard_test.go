package kalyna_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	json "encoding/json/v2"
	"os"
	"testing"

	"github.com/h0rn3t/uacrypto/kalyna"
)

// example is one example of DSTU 7624:2014 as the certified cryptonite library
// tests it (src/cryptoniteAtest/c/atest_dstu7624.c, BSD-2-Clause, see
// THIRD_PARTY_NOTICES.md), extracted to testdata/dstu7624.json. Each table
// uses the fields its mode needs.
type example struct {
	Key       hexBytes `json:"key"`
	IV        hexBytes `json:"iv"`
	Data      hexBytes `json:"data"`
	Want      hexBytes `json:"exp"`
	AuthData  hexBytes `json:"auth_data"`
	PlainData hexBytes `json:"plain_data"`
	WantCip   hexBytes `json:"exp_cip"`
	WantTag   hexBytes `json:"exp_h"`
	Q         int      `json:"q"`
	Nb        int      `json:"Nb"`
	BlockSize int      `json:"block_size"`
}

type hexBytes []byte

func (h *hexBytes) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	*h = b
	return err
}

func examples(t *testing.T, table string) []example {
	t.Helper()
	raw, err := os.ReadFile("testdata/dstu7624.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string][]example
	if err := json.Unmarshal(raw, &all, json.MatchCaseInsensitiveNames(false)); err != nil {
		t.Fatalf("testdata/dstu7624.json: %v", err)
	}
	if len(all[table]) == 0 {
		t.Fatalf("testdata/dstu7624.json has no %s", table)
	}
	return all[table]
}

// newBlock returns Kalyna with a block of blockSize bytes under key.
func newBlock(t *testing.T, blockSize int, key []byte) cipher.Block {
	t.Helper()
	newCipher := map[int]func([]byte) (cipher.Block, error){
		16: kalyna.NewCipher128,
		32: kalyna.NewCipher256,
		64: kalyna.NewCipher512,
	}[blockSize]
	if newCipher == nil {
		t.Fatalf("block size %d", blockSize)
	}
	b, err := newCipher(key)
	if err != nil {
		t.Fatalf("Kalyna-%d key of %d bytes: %v", blockSize*8, len(key), err)
	}
	return b
}

func TestStandardECB(t *testing.T) {
	for _, e := range examples(t, "enc_ecb_data") {
		b := newBlock(t, len(e.Data), e.Key)
		got := make([]byte, len(e.Data))
		b.Encrypt(got, e.Data)
		if !bytes.Equal(got, e.Want) {
			t.Errorf("Encrypt(key %x, %x) = %x, want %x", e.Key, e.Data, got, e.Want)
		}
	}
}

func TestStandardCTR(t *testing.T) {
	for _, e := range examples(t, "ctr_data") {
		for _, tt := range []struct{ in, want []byte }{{e.Data, e.Want}, {e.Want, e.Data}} {
			s, err := kalyna.NewCTR(newBlock(t, len(e.IV), e.Key), e.IV)
			if err != nil {
				t.Fatalf("NewCTR(key %x, iv %x): %v", e.Key, e.IV, err)
			}
			got := make([]byte, len(tt.in))
			s.XORKeyStream(got, tt.in)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("CTR(key %x, iv %x, %x) = %x, want %x", e.Key, e.IV, tt.in, got, tt.want)
			}
		}
	}
}

// DSTU 7624 OFB is the OFB of crypto/cipher over a Kalyna block.
func TestStandardOFB(t *testing.T) {
	for _, e := range examples(t, "ofb_data") {
		got := make([]byte, len(e.Data))
		cipher.NewOFB(newBlock(t, len(e.IV), e.Key), e.IV).XORKeyStream(got, e.Data) //nolint:staticcheck // SA1019: the mode DSTU 7624 defines
		if !bytes.Equal(got, e.Want) {
			t.Errorf("OFB(key %x, iv %x, %x) = %x, want %x", e.Key, e.IV, e.Data, got, e.Want)
		}
	}
}

// DSTU 7624 CBC is the CBC of crypto/cipher over a Kalyna block. The examples
// pad a partial last block as ISO/IEC 7816-4 does: 80 00...
func TestStandardCBC(t *testing.T) {
	for _, e := range examples(t, "cbc_data") {
		b := newBlock(t, len(e.IV), e.Key)
		plain := bytes.Clone(e.Data)
		if len(plain)%len(e.IV) != 0 {
			plain = append(plain, 0x80)
			plain = append(plain, make([]byte, (len(e.IV)-len(plain)%len(e.IV))%len(e.IV))...)
		}
		got := make([]byte, len(plain))
		cipher.NewCBCEncrypter(b, e.IV).CryptBlocks(got, plain)
		if !bytes.Equal(got, e.Want) {
			t.Errorf("CBC encrypt(key %x, iv %x, %x) = %x, want %x", e.Key, e.IV, plain, got, e.Want)
		}
		back := make([]byte, len(e.Want))
		cipher.NewCBCDecrypter(b, e.IV).CryptBlocks(back, e.Want)
		if !bytes.Equal(back, plain) {
			t.Errorf("CBC decrypt(key %x, iv %x, %x) = %x, want %x", e.Key, e.IV, e.Want, back, plain)
		}
	}
}

func TestStandardCFB(t *testing.T) {
	for _, e := range examples(t, "cfb_data") {
		c, err := kalyna.NewCFB(newBlock(t, len(e.IV), e.Key), e.Q)
		if err != nil {
			t.Fatalf("NewCFB(key %x, segment %d): %v", e.Key, e.Q, err)
		}
		got, err := c.Encrypt(e.IV, e.Data)
		if err != nil || !bytes.Equal(got, e.Want) {
			t.Errorf("CFB-%d Encrypt(key %x, iv %x, %x) = %x, %v; want %x", e.Q*8, e.Key, e.IV, e.Data, got, err, e.Want)
		}
		back, err := c.Decrypt(e.IV, e.Want)
		if err != nil || !bytes.Equal(back, e.Data) {
			t.Errorf("CFB-%d Decrypt(key %x, iv %x, %x) = %x, %v; want %x", e.Q*8, e.Key, e.IV, e.Want, back, err, e.Data)
		}
	}
}

func TestStandardCMAC(t *testing.T) {
	for _, e := range examples(t, "cmac_data") {
		got, err := kalyna.CMAC(newBlock(t, e.BlockSize, e.Key), e.Data, e.Q)
		if err != nil || !bytes.Equal(got, e.Want) {
			t.Errorf("CMAC(key %x, %d bytes, %d) = %x, %v; want %x", e.Key, len(e.Data), e.Q, got, err, e.Want)
		}
	}
}

// The 256/256 vector of cryptonite's unit tests (utest_dstu7624.c) over 48
// bytes, which ends in a partial block; IIT gives the same MAC.
func TestCMACPartialBlock(t *testing.T) {
	key := append(sequence(0, 16), sequence(0, 16)...)
	got, err := kalyna.CMAC(newBlock(t, 32, key), sequence(0x20, 48), 16)
	if want := "5df20d04735bab6d5351082da6ad8d41"; err != nil || hex.EncodeToString(got) != want {
		t.Errorf("CMAC(key %x, %d bytes, 16) = %x, %v; want %s", key, 48, got, err, want)
	}
}

func TestStandardGMAC(t *testing.T) {
	for _, e := range examples(t, "gmac_data") {
		got, err := kalyna.GMAC(newBlock(t, e.BlockSize, e.Key), e.Data, e.Q)
		if err != nil || !bytes.Equal(got, e.Want) {
			t.Errorf("GMAC(key %x, %d bytes, %d) = %x, %v; want %x", e.Key, len(e.Data), e.Q, got, err, e.Want)
		}
	}
}

func TestStandardXTS(t *testing.T) {
	for _, e := range examples(t, "xts_data") {
		x, err := kalyna.NewXTS(newBlock(t, len(e.IV), e.Key))
		if err != nil {
			t.Fatal(err)
		}
		got, err := x.Encrypt(e.IV, e.Data)
		if err != nil || !bytes.Equal(got, e.Want) {
			t.Errorf("XTS Encrypt(key %x, iv %x, %d bytes) = %x, %v; want %x", e.Key, e.IV, len(e.Data), got, err, e.Want)
		}
		back, err := x.Decrypt(e.IV, e.Want)
		if err != nil || !bytes.Equal(back, e.Data) {
			t.Errorf("XTS Decrypt(key %x, iv %x, %d bytes) = %x, %v; want %x", e.Key, e.IV, len(e.Want), back, err, e.Data)
		}
	}
}

func TestStandardWrap(t *testing.T) {
	for _, e := range examples(t, "kw_data") {
		b := newBlock(t, e.BlockSize, e.Key)
		got, err := kalyna.Wrap(b, e.Data)
		if err != nil || !bytes.Equal(got, e.Want) {
			t.Errorf("Wrap(key %x, %d bytes) = %x, %v; want %x", e.Key, len(e.Data), got, err, e.Want)
		}
		back, err := kalyna.Unwrap(b, e.Want)
		if err != nil || !bytes.Equal(back, e.Data) {
			t.Errorf("Unwrap(key %x, %x) = %x, %v; want %x", e.Key, e.Want, back, err, e.Data)
		}
	}
}

// The examples give Nb in bits and the ciphertext with the tag appended.
func TestStandardCCM(t *testing.T) {
	for _, e := range examples(t, "ccm_data") {
		c, err := kalyna.NewCCM(newBlock(t, len(e.IV), e.Key), e.Nb/8, e.Q)
		if err != nil {
			t.Fatalf("NewCCM(Nb %d, tag %d): %v", e.Nb/8, e.Q, err)
		}
		got, err := c.Seal(e.IV, e.PlainData, e.AuthData)
		if err != nil || !bytes.Equal(got, e.WantCip) {
			t.Errorf("CCM Seal(key %x, %d bytes, %d bytes AAD) = %x, %v; want %x", e.Key, len(e.PlainData), len(e.AuthData), got, err, e.WantCip)
		}
		back, err := c.Open(e.IV, e.WantCip, e.AuthData)
		if err != nil || !bytes.Equal(back, e.PlainData) {
			t.Errorf("CCM Open(key %x, %x) = %x, %v; want %x", e.Key, e.WantCip, back, err, e.PlainData)
		}
	}
}

// The examples give the tag apart from the ciphertext, in exp_h.
func TestStandardGCM(t *testing.T) {
	for _, e := range examples(t, "gcm_data") {
		g, err := kalyna.NewGCM(newBlock(t, len(e.IV), e.Key), e.Q)
		if err != nil {
			t.Fatalf("NewGCM(tag %d): %v", e.Q, err)
		}
		want := append(bytes.Clone(e.WantCip), e.WantTag...)
		got, err := g.Seal(e.IV, e.PlainData, e.AuthData)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("GCM Seal(key %x, %d bytes, %d bytes AAD) = %x, %v; want %x", e.Key, len(e.PlainData), len(e.AuthData), got, err, want)
		}
		back, err := g.Open(e.IV, want, e.AuthData)
		if err != nil || !bytes.Equal(back, e.PlainData) {
			t.Errorf("GCM Open(key %x, %x) = %x, %v; want %x", e.Key, want, back, err, e.PlainData)
		}
	}
}
