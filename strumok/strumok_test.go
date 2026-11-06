package strumok_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/h0rn3t/uacrypto/strumok"
)

// words returns the little-endian bytes of w, the byte order of the package.
func words(w ...uint64) []byte {
	var b []byte
	for _, v := range w {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	return b
}

// The keys and IVs of the DSTU 8845:2019 examples, as 64-bit words K0, K1, …
// and IV0..IV3.
var (
	key256High = words(0, 0, 0, 0x8000000000000000)
	key256AA   = bytes.Repeat([]byte{0xaa}, 32)
	key512High = words(0, 0, 0, 0, 0, 0, 0, 0x8000000000000000)
	key512AA   = bytes.Repeat([]byte{0xaa}, 64)
	ivZero     = make([]byte, 32)
	ivCount    = words(1, 2, 3, 4)
)

// TestStandard checks the first eight keystream words of the examples in
// annex D of DSTU 8845:2019 (D.1.1.1–D.1.1.4 for 256-bit keys, D.2.1.1–D.2.1.4
// for 512-bit keys), as quoted by the li0ard/dstu and li0ard/strumok test
// suites, which agree.
func TestStandard(t *testing.T) {
	tests := []struct {
		name    string
		key, iv []byte
		want    []byte
	}{
		{"D.1.1.1", key256High, ivZero, words(
			0xe442d15345dc66ca, 0xf47d700ecc66408a, 0xb4cb284b5477e641, 0xa2afc9092e4124b0,
			0x728e5fa26b11a7d9, 0xe6a7b9288c68f972, 0x70eb3606de8ba44c, 0xaced7956bd3e3de7)},
		{"D.1.1.2", key256AA, ivZero, words(
			0xa7510b38c7a95d1d, 0xcd5ea28a15b8654f, 0xc5e2e2771d0373b2, 0x98ae829686d5fcee,
			0x45bddf65c523dbb8, 0x32a93fcdd950001f, 0x752a7fb588af8c51, 0x9de92736664212d4)},
		{"D.1.1.3", key256High, ivCount, words(
			0xfe44a2508b5a2acd, 0xaf355b4ed21d2742, 0xdcd7fdd6a57a9e71, 0x5d267bd2739fb5eb,
			0xb22eee96b2832072, 0xc7de6a4cdaa9a847, 0x72d5da93812680f2, 0x4a0acb7e93da2ce0)},
		{"D.1.1.4", key256AA, ivCount, words(
			0xe6d0efd9cea5abcd, 0x1e78ba1a9b0e401e, 0xbcfbea2c02ba0781, 0x1bd375588ae08794,
			0x5493cf21e114c209, 0x66cd5d7cc7d0e69a, 0xa5cdb9f3380d07fa, 0x2940d61a4d4e9ce4)},
		{"D.2.1.1", key512High, ivZero, words(
			0xf5b9ab51100f8317, 0x898ef2086a4af395, 0x59571fecb5158d0b, 0xb7c45b6744c71fbb,
			0xff2efcf05d8d8db9, 0x7a585871e5c419c0, 0x6b5c4691b9125e71, 0xa55be7d2b358ec6e)},
		{"D.2.1.2", key512AA, ivZero, words(
			0xd2a6103c50bd4e04, 0xdc6a21af5eb13b73, 0xdf4ca6cb07797265, 0xf453c253d8d01876,
			0x039a64dc7a01800c, 0x688ce327dccb7e84, 0x41e0250b5e526403, 0x9936e478aa200f22)},
		{"D.2.1.3", key512High, ivCount, words(
			0xcca12eae8133aaaa, 0x528d85507ce8501d, 0xda83c7fe3e1823f1, 0x21416ebf63b71a42,
			0x26d76d2bf1a625eb, 0xeec66ee0cd0b1efc, 0x02dd68f338a345a8, 0x47538790a5411adb)},
		{"D.2.1.4", key512AA, ivCount, words(
			0x965648e775c717d5, 0xa63c2a7376e92df3, 0x0b0eb0bbd47ca267, 0xea593d979ae5bd39,
			0xd773b5e5193cafe1, 0xb0a26671d259422b, 0x85b2aa326b280156, 0x511ace6451435f0c)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := strumok.NewCipher(tt.key, tt.iv)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(tt.want))
			s.XORKeyStream(got, got)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("keystream(%x, %x) = %x, want %x", tt.key, tt.iv, got, tt.want)
			}
		})
	}
}

// TestEncrypt encrypts 272 bytes — two 128-byte blocks of the generator and a
// partial one — with the key of D.2.1.3; the ciphertext is that of the
// li0ard/strumok test suite, whose keystream bytes are little-endian words.
func TestEncrypt(t *testing.T) {
	plaintext := make([]byte, 272)
	plaintext[0] = 0xaa
	want, err := hex.DecodeString("00aa3381ae2ea1cc1d50e87c50858d52f123183efec783da421ab763bf6e4121" +
		"eb25a6f12b6dd726fc1e0bcde06ec6eea845a338f368dd02db1a41a5908753479e61825449b49f9f6337749259c4df42" +
		"3c885e88f457d703be65865b25bfee8d3312a332ca90d1eed635d4c2aea227553796744ab222092f1a93cd38e4ba28ac" +
		"a491c1b9a2f292c4a9d2b09ebed90fddfd84e38ae0312937f9a97c99778f37fc31a5e5eca2b12427769986515af6db4f" +
		"148de395b7217a7ed4fe43046d59d847fae597218654c1e9e12fedcaf815977f95c0adf62895c91bbc6d1394fdead6b5" +
		"17c82b5c9f3696e35bf98ac502975815d6e01b3b0f0c9611945ef62a25055de4416a49b183da628d34b79454680cb323")
	if err != nil {
		t.Fatal(err)
	}

	enc, err := strumok.NewCipher(key512High, ivCount)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	enc.XORKeyStream(got, plaintext)
	if !bytes.Equal(got, want) {
		t.Errorf("encrypt(%x) = %x, want %x", plaintext, got, want)
	}

	// The same stream split at odd points, decrypting in place.
	dec, err := strumok.NewCipher(key512High, ivCount)
	if err != nil {
		t.Fatal(err)
	}
	back := bytes.Clone(want)
	for _, part := range [][]byte{back[:3], back[3:8], back[8:9], back[9:130], back[130:]} {
		dec.XORKeyStream(part, part)
	}
	if !bytes.Equal(back, plaintext) {
		t.Errorf("decrypt in parts = %x, want %x", back, plaintext)
	}
}

func TestNewCipherSizes(t *testing.T) {
	tests := []struct {
		name    string
		key, iv []byte
	}{
		{"nil key", nil, ivZero},
		{"16-byte key", make([]byte, 16), ivZero},
		{"48-byte key", make([]byte, 48), ivZero},
		{"nil IV", key256AA, nil},
		{"16-byte IV", key256AA, make([]byte, 16)},
		{"33-byte IV", key512AA, make([]byte, 33)},
	}
	for _, tt := range tests {
		if _, err := strumok.NewCipher(tt.key, tt.iv); err == nil {
			t.Errorf("NewCipher(%d-byte key, %d-byte IV) error = nil, want an error", len(tt.key), len(tt.iv))
		}
	}
}

func TestShortDst(t *testing.T) {
	s, err := strumok.NewCipher(key256AA, ivZero)
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
