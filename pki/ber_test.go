package pki_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/h0rn3t/uacrypto/pki"
)

// berSeq is a SEQUENCE with the indefinite length of BER: 30 80 … 00 00.
func berSeq(parts ...[]byte) []byte {
	b := []byte{0x30, 0x80}
	for _, p := range parts {
		b = append(b, p...)
	}
	return append(b, 0, 0)
}

// nestedSeq is n nested SEQUENCEs with 4-byte lengths: 30 84 xx xx xx xx.
func nestedSeq(n int) []byte {
	b := make([]byte, 0, 6*n+2)
	for i := range n {
		l := 6*(n-1-i) + 2
		b = append(b, 0x30, 0x84, byte(l>>24), byte(l>>16), byte(l>>8), byte(l)) //nolint:gosec // G115: the octets of l
	}
	return append(b, 0x30, 0x00)
}

func TestToDER(t *testing.T) {
	five := []byte{0x02, 0x01, 0x05}
	seq := func(body ...byte) []byte { return append([]byte{0x30, byte(len(body))}, body...) } //nolint:gosec // G115: short bodies
	long := append([]byte{0x04, 0x82, 0x01, 0x2c}, make([]byte, 300)...)                       // a 300-byte OCTET STRING
	longSeq := append([]byte{0x30, 0x82, 0x01, 0x30}, long...)
	tests := []struct {
		name    string
		in, der []byte
	}{
		{"DER stays", seq(seq(five...)...), seq(seq(five...)...)},
		{"indefinite outer", berSeq(seq(five...), []byte{0x04, 0x02, 1, 2}), seq(append(seq(five...), 0x04, 0x02, 1, 2)...)},
		{"indefinite nested", berSeq(berSeq(five)), seq(seq(five...)...)},
		{"non-minimal length", []byte{0x30, 0x81, 0x03, 0x02, 0x01, 0x05}, seq(five...)},
		{"non-minimal primitive length", []byte{0x02, 0x82, 0x00, 0x01, 0x05}, five},
		{"BER child of a DER parent", append([]byte{0x30, 0x82, 0x01, 0x34}, berSeq(long)...), append([]byte{0x30, 0x82, 0x01, 0x34}, longSeq...)},
		{"multi-byte tag", []byte{0xbf, 0x81, 0x00, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00}, []byte{0xbf, 0x81, 0x00, 0x03, 0x02, 0x01, 0x05}},
		{"shallow nesting", nestedSeq(32), nil},
		{"chunked OCTET STRING", []byte{0x24, 0x80, 0x04, 0x01, 'a', 0x04, 0x02, 'b', 'c', 0x00, 0x00}, []byte{0x04, 0x03, 'a', 'b', 'c'}},
		{"definite chunked OCTET STRING", []byte{0x24, 0x06, 0x04, 0x01, 'a', 0x04, 0x01, 'b'}, []byte{0x04, 0x02, 'a', 'b'}},
		{"nested chunks", []byte{0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 'a', 0x00, 0x00, 0x04, 0x01, 'b', 0x00, 0x00}, []byte{0x04, 0x02, 'a', 'b'}},
		{"no chunks", []byte{0x24, 0x80, 0x00, 0x00}, []byte{0x04, 0x00}},
		{"chunked OCTET STRING in a SEQUENCE", berSeq([]byte{0x24, 0x80, 0x04, 0x01, 'a', 0x00, 0x00}, five), []byte{0x30, 0x06, 0x04, 0x01, 'a', 0x02, 0x01, 0x05}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pki.ToDER(tt.in)
			if err != nil {
				t.Fatalf("toDER(%x) error = %v", tt.in, err)
			}
			if tt.der != nil && !bytes.Equal(got, tt.der) {
				t.Errorf("toDER(%x) = %x, want %x", tt.in, got, tt.der)
			}
		})
	}

	for name, in := range map[string][]byte{
		"primitive indefinite":       {0x04, 0x80, 0x01, 0x00, 0x00},
		"missing end-of-contents":    {0x30, 0x80, 0x02, 0x01, 0x05},
		"length past the end":        {0x30, 0x05, 0x02, 0x01, 0x05},
		"5-byte length":              {0x30, 0x85, 0, 0, 0, 0, 3, 0x02, 0x01, 0x05},
		"trailing data":              {0x02, 0x01, 0x05, 0x00},
		"end-of-contents in DER":     {0x30, 0x02, 0x00, 0x00},
		"empty":                      nil,
		"deeper than 64 levels":      nestedSeq(65),
		"truncated multi-byte tag":   {0xbf, 0x81},
		"INTEGER in an OCTET STRING": {0x24, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00},
	} {
		if got, err := pki.ToDER(in); err == nil {
			t.Errorf("toDER(%s %x) = %x, want error", name, in, got)
		}
	}

	// Bouncy Castle re-encoded these DER signatures in BER: back in DER they are the originals
	for _, file := range []string{"czo-test-xlong-full-gost", "tsa-diia-kupyna"} {
		der, err := os.ReadFile(filepath.Join("testdata", file+".p7s"))
		if err != nil {
			t.Fatal(err)
		}
		ber, err := os.ReadFile(filepath.Join("testdata", file+"-ber.p7s"))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := pki.ToDER(ber); err != nil || !bytes.Equal(got, der) {
			t.Errorf("toDER(%s-ber.p7s) = %d bytes, %v; want the %d bytes of %s.p7s", file, len(got), err, len(der), file)
		}
	}
}
