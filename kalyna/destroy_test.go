package kalyna

import (
	"bytes"
	"strconv"
	"testing"
)

func TestDestroy(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			block, err := newCipher(n, bytes.Repeat([]byte{0xa5}, n), n)
			if err != nil {
				t.Fatal(err)
			}
			keys := block.(*kalyna).keys
			Destroy(block)
			Destroy(block)
			for i, key := range keys {
				if !bytes.Equal(key, make([]byte, len(key))) {
					t.Errorf("Destroy left round key %d: %x", i, key)
				}
			}
			for _, op := range []struct {
				name string
				call func([]byte, []byte)
			}{{"Encrypt", block.Encrypt}, {"Decrypt", block.Decrypt}} {
				t.Run(op.name, func(t *testing.T) {
					defer func() {
						if recover() == nil {
							t.Errorf("%s after Destroy did not panic", op.name)
						}
					}()
					op.call(make([]byte, n), make([]byte, n))
				})
			}
		})
	}
}
