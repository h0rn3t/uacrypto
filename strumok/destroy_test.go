package strumok

import (
	"bytes"
	"testing"
)

func TestDestroy(t *testing.T) {
	for _, n := range []int{KeySize256, KeySize512} {
		v, err := NewCipher(bytes.Repeat([]byte{0xa5}, n), make([]byte, IVSize))
		if err != nil {
			t.Fatal(err)
		}
		v.XORKeyStream(make([]byte, 3), make([]byte, 3)) // leave a partial word
		Destroy(v)
		Destroy(v)
		c := v.(*stream)
		if c.s != [16]uint64{} || c.r1 != 0 || c.r2 != 0 || c.word != [8]byte{} {
			t.Errorf("Destroy(%d-byte key) left secret state", n)
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("XORKeyStream after Destroy(%d-byte key) did not panic", n)
				}
			}()
			v.XORKeyStream(make([]byte, 1), []byte{0})
		}()
	}
}
