package kalyna_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/h0rn3t/uacrypto/kalyna"
)

func TestGCMNonceAuthentication(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		for _, size := range []int{0, 1, 2 * n} {
			for _, aadSize := range []int{0, 3} {
				t.Run(fmt.Sprintf("block=%d/plain=%d/aad=%d", n, size, aadSize), func(t *testing.T) {
					t.Parallel()
					g, err := kalyna.NewGCM(mustCipher(t, n, n), 16)
					if err != nil {
						t.Fatal(err)
					}
					nonce := sequence(1, n)
					aad := sequence(9, aadSize)
					sealed, err := g.Seal(nonce, sequence(20, size), aad)
					if err != nil {
						t.Fatalf("Seal() error = %v", err)
					}
					for i := range nonce {
						nonce[i] ^= 1
						got, err := g.Open(nonce, sealed, aad)
						if !errors.Is(err, kalyna.ErrAuthentication) || got != nil {
							t.Errorf("Open(nonce byte %d changed) = %x, %v; want nil, ErrAuthentication", i, got, err)
						}
						nonce[i] ^= 1
					}
				})
			}
		}
	}
}

func TestModeNonceLength(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		t.Run(fmt.Sprintf("block=%d", n), func(t *testing.T) {
			t.Parallel()
			b := mustCipher(t, n, n)
			g, err := kalyna.NewGCM(b, 16)
			if err != nil {
				t.Fatal(err)
			}
			c, err := kalyna.NewCCM(b, 4, 16)
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []struct {
				name string
				seal func([]byte, []byte, []byte) ([]byte, error)
				open func([]byte, []byte, []byte) ([]byte, error)
			}{
				{"GCM", g.Seal, g.Open},
				{"CCM", c.Seal, c.Open},
			} {
				sealed, err := mode.seal(make([]byte, n), []byte("message"), nil)
				if err != nil {
					t.Fatalf("%s Seal(full nonce) error = %v", mode.name, err)
				}
				for _, size := range []int{0, 1, 2, n - 1, n + 1} {
					nonce := make([]byte, size)
					if got, err := mode.seal(nonce, nil, nil); err == nil || errors.Is(err, kalyna.ErrAuthentication) || got != nil {
						t.Errorf("%s Seal(nonce length %d) = %x, %v; want nil, parameter error", mode.name, size, got, err)
					}
					if got, err := mode.open(nonce, sealed, nil); err == nil || errors.Is(err, kalyna.ErrAuthentication) || got != nil {
						t.Errorf("%s Open(nonce length %d) = %x, %v; want nil, parameter error", mode.name, size, got, err)
					}
				}
			}
		})
	}
}
