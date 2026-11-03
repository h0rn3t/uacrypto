package dstu4145_test

import (
	"crypto/rand"
	"fmt"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost34311"
)

func Example() {
	c, err := dstu4145.NamedCurve(6) // M257
	if err != nil {
		panic(err)
	}
	key, err := dstu4145.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	digest := gost34311.Sum([]byte("message"))
	r, s, err := dstu4145.Sign(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	fmt.Println(dstu4145.Verify(key.Public(), digest[:], r, s))
	// Output: true
}
