package kalyna_test

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/h0rn3t/uacrypto/kalyna"
)

func Example() {
	key := make([]byte, 32)
	rand.Read(key)
	block, err := kalyna.NewCipher256(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, block.BlockSize()) // a fresh IV for every message
	rand.Read(iv)
	msg := []byte("повідомлення")

	ciphertext := make([]byte, len(msg))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, msg)
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
	fmt.Println(string(plaintext))
	// Output: повідомлення
}
