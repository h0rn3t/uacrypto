// The parity command cross-checks uacrypto against other implementations of
// the same standards (see README.md in this directory).
//
//	parity gen > cases.txt          deterministic random cases computed by uacrypto
//	parity verify signatures.txt    checks signatures made by the other implementations
//
// Case lines are space-separated hex ("-" for an empty value):
//
//	H <message> <gost34311> <kupyna256> <kupyna384> <kupyna512>
//	C <key> <plaintext> <ciphertext>
//	K <key> <plaintext> <ciphertext>                   Kalyna; the block size is the plaintext length
//	S <curve> <index> <d> <Q> <hash> <r> <s> <r||s>    r||s as dstu4145.MarshalSignature encodes it
//
// Signature lines from the other implementations:
//
//	X <source> <curve> <Q> <hash> <r> <s>
package main

import (
	"bufio"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kalyna"
	"github.com/h0rn3t/uacrypto/kupyna"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "parity:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "gen":
		w := bufio.NewWriter(out)
		if err := generate(w); err != nil {
			return err
		}
		return w.Flush()
	case len(args) == 2 && args[0] == "verify":
		return verify(args[1], out)
	}
	return errors.New("usage: parity gen | parity verify <signatures.txt>")
}

func encode(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

// generate writes the cases; a fixed seed keeps them identical between runs.
func generate(w io.Writer) error {
	rng := rand.NewChaCha8([32]byte{'u', 'a', 'c', 'r', 'y', 'p', 't', 'o'})
	r := rand.New(rng) //nolint:gosec // G404: reproducible test data, not secrets

	// block boundaries of GOST 34.311 (32) and Kupyna (64, 128), then random lengths
	lengths := []int{0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096}
	for range 300 {
		lengths = append(lengths, r.IntN(2048))
	}
	for _, n := range lengths {
		msg := make([]byte, n)
		_, _ = rng.Read(msg) // ChaCha8.Read never fails
		g := gost34311.Sum(msg)
		k256, k384, k512 := kupyna.Sum256(msg), kupyna.Sum384(msg), kupyna.Sum512(msg)
		if _, err := fmt.Fprintln(w, "H", encode(msg), encode(g[:]), encode(k256[:]), encode(k384[:]), encode(k512[:])); err != nil {
			return err
		}
	}

	for range 300 {
		key, plaintext := make([]byte, gost28147.KeySize), make([]byte, gost28147.BlockSize)
		_, _ = rng.Read(key) // ChaCha8.Read never fails
		_, _ = rng.Read(plaintext)
		block, err := gost28147.NewCipher(key, gost28147.DKE1())
		if err != nil {
			return err
		}
		ciphertext := make([]byte, gost28147.BlockSize)
		block.Encrypt(ciphertext, plaintext)
		if _, err := fmt.Fprintln(w, "C", encode(key), encode(plaintext), encode(ciphertext)); err != nil {
			return err
		}
	}

	kalynas := []struct {
		newCipher func([]byte) (cipher.Block, error)
		keySize   int
	}{
		{kalyna.NewCipher128, 16}, {kalyna.NewCipher128, 32},
		{kalyna.NewCipher256, 32}, {kalyna.NewCipher256, 64},
		{kalyna.NewCipher512, 64},
	}
	for _, k := range kalynas {
		for range 60 {
			key := make([]byte, k.keySize)
			_, _ = rng.Read(key) // ChaCha8.Read never fails
			block, err := k.newCipher(key)
			if err != nil {
				return err
			}
			plaintext, ciphertext := make([]byte, block.BlockSize()), make([]byte, block.BlockSize())
			_, _ = rng.Read(plaintext)
			block.Encrypt(ciphertext, plaintext)
			if _, err := fmt.Fprintln(w, "K", encode(key), encode(plaintext), encode(ciphertext)); err != nil {
				return err
			}
		}
	}

	// hash lengths per curve: GOST 34.311 and Kupyna digests, a 1-byte hash and
	// a zero hash, which DSTU 4145 replaces with 1
	hashLengths := []int{32, 32, 32, 32, 32, 32, 64, 48, 1, 0}
	for id := range 10 {
		c, err := dstu4145.NamedCurve(id)
		if err != nil {
			return err
		}
		for i, n := range hashLengths {
			key, err := dstu4145.GenerateKey(c, rng)
			if err != nil {
				return err
			}
			hash := make([]byte, max(n, 32))
			if n > 0 {
				hash = hash[:n]
				_, _ = rng.Read(hash) // ChaCha8.Read never fails
			}
			rr, ss, err := dstu4145.Sign(rng, key, hash)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, "S", id, i, encode(key.Bytes()), encode(key.Public().Bytes()), encode(hash), rr.Text(16), ss.Text(16), encode(dstu4145.MarshalSignature(c, rr, ss))); err != nil {
				return err
			}
		}
	}
	return nil
}

// verify checks every signature line with uacrypto and fails if any is rejected.
func verify(path string, out io.Writer) error {
	data, err := os.ReadFile(path) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}

	ok, failed := map[string]int{}, map[string]int{}
	var sources []string
	var report strings.Builder
	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) != 7 || fields[0] != "X" {
			return fmt.Errorf("malformed line %q", line)
		}
		source := fields[1]
		if ok[source]+failed[source] == 0 {
			sources = append(sources, source)
		}
		accepted, err := verifyLine(fields)
		if err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		if accepted {
			ok[source]++
		} else {
			failed[source]++
			fmt.Fprintln(&report, "REJECTED", strings.Join(fields, " "))
		}
	}

	total := 0
	for _, s := range sources {
		fmt.Fprintf(&report, "uacrypto verifies %-16s %4d ok %d rejected\n", s, ok[s], failed[s])
		total += failed[s]
	}
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	if total > 0 {
		return fmt.Errorf("%d signatures rejected", total)
	}
	return nil
}

func verifyLine(fields []string) (bool, error) {
	id, err := strconv.Atoi(fields[2])
	if err != nil {
		return false, fmt.Errorf("curve %q: %w", fields[2], err)
	}
	c, err := dstu4145.NamedCurve(id)
	if err != nil {
		return false, err
	}
	q, err := hex.DecodeString(fields[3])
	if err != nil {
		return false, fmt.Errorf("public key: %w", err)
	}
	pub, err := dstu4145.ParsePublicKey(c, q)
	if err != nil {
		return false, err
	}
	hash, err := hex.DecodeString(fields[4])
	if err != nil {
		return false, fmt.Errorf("hash: %w", err)
	}
	r, okR := new(big.Int).SetString(fields[5], 16)
	s, okS := new(big.Int).SetString(fields[6], 16)
	if !okR || !okS {
		return false, fmt.Errorf("signature %s %s is not hex", fields[5], fields[6])
	}
	return dstu4145.Verify(pub, hash, r, s), nil
}
