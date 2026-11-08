// Command cryptodstu cross-checks the uacrypto cases against
// github.com/amaneshi/crypto-dstu, another pure-Go implementation of the
// Ukrainian standards. It is a module of its own, so that the uacrypto module
// keeps no dependencies.
//
//	cryptodstu cases.txt cryptodstu_sigs.txt
//
// It checks GOST 34.311, Kupyna, GOST 28147 (block and CFB), Kalyna and
// DSTU 4145 against the case lines of parity gen, and signs the same hashes
// with the same keys; the signature lines it writes go to parity verify.
// crypto-dstu has no GOST 28147 MAC, so those columns are not checked.
package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"hash"
	"maps"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kalyna"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: cryptodstu <cases.txt> <cryptodstu_sigs.txt>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "cryptodstu:", err)
		os.Exit(1)
	}
}

func run(casesPath, sigsPath string) error {
	data, err := os.ReadFile(casesPath) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}

	stats := map[string][2]int{}
	check := func(what string, ok bool, detail string) {
		c := stats[what]
		if ok {
			c[0]++
		} else {
			c[1]++
			fmt.Fprintln(os.Stderr, "MISMATCH", what, detail)
		}
		stats[what] = c
	}

	var sigs bytes.Buffer
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		at := line[:min(len(line), 60)]
		h := make([][]byte, len(f)) // h[i] is f[i] decoded; "-" stays nil
		for i := 1; i < len(f); i++ {
			if f[i] == "-" {
				continue
			}
			if h[i], err = hex.DecodeString(f[i]); err != nil && f[0] != "S" { // S has a decimal curve and index
				return fmt.Errorf("line %q: %w", at, err)
			}
		}
		switch f[0] {
		case "H":
			names := []string{"gost34311", "kupyna256", "kupyna384", "kupyna512"}
			for i, newHash := range []func() hash.Hash{gost34311.New, kupyna.New256, kupyna.New384, kupyna.New512} {
				d := newHash()
				d.Write(h[1])
				check(names[i], bytes.Equal(d.Sum(nil), h[2+i]), at)
			}
		case "C":
			block, err := gost28147.NewCipher(h[1])
			if err != nil {
				return err
			}
			ct := make([]byte, gost28147.BlockSize)
			block.Encrypt(ct, h[2])
			check("gost28147", bytes.Equal(ct, h[3]), at)
		case "G":
			// key iv msg cfb mac32 mac64
			ct, err := gost28147.EncryptCFB(h[1], h[2], h[3])
			if err != nil {
				return err
			}
			check("gost28147 cfb encrypt", bytes.Equal(ct, h[4]), at)
			pt, err := gost28147.DecryptCFB(h[1], h[2], h[4])
			if err != nil {
				return err
			}
			check("gost28147 cfb decrypt", bytes.Equal(pt, h[3]), at)
		case "K":
			// key plaintext ciphertext; the block size is the plaintext length
			newCipher := map[[2]int]func([]byte) (cipher.Block, error){
				{16, 16}: kalyna.NewCipher128_128, {16, 32}: kalyna.NewCipher128_256,
				{32, 32}: kalyna.NewCipher256_256, {32, 64}: kalyna.NewCipher256_512,
				{64, 64}: kalyna.NewCipher512_512,
			}[[2]int{len(h[2]), len(h[1])}]
			block, err := newCipher(h[1])
			if err != nil {
				return err
			}
			ct, pt := make([]byte, len(h[2])), make([]byte, len(h[2]))
			block.Encrypt(ct, h[2])
			block.Decrypt(pt, h[3])
			name := fmt.Sprintf("kalyna %d/%d", 8*len(h[2]), 8*len(h[1]))
			check(name+" encrypt", bytes.Equal(ct, h[3]), at)
			check(name+" decrypt", bytes.Equal(pt, h[2]), at)
		case "S":
			x, err := checkSignature(f, check)
			if err != nil {
				return fmt.Errorf("line %q: %w", at, err)
			}
			sigs.WriteString(x)
		}
	}
	if err := os.WriteFile(sigsPath, sigs.Bytes(), 0o600); err != nil { //nolint:gosec // G703: the operator names the file on the command line
		return err
	}

	failed := 0
	for _, what := range slices.Sorted(maps.Keys(stats)) {
		c := stats[what]
		fmt.Printf("crypto-dstu %-32s %4d ok %d mismatch\n", what, c[0], c[1])
		failed += c[1]
	}
	if failed > 0 {
		return fmt.Errorf("%d mismatches", failed)
	}
	return nil
}

// checkSignature checks the public key and the uacrypto signature of the line
// S <curve> <index> <d> <Q> <hash> <r> <s> <r||s> and returns the X line of
// its own signature of the same hash with the same key.
//
// uacrypto, like IIT, reads the hash as a little-endian
// number; crypto-dstu reads the digest it is given as big-endian, so the hash
// is reversed on the way in. Both number the curves DSTU_PB_163..431 from 0.
func checkSignature(f []string, check func(string, bool, string)) (string, error) {
	id, err := strconv.Atoi(f[1])
	if err != nil || id < 0 || id > 9 {
		return "", fmt.Errorf("curve %q", f[1])
	}
	curve := dstu4145.AllParams()[id].Curve
	at := "curve " + f[1] + " #" + f[2]
	d, okD := new(big.Int).SetString(f[3], 16)
	r, okR := new(big.Int).SetString(f[6], 16)
	s, okS := new(big.Int).SetString(f[7], 16)
	q, errQ := hex.DecodeString(f[4])
	digest, errH := hex.DecodeString(f[5])
	if !okD || !okR || !okS || errQ != nil || errH != nil {
		return "", fmt.Errorf("%s: malformed key, hash or signature", at)
	}
	slices.Reverse(digest)

	priv := &dstu4145.PrivateKey{D: d, Curve: curve}
	pub := priv.Public()
	check("dstu4145 public key from d", bytes.Equal(pub.Q.Compress(), q), at)
	point, err := curve.Expand(q)
	if err != nil {
		return "", fmt.Errorf("%s: %w", at, err)
	}
	check("dstu4145 decode Go key", point.Equal(pub.Q), at)
	goSig := &dstu4145.Signature{R: gf2m.FromBytes(r.Bytes(), curve.Words), S: s}
	check("dstu4145 verify Go signature", dstu4145.Verify(&dstu4145.PublicKey{Q: point, Curve: curve}, digest, goSig), at)

	sig, err := dstu4145.Sign(nil, priv, digest)
	if err != nil {
		return "", fmt.Errorf("%s: %w", at, err)
	}
	return fmt.Sprintf("X crypto-dstu %s %s %s %x %x\n", f[1], f[4], f[5], new(big.Int).SetBytes(sig.R.Bytes()), sig.S), nil
}
