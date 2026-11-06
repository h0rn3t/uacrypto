// The iit command checks the EU Sign library of IIT («Користувач ЦСК»), which
// is certified in Ukraine but ships only as a binary, against the reference
// examples of the standards and against uacrypto:
//
//	go run . /path/to/euscp.dylib
//
// It needs cgo and the library with its modules; no key, certificate or
// settings file. The library's GOST 34.311 (ДКЕ №1), Kupyna-256/384/512,
// Kalyna-256 in CFB mode and Kalyna-256 MAC are compared on the examples of
// DSTU 7564 and DSTU 7624 and on reproducible random inputs that cross every
// block boundary. Any mismatch makes the exit code non-zero.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"

	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kalyna"
	"github.com/h0rn3t/uacrypto/kupyna"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "iit:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: iit <path to euscp.dylib or euscp.so>")
	}
	lib, err := openLibrary(args[0])
	if err != nil {
		return err
	}

	t := &tally{}
	checkExamples(lib, t)
	checkHashes(lib, t)
	checkKalyna(lib, t)
	t.report = fmt.Appendf(t.report, "%d cases, %d mismatches, %d notes\n", t.cases, t.failures, t.notes)
	if _, err := out.Write(t.report); err != nil {
		return err
	}
	if t.failures > 0 {
		return fmt.Errorf("%d mismatches", t.failures)
	}
	return nil
}

// tally counts the cases and keeps the report of the mismatches and notes.
type tally struct {
	report                 []byte
	cases, failures, notes int
}

func (t *tally) expect(what string, got []byte, err error, want []byte) {
	t.cases++
	switch {
	case err != nil:
		t.failures++
		t.report = fmt.Appendf(t.report, "FAIL %s: %v\n", what, err)
	case !bytes.Equal(got, want):
		t.failures++
		t.report = fmt.Appendf(t.report, "FAIL %s:\n  got  %x\n  want %x\n", what, got, want)
	}
}

func (t *tally) note(format string, args ...any) {
	t.notes++
	t.report = fmt.Appendf(t.report, "NOTE "+format+"\n", args...)
}

// sequence returns n bytes start, start+1, ...: the inputs of the examples in
// DSTU 7564 and DSTU 7624.
func sequence(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i) //nolint:gosec // G115: wraps by design, the pattern continues mod 256
	}
	return b
}

// checkExamples holds both the library and uacrypto to the examples printed
// in the standards. GOST 34.311-95 has no example with ДКЕ №1, so it is
// checked only against uacrypto.
func checkExamples(lib *library, t *tally) {
	examples := []struct {
		name string
		algo int
		sum  func([]byte) []byte
		in   []byte
		want string
	}{
		{"DSTU 7564 Kupyna-256, empty", hashKupyna256, kupyna256, nil,
			"cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6"},
		{"DSTU 7564 Kupyna-256, 512 bits", hashKupyna256, kupyna256, sequence(0, 64),
			"08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875"},
		{"DSTU 7564 Kupyna-512, 512 bits", hashKupyna512, kupyna512, sequence(0, 64),
			"3813e2109118cdfb5a6d5e72f7208dccc80a2dfb3afdfb02f46992b5edbe536b3560dd1d7e29c6f53978af58b444e37ba685c0dd910533ba5d78efffc13de62a"},
	}
	for _, e := range examples {
		want, _ := hex.DecodeString(e.want) // literals above
		t.expect(e.name+" (uacrypto)", e.sum(e.in), nil, want)
		got, err := lib.hash(e.algo, e.in)
		if len(e.in) == 0 && err != nil {
			t.note("%s: IIT rejects an empty message: %v", e.name, err)
			continue
		}
		t.expect(e.name+" (IIT)", got, err, want)
	}

	// The 256/256 example of DSTU 7624: key 00..1f, plaintext 20..3f. CFB of a
	// zero block under IV 20..3f is the encryption of the IV itself.
	want, _ := hex.DecodeString("f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c")
	block, err := kalyna.NewCipher256(sequence(0, 32))
	if err != nil {
		t.expect("DSTU 7624 Kalyna 256/256 (uacrypto)", nil, err, want)
		return
	}
	ours := make([]byte, 32)
	block.Encrypt(ours, sequence(32, 32))
	t.expect("DSTU 7624 Kalyna 256/256 (uacrypto)", ours, nil, want)
	got, err := lib.encryptCFB(sequence(0, 32), sequence(32, 32), make([]byte, 32))
	t.expect("DSTU 7624 Kalyna 256/256 (IIT, CFB of a zero block)", got, err, want)
}

func kupyna256(b []byte) []byte { s := kupyna.Sum256(b); return s[:] }
func kupyna384(b []byte) []byte { s := kupyna.Sum384(b); return s[:] }
func kupyna512(b []byte) []byte { s := kupyna.Sum512(b); return s[:] }

// newRand returns the reproducible source of the random cases.
func newRand() *rand.ChaCha8 {
	return rand.NewChaCha8([32]byte{'u', 'a', 'c', 'r', 'y', 'p', 't', 'o', '-', 'i', 'i', 't'})
}

func randomBytes(r *rand.ChaCha8, n int) []byte {
	b := make([]byte, n)
	_, _ = r.Read(b) // always fills b, never fails
	return b
}

// checkHashes compares every length up to three Kupyna-512 blocks and a few
// long inputs: GOST 34.311 works on 32-byte blocks, Kupyna on 64 and 128.
func checkHashes(lib *library, t *tally) {
	hashes := []struct {
		name string
		algo int
		sum  func([]byte) []byte
	}{
		{"GOST 34.311", hashGOST34311, func(b []byte) []byte { s := gost34311.Sum(b); return s[:] }},
		{"Kupyna-256", hashKupyna256, kupyna256},
		{"Kupyna-384", hashKupyna384, kupyna384},
		{"Kupyna-512", hashKupyna512, kupyna512},
	}
	r := newRand()
	var lengths []int
	for n := range 3*128 + 1 {
		lengths = append(lengths, n)
	}
	for _, n := range append(lengths, 1000, 4095, 4096, 4097, 65536+13) {
		data := randomBytes(r, n)
		for _, h := range hashes {
			what := fmt.Sprintf("%s of %d bytes %.32x…", h.name, n, data)
			got, err := lib.hash(h.algo, data)
			if n == 0 && err != nil {
				t.note("%s: IIT rejects an empty message: %v", what, err)
				continue
			}
			t.expect(what, got, err, h.sum(data))
		}
	}
}

// checkKalyna compares CFB on every length up to seven blocks and the MAC on
// every length up to four blocks, with each MAC size the library names.
func checkKalyna(lib *library, t *tally) {
	r := newRand()
	for n := range 7*32 + 1 {
		key, iv, plaintext := randomBytes(r, 32), randomBytes(r, 32), randomBytes(r, n)
		block, err := kalyna.NewCipher256(key)
		if err != nil {
			t.expect("Kalyna-256 key", nil, err, nil)
			return
		}
		cfb, err := kalyna.NewCFB(block, 32)
		if err != nil {
			t.expect("Kalyna-256 CFB", nil, err, nil)
			return
		}
		want, err := cfb.Encrypt(iv, plaintext)
		if err != nil {
			t.expect("Kalyna-256 CFB (uacrypto)", nil, err, nil)
			continue
		}
		got, err := lib.encryptCFB(key, iv, plaintext)
		t.expect(fmt.Sprintf("Kalyna-256 CFB of %d bytes, key %x", n, key), got, err, want)
	}

	for n := range 4*32 + 1 {
		key, iv, data := randomBytes(r, 32), randomBytes(r, 32), randomBytes(r, n)
		block, err := kalyna.NewCipher256(key)
		if err != nil {
			t.expect("Kalyna-256 key", nil, err, nil)
			return
		}
		for _, size := range []int{8, 16, 32} {
			what := fmt.Sprintf("Kalyna-256 MAC-%d of %d bytes, key %x", size*8, n, key)
			want, err := kalyna.CMAC(block, data, size)
			if err != nil {
				t.expect(what+" (uacrypto)", nil, err, nil)
				continue
			}
			got, err := lib.mac(key, iv, data, size)
			if n == 0 && err != nil {
				t.note("%s: IIT rejects an empty message (%v), uacrypto gives the MAC of one zero block", what, err)
				continue
			}
			t.expect(what, got, err, want)
		}
	}
}
