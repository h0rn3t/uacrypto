// The parity command cross-checks uacrypto against other implementations of
// the same standards (see README.md in this directory).
//
//	parity gen > cases.txt          deterministic random cases computed by uacrypto
//	parity verify signatures.txt    checks signatures made by the other implementations
//	parity czo CACertificates.p7b   checks every DSTU 4145 certificate of the CZO bundle against its issuer
//	parity cms rust.txt go.txt      checks the CMS signatures of ua-cryptography-pki and signs with the same keys
//	parity tsa URL rust_cms.txt rust_t.txt go.txt
//	                                checks the CAdES-T of ua-cryptography-pki and makes CAdES-T with the TSA at URL
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
	"bytes"
	"context"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kalyna"
	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/pki"
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
	case len(args) == 2 && args[0] == "czo":
		return checkBundle(args[1], out)
	case len(args) == 3 && args[0] == "cms":
		return checkCMS(args[1], args[2], out)
	case len(args) == 5 && args[0] == "tsa":
		return checkCAdEST(args[1], args[2], args[3], args[4], out)
	}
	return errors.New("usage: parity gen | parity verify <signatures.txt> | parity czo <CACertificates.p7b> | parity cms <rust.txt> <go.txt> | parity tsa <URL> <rust_cms.txt> <rust_t.txt> <go.txt>")
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

// checkBundle verifies each certificate of a PKCS#7 bundle whose issuer, found
// by key identifier, has a DSTU 4145 key. It fails on any rejected signature.
func checkBundle(path string, out io.Writer) error {
	data, err := os.ReadFile(path) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}
	var bundle struct {
		Type       asn1.ObjectIdentifier
		SignedData struct {
			Version      int
			Digests      asn1.RawValue
			Content      asn1.RawValue
			Certificates asn1.RawValue `asn1:"optional,tag:0"`
			SignerInfos  asn1.RawValue
		} `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("PKCS#7 bundle: %w", err)
	}
	var certs []*x509.Certificate
	for rest := bundle.SignedData.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return fmt.Errorf("bundle certificate: %w", err)
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}

	var ok, other, orphans, rejected int
	var report strings.Builder
	for _, c := range certs {
		i := slices.IndexFunc(certs, func(p *x509.Certificate) bool {
			return len(c.AuthorityKeyId) > 0 && bytes.Equal(p.SubjectKeyId, c.AuthorityKeyId)
		})
		if i < 0 {
			orphans++
			continue
		}
		err := pki.CheckCertificateSignature(c, certs[i])
		switch {
		case err == nil:
			ok++
		case errors.Is(err, x509.ErrUnsupportedAlgorithm) && c.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm && certs[i].PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm:
			other++ // RSA or ECDSA on both sides: crypto/x509's business
		default:
			rejected++
			fmt.Fprintf(&report, "REJECTED %s: %v\n", c.Subject, err)
		}
	}
	fmt.Fprintf(&report, "CZO bundle: %d certificates, DSTU 4145 %d ok %d rejected; %d RSA/ECDSA, %d without issuer in the bundle\n",
		len(certs), ok, rejected, other, orphans)
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	if rejected > 0 {
		return fmt.Errorf("%d certificates rejected", rejected)
	}
	return nil
}

// checkCMS reads the lines R <curve> <d> <certificate> <hash> <detached> <content> <signature>
// of ua-cryptography-pki, checks the self-signed certificate and the CMS
// signature, and signs the same content with the same key and options into
// goPath as G <certificate> <hash> <detached> <content> <signature>.
func checkCMS(rustPath, goPath string, out io.Writer) error {
	data, err := os.ReadFile(rustPath) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}
	var signed strings.Builder
	var certsOK, cmsOK int
	var report strings.Builder
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) != 8 || f[0] != "R" {
			return fmt.Errorf("malformed line %q", line)
		}
		id, err := strconv.Atoi(f[1])
		if err != nil {
			return err
		}
		c, err := dstu4145.NamedCurve(id)
		if err != nil {
			return err
		}
		d, certDER, sig := decode(f[2]), decode(f[3]), decode(f[7])
		content := decode(f[6])
		key, err := dstu4145.NewPrivateKey(c, d)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return err
		}
		tag := fmt.Sprintf("curve %d %s detached=%s", id, f[4], f[5])
		if err := pki.CheckCertificateSignature(cert, cert); err != nil {
			fmt.Fprintf(&report, "MISMATCH certificate %s: %v\n", tag, err)
		} else {
			certsOK++
		}
		var detached []byte
		if f[5] == "1" {
			detached = content
		}
		if _, _, err := pki.VerifySignedData(sig, detached, nil); err != nil {
			fmt.Fprintf(&report, "MISMATCH CMS %s: %v\n", tag, err)
		} else {
			cmsOK++
		}

		own, err := pki.SignData(crand.Reader, content, key, cert, pki.SignOptions{Detached: f[5] == "1", GOST34311: f[4] == "gost"})
		if err != nil {
			return fmt.Errorf("SignData %s: %w", tag, err)
		}
		fmt.Fprintln(&signed, "G", f[3], f[4], f[5], f[6], encode(own))
	}
	if err := os.WriteFile(goPath, []byte(signed.String()), 0o600); err != nil { //nolint:gosec // G703: the operator names the file on the command line
		return err
	}
	total := strings.Count(string(data), "\n")
	fmt.Fprintf(&report, "uacrypto verifies ua-cryptography-pki certificates %4d ok %d rejected\n", certsOK, total-certsOK)
	fmt.Fprintf(&report, "uacrypto verifies ua-cryptography-pki CMS          %4d ok %d rejected\n", cmsOK, total-cmsOK)
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	if certsOK != total || cmsOK != total {
		return errors.New("ua-cryptography-pki signatures rejected")
	}
	return nil
}

// decode reads a hex field, "-" for empty, as a non-nil slice.
func decode(s string) []byte {
	if s == "-" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("parity: bad hex %q", s))
	}
	return b
}

// checkCAdEST verifies the CAdES-T lines T <certificate> <hash> <content> <signature>
// of ua-cryptography-pki, then signs with the first two keys of rustCMS,
// stamps the signatures at the TSA url and writes them to goPath in the G
// format of checkCMS.
func checkCAdEST(url, rustCMS, rustT, goPath string, out io.Writer) error {
	var report strings.Builder
	data, err := os.ReadFile(rustT) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) != 5 || f[0] != "T" {
			return fmt.Errorf("malformed line %q", line)
		}
		_, signers, err := pki.VerifySignedData(decode(f[4]), nil, nil)
		if err != nil {
			return fmt.Errorf("ua-cryptography-pki CAdES-T %s: %w", f[2], err)
		}
		ts := signers[0].TimeStamp
		if ts == nil {
			return fmt.Errorf("ua-cryptography-pki CAdES-T %s carries no signature time-stamp", f[2])
		}
		fmt.Fprintf(&report, "uacrypto verifies ua-cryptography-pki CAdES-T %-6s ok: stamped %s by %s\n", f[2], ts.Time.Format(time.RFC3339), ts.Certificate.Subject.CommonName)
	}

	data, err = os.ReadFile(rustCMS) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}
	tsa := &pki.TSAClient{URL: url}
	var signed strings.Builder
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if f[1] != "6" || f[5] != "0" { // M257 keys, attached content
			continue
		}
		c, err := dstu4145.NamedCurve(6)
		if err != nil {
			return err
		}
		key, err := dstu4145.NewPrivateKey(c, decode(f[2]))
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(decode(f[3]))
		if err != nil {
			return err
		}
		content := []byte("uacrypto CAdES-T " + f[4])
		bes, err := pki.SignData(crand.Reader, content, key, cert, pki.SignOptions{GOST34311: f[4] == "gost"})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cadesT, err := pki.AddSignatureTimeStamp(ctx, bes, tsa)
		cancel()
		if err != nil {
			return fmt.Errorf("AddSignatureTimeStamp %s: %w", f[4], err)
		}
		_, signers, err := pki.VerifySignedData(cadesT, nil, nil)
		if err != nil || signers[0].TimeStamp == nil {
			return fmt.Errorf("uacrypto CAdES-T %s does not verify: %v", f[4], err)
		}
		fmt.Fprintf(&report, "uacrypto CAdES-T %-6s stamped %s by %s\n", f[4], signers[0].TimeStamp.Time.Format(time.RFC3339), signers[0].TimeStamp.Certificate.Subject.CommonName)
		fmt.Fprintln(&signed, "G", f[3], f[4], "0", encode(content), encode(cadesT))
		if strings.Count(signed.String(), "\n") == 2 {
			break
		}
	}
	if err := os.WriteFile(goPath, []byte(signed.String()), 0o600); err != nil { //nolint:gosec // G703: the operator names the file on the command line
		return err
	}
	_, err = io.WriteString(out, report.String())
	return err
}
