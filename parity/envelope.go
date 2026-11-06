package main

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/pki"
)

// envelopeParty is a key agreement key with its self-signed certificate.
type envelopeParty struct {
	curve int
	key   *dstu4145.PrivateKey
	cert  *x509.Certificate
}

func newEnvelopeParty(curve int, serial int64, name string) (envelopeParty, error) {
	c, err := dstu4145.NamedCurve(curve)
	if err != nil {
		return envelopeParty{}, err
	}
	key, err := dstu4145.GenerateKey(c, crand.Reader)
	if err != nil {
		return envelopeParty{}, err
	}
	spki, err := pki.MarshalPublicKey(&pki.PublicKey{Key: key.Public(), DKE: gost28147.DKE1()})
	if err != nil {
		return envelopeParty{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	der, err := pki.CreateCertificate(crand.Reader, tmpl, tmpl, spki, key)
	if err != nil {
		return envelopeParty{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return envelopeParty{}, err
	}
	return envelopeParty{curve, key, cert}, nil
}

// envelopeGen writes envelopes from uacrypto for jkurwa to decrypt, one line
// each, on the three curves jkurwa has and once from a sender on another
// curve than the recipient, which takes an ephemeral key:
//
//	E <sender curve> <sender d> <sender cert> <recipient curve> <recipient d> <recipient cert> <content> <envelope>
func envelopeGen(path string) error {
	pairs := [][2]int{{4, 4}, {6, 6}, {9, 9}, {6, 9}}
	w := new(bytes.Buffer)
	for i, p := range pairs {
		sender, err := newEnvelopeParty(p[0], int64(2*i+1), "uacrypto sender "+strconv.Itoa(i))
		if err != nil {
			return err
		}
		recipient, err := newEnvelopeParty(p[1], int64(2*i+2), "uacrypto recipient "+strconv.Itoa(i))
		if err != nil {
			return err
		}
		content := make([]byte, 1+100*i)
		_, _ = crand.Read(content) // crypto/rand.Read never fails
		env, err := pki.EncryptEnvelopedData(crand.Reader, content, sender.key, sender.cert, []*x509.Certificate{recipient.cert})
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "E", sender.curve, encode(sender.key.Bytes()), encode(sender.cert.Raw),
			recipient.curve, encode(recipient.key.Bytes()), encode(recipient.cert.Raw), encode(content), encode(env))
	}
	return os.WriteFile(path, w.Bytes(), 0o600) //nolint:gosec // G703: the operator names the file on the command line
}

// envelopeCheck decrypts with uacrypto the envelopes of jkurwa, one line each,
// that send the content of line i of gen back from its recipient to its sender:
//
//	J <i> <envelope>
func envelopeCheck(gen, jkurwa string, out io.Writer) error {
	genLines, err := readFields(gen)
	if err != nil {
		return err
	}
	jLines, err := readFields(jkurwa)
	if err != nil {
		return err
	}
	if len(jLines) == 0 {
		return fmt.Errorf("%s has no envelopes", jkurwa)
	}
	ok := 0
	for _, f := range jLines {
		i, err := strconv.Atoi(f[1])
		if err != nil || i < 0 || i >= len(genLines) {
			return fmt.Errorf("jkurwa envelope for line %q", f[1])
		}
		g := genLines[i]
		curve, err := strconv.Atoi(g[1])
		if err != nil {
			return err
		}
		c, err := dstu4145.NamedCurve(curve)
		if err != nil {
			return err
		}
		key, err := dstu4145.NewPrivateKey(c, decode(g[2]))
		if err != nil {
			return err
		}
		sender, err := x509.ParseCertificate(decode(g[3]))
		if err != nil {
			return err
		}
		recipient, err := x509.ParseCertificate(decode(g[6]))
		if err != nil {
			return err
		}
		got, err := pki.DecryptEnvelopedData(decode(f[2]), key, sender, []*x509.Certificate{recipient})
		if err != nil || !bytes.Equal(got, decode(g[7])) {
			_, _ = fmt.Fprintf(os.Stderr, "MISMATCH envelope from jkurwa for line %d: %v\n", i, err) // the count below reports the failure
			continue
		}
		ok++
	}
	_, err = fmt.Fprintf(out, "uacrypto %-32s %4d ok %d mismatch\n", "decrypt jkurwa envelope", ok, len(jLines)-ok)
	if ok != len(jLines) {
		return fmt.Errorf("%d envelopes from jkurwa did not decrypt", len(jLines)-ok)
	}
	return err
}

func readFields(path string) ([][]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return nil, err
	}
	var lines [][]string
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(nil, len(data)+1)
	for s.Scan() {
		if line := strings.Fields(s.Text()); len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines, s.Err()
}
