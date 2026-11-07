package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

var oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// crlGen writes CRLs from uacrypto for Bouncy Castle to verify, a full CRL
// with entries, a delta CRL and an empty CRL on each of three curves, one line
// each:
//
//	L <curve> <CA d> <CA cert> <CRL> <number> <base number or -> <entries>
//
// entries are serial:reason:Unix time, the serial in hex, comma-separated,
// or - for none.
func crlGen(path string) error {
	w := new(bytes.Buffer)
	for _, curve := range []int{dstu4145.M163, dstu4145.M257, dstu4145.M431} {
		key, ca, err := newCRLIssuer(curve)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Second)
		for _, crl := range []struct {
			number, base int64
			entries      []x509.RevocationListEntry
		}{
			{10, 0, []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(1), RevocationTime: now.Add(-time.Hour), ReasonCode: 6},                               // certificateHold
				{SerialNumber: new(big.Int).Lsh(big.NewInt(0x5a), 150), RevocationTime: now.Add(-2 * time.Hour), ReasonCode: 1}, // keyCompromise
				{SerialNumber: big.NewInt(7), RevocationTime: now.Add(-3 * time.Hour)},                                          // no reason
			}},
			{11, 10, []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(1), RevocationTime: now.Add(-time.Hour), ReasonCode: 8}, // removeFromCRL
			}},
			{12, 0, nil},
		} {
			tmpl := &x509.RevocationList{
				Number:                    big.NewInt(crl.number),
				ThisUpdate:                now,
				NextUpdate:                now.Add(24 * time.Hour),
				RevokedCertificateEntries: crl.entries,
			}
			base := "-"
			if crl.base > 0 {
				v, err := asn1.Marshal(big.NewInt(crl.base))
				if err != nil {
					return err
				}
				tmpl.ExtraExtensions = []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: v}}
				base = strconv.FormatInt(crl.base, 10)
			}
			der, err := pki.CreateRevocationList(crand.Reader, tmpl, ca, key)
			if err != nil {
				return err
			}
			fmt.Fprintln(w, "L", curve, encode(key.Bytes()), encode(ca.Raw), encode(der), crl.number, base, formatCRLEntries(crl.entries))
		}
	}
	return os.WriteFile(path, w.Bytes(), 0o600) //nolint:gosec // G703: the operator names the file on the command line
}

// newCRLIssuer returns a key on curve with a self-signed CA certificate that
// may sign CRLs.
func newCRLIssuer(curve int) (*dstu4145.PrivateKey, *x509.Certificate, error) {
	c, err := dstu4145.NamedCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	key, err := dstu4145.GenerateKey(c, crand.Reader)
	if err != nil {
		return nil, nil, err
	}
	spki, err := pki.MarshalPublicKey(&pki.PublicKey{Key: key.Public(), DKE: gost28147.DKE1()})
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(curve) + 1),
		Subject:               pkix.Name{CommonName: "uacrypto CRL issuer " + strconv.Itoa(curve), Country: []string{"UA"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := pki.CreateCertificate(crand.Reader, tmpl, tmpl, spki, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func formatCRLEntries(entries []x509.RevocationListEntry) string {
	if len(entries) == 0 {
		return "-"
	}
	fields := make([]string, len(entries))
	for i, e := range entries {
		fields[i] = fmt.Sprintf("%s:%d:%d", e.SerialNumber.Text(16), e.ReasonCode, e.RevocationTime.Unix())
	}
	return strings.Join(fields, ",")
}

// crlCheck reads the lines B <curve> <CA cert> <CRL> <number> <base number or -> <entries>
// in which Bouncy Castle issued the CRL of each L line of goPath again with
// the same key, and checks each with pki.ParseRevocationList.
func crlCheck(goPath, bcPath string, out io.Writer) error {
	goLines, err := os.ReadFile(goPath) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}
	data, err := os.ReadFile(bcPath) //nolint:gosec // G703: the operator names the file on the command line
	if err != nil {
		return err
	}
	var ok, failed int
	var report strings.Builder
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) != 7 || f[0] != "B" {
			return fmt.Errorf("malformed line %q", line)
		}
		if err := checkBCCRL(f); err != nil {
			failed++
			fmt.Fprintf(&report, "REJECTED Bouncy Castle CRL %s on curve %s: %v\n", f[4], f[1], err)
			continue
		}
		ok++
	}
	if want := strings.Count(string(goLines), "\n"); ok+failed != want {
		fmt.Fprintf(&report, "Bouncy Castle issued %d CRLs, want %d\n", ok+failed, want)
		failed++
	}
	fmt.Fprintf(&report, "uacrypto parses CRLs of Bouncy Castle %4d ok %d rejected\n", ok, failed)
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d CRLs of Bouncy Castle rejected", failed)
	}
	return nil
}

func checkBCCRL(f []string) error {
	ca, err := x509.ParseCertificate(decode(f[2]))
	if err != nil {
		return err
	}
	crl, err := pki.ParseRevocationList(decode(f[3]), ca)
	if err != nil {
		return err
	}
	if crl.Number == nil || crl.Number.String() != f[4] {
		return fmt.Errorf("number %v, want %s", crl.Number, f[4])
	}
	base := "-"
	for _, e := range crl.Extensions {
		if !e.Id.Equal(oidDeltaCRLIndicator) {
			continue
		}
		var n *big.Int
		if _, err := asn1.Unmarshal(e.Value, &n); err != nil {
			return fmt.Errorf("delta CRL indicator: %w", err)
		}
		base = n.String()
	}
	if base != f[5] {
		return fmt.Errorf("base CRL %s, want %s", base, f[5])
	}
	if got := formatCRLEntries(crl.RevokedCertificateEntries); got != f[6] {
		return fmt.Errorf("entries %s, want %s", got, f[6])
	}
	return nil
}
