package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/pki"
)

var oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// The czo-*.crl files are the CRLs of the ЦЗО, downloaded 2026-11-06 from the
// distribution points of the certificates it issued.
func TestParseRevocationList(t *testing.T) {
	tests := []struct {
		crl, issuer string
		number      int64
		revoked     int
	}{
		{"czo-2020-full.crl", "czo-2020.der", 343283, 2},
		{"czo-2020-delta.crl", "czo-2020.der", 343357, 0},
		{"czo-2026-full.crl", "czo-2601.der", 342847, 0},
		{"czo-2026-delta.crl", "czo-2601.der", 343350, 0},
	}
	for _, tt := range tests {
		t.Run(tt.crl, func(t *testing.T) {
			crl, err := pki.ParseRevocationList(readTestdata(t, tt.crl), readCert(t, tt.issuer))
			if err != nil {
				t.Fatalf("ParseRevocationList(%s, %s) error = %v", tt.crl, tt.issuer, err)
			}
			if crl.Number.Int64() != tt.number || len(crl.RevokedCertificateEntries) != tt.revoked {
				t.Errorf("ParseRevocationList(%s) = number %v with %d entries, want %d with %d",
					tt.crl, crl.Number, len(crl.RevokedCertificateEntries), tt.number, tt.revoked)
			}
		})
	}
}

func TestParseRevocationListRejects(t *testing.T) {
	full := readTestdata(t, "czo-2020-full.crl")
	tampered := bytes.Clone(full)
	tampered[len(full)-200] ^= 1 // inside the revoked certificates, before the signature

	ca, key := newTestRoot(t)
	tmpl := rootTemplate()
	tmpl.KeyUsage = x509.KeyUsageCertSign
	noCRLSignDER, err := pki.CreateCertificate(rand.Reader, tmpl, tmpl, marshalKey(t, key), key)
	if err != nil {
		t.Fatal(err)
	}
	noCRLSign, err := x509.ParseCertificate(noCRLSignDER)
	if err != nil {
		t.Fatal(err)
	}
	own, err := pki.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, ca, key)
	if err != nil {
		t.Fatalf("CreateRevocationList() error = %v", err)
	}
	otherKeyID := new(x509.Certificate)
	*otherKeyID = *ca
	otherKeyID.SubjectKeyId = []byte{1, 2, 3}

	tests := []struct {
		name    string
		crl     []byte
		issuer  *x509.Certificate
		wantErr error
	}{
		{"another CA", full, readCert(t, "czo-2601.der"), nil},
		{"signature over changed content", tampered, readCert(t, "czo-2020.der"), pki.ErrInvalidSignature},
		{"issuer without cRLSign", own, noCRLSign, nil},
		{"not a CRL", readCert(t, "czo-2020.der").Raw, readCert(t, "czo-2020.der"), nil},
		{"another key of the CA", own, otherKeyID, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pki.ParseRevocationList(tt.crl, tt.issuer)
			if err == nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseRevocationList(%s) error = %v, want an error matching %v (nil: any)", tt.name, err, tt.wantErr)
			}
		})
	}
}

// The ЦЗО revoked the certificate of ocsp-czo-revoked.der on 2021-10-07
// 15:56:54 UTC as superseded; its OCSP response says the same.
func TestRevocationStatusCZO(t *testing.T) {
	issuer := readCert(t, "czo-2020.der")
	full, err := pki.ParseRevocationList(readTestdata(t, "czo-2020-full.crl"), issuer)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := pki.ParseRevocationList(readTestdata(t, "czo-2020-delta.crl"), issuer)
	if err != nil {
		t.Fatal(err)
	}
	revoked := serial(t, "05E19E2CD92EA299020000000100000006010000")
	got, ok, err := pki.RevocationStatus(revoked, full, delta)
	if err != nil || !ok || got.ReasonCode != 4 || !got.RevocationTime.Equal(time.Date(2021, 10, 7, 15, 56, 54, 0, time.UTC)) {
		t.Errorf("RevocationStatus(%X, CZO-2020) = %+v, %t, %v, want superseded at 2021-10-07 15:56:54", revoked, got, ok, err)
	}
	if got, ok, err := pki.RevocationStatus(issuer.SerialNumber, full, delta); ok || err != nil {
		t.Errorf("RevocationStatus(%X, CZO-2020) = %+v, %t, %v, want not revoked", issuer.SerialNumber, got, ok, err)
	}
}

func TestRevocationStatus(t *testing.T) {
	ca, key := newTestRoot(t)
	now := time.Now().UTC().Truncate(time.Second)
	create := func(t *testing.T, number int64, base int64, entries ...x509.RevocationListEntry) *x509.RevocationList {
		t.Helper()
		tmpl := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now, NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries}
		if base > 0 {
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: mustMarshal(t, big.NewInt(base))}}
		}
		der, err := pki.CreateRevocationList(rand.Reader, tmpl, ca, key)
		if err != nil {
			t.Fatalf("CreateRevocationList(number %d) error = %v", number, err)
		}
		crl, err := pki.ParseRevocationList(der, ca)
		if err != nil {
			t.Fatalf("ParseRevocationList(CreateRevocationList(number %d)) error = %v", number, err)
		}
		return crl
	}
	entry := func(serial int64, reason int) x509.RevocationListEntry {
		return x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: now.Add(-time.Duration(serial) * time.Minute), ReasonCode: reason}
	}
	const (
		keyCompromise   = 1
		certificateHold = 6
		removeFromCRL   = 8
	)
	full := create(t, 10, 0, entry(1, certificateHold), entry(3, keyCompromise))
	delta := create(t, 11, 10, entry(1, removeFromCRL), entry(2, keyCompromise))

	tests := []struct {
		name       string
		serial     int64
		full       *x509.RevocationList
		delta      *x509.RevocationList
		wantReason int // -1: not revoked
	}{
		{"hold released in the delta", 1, full, delta, -1},
		{"held, without a delta", 1, full, nil, certificateHold},
		{"revoked in the delta", 2, full, delta, keyCompromise},
		{"revoked in the full CRL", 3, full, delta, keyCompromise},
		{"never revoked", 4, full, delta, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, revoked, err := pki.RevocationStatus(big.NewInt(tt.serial), tt.full, tt.delta)
			if err != nil {
				t.Fatalf("RevocationStatus(%d) error = %v", tt.serial, err)
			}
			switch {
			case tt.wantReason < 0 && revoked:
				t.Errorf("RevocationStatus(%d) = %+v, revoked, want not revoked", tt.serial, got)
			case tt.wantReason >= 0 && (!revoked || got.ReasonCode != tt.wantReason || got.SerialNumber.Int64() != tt.serial):
				t.Errorf("RevocationStatus(%d) = %+v, %t, want revoked with reason %d", tt.serial, got, revoked, tt.wantReason)
			}
		})
	}

	other, otherKey := newTestRoot(t)
	foreignDER, err := pki.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(11), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: mustMarshal(t, big.NewInt(10))}}}, other, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := pki.ParseRevocationList(foreignDER, other)
	if err != nil {
		t.Fatal(err)
	}
	invalid := []struct {
		name        string
		full, delta *x509.RevocationList
	}{
		{"delta as the full CRL", delta, nil},
		{"full CRL as the delta", full, full},
		{"delta on a newer base", full, create(t, 12, 11)},
		{"delta of another CA", full, foreign},
		{"malformed delta CRL indicator", full, &x509.RevocationList{Number: big.NewInt(11),
			Extensions: []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{0x02}}}}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if got, revoked, err := pki.RevocationStatus(big.NewInt(2), tt.full, tt.delta); err == nil {
				t.Errorf("RevocationStatus(%s) = %+v, %t, nil, want error", tt.name, got, revoked)
			}
		})
	}
}

func TestCreateRevocationList(t *testing.T) {
	ca, key := newTestRoot(t)
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(0x313233), RevocationTime: now.Add(-time.Hour), ReasonCode: 1},
		},
	}
	der, err := pki.CreateRevocationList(rand.Reader, tmpl, ca, key)
	if err != nil {
		t.Fatalf("CreateRevocationList() error = %v", err)
	}
	crl, err := pki.ParseRevocationList(der, ca)
	if err != nil {
		t.Fatalf("ParseRevocationList(CreateRevocationList()) error = %v", err)
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatal(err)
	}
	dstu4145le := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	if !outer.Algorithm.Algorithm.Equal(dstu4145le) {
		t.Errorf("CreateRevocationList() signature algorithm = %v, want dstu4145le %v", outer.Algorithm.Algorithm, dstu4145le)
	}
	if !bytes.Equal(crl.AuthorityKeyId, ca.SubjectKeyId) || crl.Number.Int64() != 7 || !crl.NextUpdate.Equal(tmpl.NextUpdate) {
		t.Errorf("CreateRevocationList() = AKI %x, number %v, next update %v, want AKI %x, 7, %v",
			crl.AuthorityKeyId, crl.Number, crl.NextUpdate, ca.SubjectKeyId, tmpl.NextUpdate)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Int64() != 0x313233 ||
		crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("CreateRevocationList() entries = %+v, want serial 313233 revoked for key compromise", crl.RevokedCertificateEntries)
	}

	if _, err := pki.CreateRevocationList(rand.Reader, tmpl, ca, newKey(t)); err == nil {
		t.Error("CreateRevocationList(a key not of the issuer) error = nil, want error")
	}
	if _, err := pki.CreateRevocationList(rand.Reader, tmpl, newECDSACert(t), key); err == nil {
		t.Error("CreateRevocationList(an ECDSA issuer) error = nil, want error")
	}
}
