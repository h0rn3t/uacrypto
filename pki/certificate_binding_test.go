package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/pki"
)

func TestVerifyPAdESByteRangeOverflow(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offsets := make([]int, 5)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [3 0 R] >> >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /FT /Sig /V 4 0 R /T (Review) >>",
		"<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 0000000000000000000 0000000000000000000 9223372036854775807] /Contents <00> >>",
	}
	for i, obj := range objects {
		offsets[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := b.Len()
	b.WriteString("xref\n0 5\n0000000000 65535 f \n")
	for _, off := range offsets[1:] {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	pdf := b.Bytes()
	gap := bytes.Index(pdf, []byte("<00>"))
	br := bytes.Index(pdf, []byte("[0 ")) + 3
	for _, tt := range []struct {
		name                  string
		first, second, length int64
	}{
		{"sum overflow", int64(gap), int64(gap + 4), math.MaxInt64},
		{"first offset overflow", math.MaxInt64, int64(gap + 4), 0},
		{"second offset overflow", int64(gap), math.MaxInt64, 0},
		{"reversed offsets", int64(gap + 4), int64(gap), 0},
		{"past document", int64(gap), int64(gap + 4), int64(len(pdf))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.Clone(pdf)
			copy(input[br:br+19], fmt.Sprintf("%019d", tt.first))
			copy(input[br+20:br+39], fmt.Sprintf("%019d", tt.second))
			copy(input[br+40:br+59], fmt.Sprintf("%019d", tt.length))
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("VerifyPAdES(%s) panicked: %v", tt.name, r)
				}
			}()
			if _, err := pki.VerifyPAdES(input, nil); err == nil {
				t.Errorf("VerifyPAdES(%s) error = nil, want invalid ByteRange", tt.name)
			}
		})
	}
}

type bindingSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}
type bindingSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	Encap            asn1.RawValue
	Certificates     asn1.RawValue       `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue       `asn1:"optional,tag:1"`
	SignerInfos      []bindingSignerInfo `asn1:"set"`
}

func TestVerifySignedDataCertificateSubstitution(t *testing.T) {
	original := newTestSigner(t)
	msg := []byte("local dummy certification review")
	signed, err := pki.SignData(rand.Reader, msg, original.key, original.cert, pki.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, initial, err := pki.VerifySignedData(signed, nil, nil)
	if err != nil || len(initial) != 1 {
		t.Fatalf("original verification: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "replacement certificate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	replacementDER, err := pki.CreateCertificate(rand.Reader, tmpl, tmpl, original.cert.RawSubjectPublicKeyInfo, original.key)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := x509.ParseCertificate(replacementDER)
	if err != nil {
		t.Fatal(err)
	}
	// Both certificates already exist before the attack. Only unsigned fields change.
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}
	if _, err := asn1.Unmarshal(signed, &ci); err != nil {
		t.Fatal(err)
	}
	var sd bindingSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	beforeAttrs := bytes.Clone(sd.SignerInfos[0].SignedAttrs.FullBytes)
	beforeSignature := bytes.Clone(sd.SignerInfos[0].Signature)
	sid := mustMarshal(t, struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: replacement.RawIssuer}, replacement.SerialNumber})
	sd.SignerInfos[0].SID = asn1.RawValue{FullBytes: sid}
	sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: replacementDER}
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(t, sd)}
	mutated := mustMarshal(t, ci)
	if !bytes.Equal(beforeAttrs, sd.SignerInfos[0].SignedAttrs.FullBytes) || !bytes.Equal(beforeSignature, sd.SignerInfos[0].Signature) {
		t.Fatal("test changed signed material")
	}
	if _, _, err := pki.VerifySignedData(mutated, nil, nil); !errors.Is(err, pki.ErrInvalidSignature) {
		t.Errorf("VerifySignedData(substituted certificate) error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifySignedDataRenewedCertificate(t *testing.T) {
	original := newTestSigner(t)
	msg := []byte("signed under the original certificate")
	signed, err := pki.SignData(rand.Reader, msg, original.key, original.cert, pki.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// a renewed certificate of the same key carries the same SKI
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "renewed certificate"}, SubjectKeyId: original.cert.SubjectKeyId, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	renewedDER, err := pki.CreateCertificate(rand.Reader, tmpl, tmpl, original.cert.RawSubjectPublicKeyInfo, original.key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := x509.ParseCertificate(renewedDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renewed.SubjectKeyId, original.cert.SubjectKeyId) {
		t.Fatalf("renewed SKI %x, want the original %x", renewed.SubjectKeyId, original.cert.SubjectKeyId)
	}
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}
	if _, err := asn1.Unmarshal(signed, &ci); err != nil {
		t.Fatal(err)
	}
	var sd bindingSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	// IIT names the signer by SKI; the renewed certificate comes first
	sd.SignerInfos[0].SID = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: original.cert.SubjectKeyId}
	sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: slices.Concat(renewedDER, original.cert.Raw)}
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(t, sd)}

	content, signers, err := pki.VerifySignedData(mustMarshal(t, ci), nil, nil)
	if err != nil {
		t.Fatalf("VerifySignedData(renewed certificate first) error = %v, want nil", err)
	}
	if !bytes.Equal(content, msg) {
		t.Errorf("VerifySignedData(renewed certificate first) content = %q, want %q", content, msg)
	}
	if !signers[0].Certificate.Equal(original.cert) {
		t.Errorf("VerifySignedData(renewed certificate first) signer = %s, want %s", signers[0].Certificate.Subject, original.cert.Subject)
	}
}
