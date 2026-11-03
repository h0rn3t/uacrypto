package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/kupyna"
	"github.com/h0rn3t/uacrypto/pki"
)

// The tokens in testdata are RFC 3161 time-stamp tokens that three Ukrainian
// TSAs returned for the GOST 34.311 or Kupyna-256 digest of tsaMessage.
const tsaMessage = "uacrypto test"

func TestVerifySignedDataTSA(t *testing.T) {
	gost, kupyna256 := gost34311.Sum([]byte(tsaMessage)), kupyna.Sum256([]byte(tsaMessage))
	tests := []struct {
		file   string
		digest []byte
	}{
		{"tsa-tax-gost.p7s", gost[:]},
		{"tsa-privatbank-gost.p7s", gost[:]},
		{"tsa-diia-kupyna.p7s", kupyna256[:]},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			der, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			content, signers, err := pki.VerifySignedData(der, nil, nil)
			if err != nil {
				t.Fatalf("VerifySignedData(%s) error = %v", tt.file, err)
			}
			if !bytes.Contains(content, tt.digest) {
				t.Errorf("VerifySignedData(%s) content %x lacks the requested digest %x", tt.file, content, tt.digest)
			}
			if len(signers) != 1 || signers[0].Subject.CommonName == "" {
				t.Errorf("VerifySignedData(%s) signers = %v, want the TSA certificate", tt.file, signers)
			}

			// the TSTInfo is signed through the messageDigest attribute; the
			// signature value is the last 64 bytes of the token
			for name, at := range map[string]int{"content": bytes.Index(der, tt.digest), "signature": len(der) - 1} {
				tampered := bytes.Clone(der)
				tampered[at] ^= 1
				if _, _, err := pki.VerifySignedData(tampered, nil, nil); !errors.Is(err, pki.ErrInvalidSignature) {
					t.Errorf("VerifySignedData(%s with %s changed) error = %v, want ErrInvalidSignature", tt.file, name, err)
				}
			}
		})
	}
}

// testSigner is a DSTU 4145 key on M257 with a self-signed certificate.
type testSigner struct {
	key  *dstu4145.PrivateKey
	cert *x509.Certificate
}

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidGOST34311     = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 1}
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1.Marshal(%T) error = %v", v, err)
	}
	return b
}

// signLE returns r||s little-endian over the GOST 34.311 digest of data.
func (s *testSigner) signLE(t *testing.T, data []byte) []byte {
	t.Helper()
	digest := gost34311.Sum(data)
	r, sv, err := dstu4145.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return dstu4145.MarshalSignature(s.key.Public().Curve(), r, sv)
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	c, err := dstu4145.NamedCurve(6)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dstu4145.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &testSigner{key: key}
	point := key.Public().Bytes()
	slices.Reverse(point)
	name := mustMarshal(t, pkix.Name{CommonName: "uacrypto test"}.ToRDNSequence())
	ski := mustMarshal(t, []byte("test key id"))
	tbs := mustMarshal(t, struct {
		Version    int `asn1:"explicit,tag:0"`
		Serial     *big.Int
		Algorithm  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		Validity   struct{ NotBefore, NotAfter time.Time }
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Extensions []pkix.Extension `asn1:"explicit,tag:3"`
	}{
		Version: 2, Serial: big.NewInt(7), Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidLE},
		Issuer:     asn1.RawValue{FullBytes: name},
		Validity:   struct{ NotBefore, NotAfter time.Time }{time.Now().UTC().Truncate(time.Second), time.Now().UTC().Truncate(time.Second).Add(time.Hour)},
		Subject:    asn1.RawValue{FullBytes: name},
		SPKI:       asn1.RawValue{FullBytes: namedCurveSPKI(t, oidLE, 6, nil, point)},
		Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: ski}},
	})
	sig := mustMarshal(t, s.signLE(t, tbs))
	der := mustMarshal(t, struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: oidLE}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if s.cert, err = x509.ParseCertificate(der); err != nil {
		t.Fatalf("x509.ParseCertificate(test certificate) error = %v", err)
	}
	if err := pki.CheckCertificateSignature(s.cert, s.cert); err != nil {
		t.Fatalf("CheckCertificateSignature(test certificate) = %v", err)
	}
	return s
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type cmsOptions struct {
	detached    bool // leave eContent out
	noAttrs     bool // sign the content itself, without signed attributes
	wrapped     bool // signature value as a DER OCTET STRING, as Bouncy Castle writes it
	bigEndian   bool // dstu4145be: s||r big-endian
	byKeyID     bool // identify the signer by subjectKeyIdentifier
	omitCert    bool // leave the signer certificate out of the SignedData
	wrongDigest bool // a messageDigest attribute that does not match the content
	wrongType   bool // a contentType attribute that does not match eContentType
}

func (s *testSigner) signedData(t *testing.T, content []byte, o cmsOptions) []byte {
	t.Helper()
	signed := content
	var attrs asn1.RawValue
	if !o.noAttrs {
		digest := gost34311.Sum(content)
		if o.wrongDigest {
			digest[0] ^= 1
		}
		contentType := oidData
		if o.wrongType {
			contentType = oidSignedData
		}
		set := func(v []byte) asn1.RawValue {
			return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}
		}
		var err error
		signed, err = asn1.MarshalWithParams([]attribute{
			{oidContentType, set(mustMarshal(t, contentType))},
			{oidMessageDigest, set(mustMarshal(t, digest[:]))},
		}, "set")
		if err != nil {
			t.Fatal(err)
		}
		attrs = asn1.RawValue{FullBytes: append([]byte{0xa0}, signed[1:]...)}
	}

	sig := s.signLE(t, signed)
	alg := oidLE
	if o.bigEndian {
		slices.Reverse(sig)
		alg = oidBE
	}
	if o.wrapped {
		sig = mustMarshal(t, sig)
	}

	sid := asn1.RawValue{FullBytes: mustMarshal(t, struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: s.cert.RawIssuer}, s.cert.SerialNumber})}
	version := 1
	if o.byKeyID {
		sid = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: s.cert.SubjectKeyId}
		version = 3
	}
	signerInfo := struct {
		Version            int
		SID                asn1.RawValue
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        asn1.RawValue `asn1:"optional"`
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}{version, sid, pkix.AlgorithmIdentifier{Algorithm: oidGOST34311}, attrs, pkix.AlgorithmIdentifier{Algorithm: alg}, sig}

	encap := struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"optional,explicit,tag:0"`
	}{Type: oidData}
	if !o.detached {
		encap.Content = content
	}
	var certs asn1.RawValue
	if !o.omitCert {
		certs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: s.cert.Raw}
	}
	sd := mustMarshal(t, struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		Encap            any
		Certificates     asn1.RawValue `asn1:"optional"`
		SignerInfos      []any         `asn1:"set"`
	}{1, []pkix.AlgorithmIdentifier{{Algorithm: oidGOST34311}}, encap, certs, []any{signerInfo}})
	return mustMarshal(t, struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}

func TestVerifySignedData(t *testing.T) {
	s := newTestSigner(t)
	content := []byte("підписаний документ")
	tests := map[string]cmsOptions{
		"attached":                {},
		"detached":                {detached: true},
		"without signed attrs":    {noAttrs: true},
		"Bouncy Castle signature": {wrapped: true},
		"big-endian":              {bigEndian: true},
		"by key identifier":       {byKeyID: true},
	}
	for name, o := range tests {
		t.Run(name, func(t *testing.T) {
			der := s.signedData(t, content, o)
			var detached []byte
			if o.detached {
				detached = content
			}
			got, signers, err := pki.VerifySignedData(der, detached, nil)
			if err != nil {
				t.Fatalf("VerifySignedData(%+v) error = %v", o, err)
			}
			if !bytes.Equal(got, content) {
				t.Errorf("VerifySignedData(%+v) content = %q, want %q", o, got, content)
			}
			if len(signers) != 1 || !signers[0].Equal(s.cert) {
				t.Errorf("VerifySignedData(%+v) signers = %v, want the test certificate", o, signers)
			}
		})
	}
}

func TestVerifySignedDataCertificateFromCaller(t *testing.T) {
	s := newTestSigner(t)
	der := s.signedData(t, []byte("data"), cmsOptions{omitCert: true})
	if _, _, err := pki.VerifySignedData(der, nil, nil); err == nil {
		t.Error("VerifySignedData(no signer certificate) error = nil, want error")
	}
	if _, signers, err := pki.VerifySignedData(der, nil, []*x509.Certificate{s.cert}); err != nil || len(signers) != 1 {
		t.Errorf("VerifySignedData(certificate passed by the caller) = %v, %v, want the signer", signers, err)
	}
}

func TestVerifySignedDataRejects(t *testing.T) {
	s := newTestSigner(t)
	content := []byte("data")
	attached := s.signedData(t, content, cmsOptions{})
	detached := s.signedData(t, content, cmsOptions{detached: true})
	tests := []struct {
		name          string
		der, detached []byte
		wantInvalid   bool // the error is ErrInvalidSignature
	}{
		{"wrong messageDigest", s.signedData(t, content, cmsOptions{wrongDigest: true}), nil, true},
		{"other detached content", detached, []byte("other"), true},
		{"wrong contentType", s.signedData(t, content, cmsOptions{wrongType: true}), nil, false},
		{"detached without content", detached, nil, false},
		{"attached and detached", attached, content, false},
		{"not DER", []byte{0x30, 0x80, 0, 0}, nil, false},
		{"nil", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := pki.VerifySignedData(tt.der, tt.detached, nil)
			if err == nil {
				t.Fatalf("VerifySignedData(%s) error = nil, want error", tt.name)
			}
			if got := errors.Is(err, pki.ErrInvalidSignature); got != tt.wantInvalid {
				t.Errorf("VerifySignedData(%s) error = %v, ErrInvalidSignature %v, want %v", tt.name, err, got, tt.wantInvalid)
			}
		})
	}
}

// signedAttrTypes returns the signed attribute types of the only signer and
// the certHash of signingCertificateV2.
func signedAttrTypes(t *testing.T, der []byte) (types []string, certHash []byte) {
	t.Helper()
	var ci struct {
		Type asn1.ObjectIdentifier
		SD   struct {
			Version      int
			Digests      asn1.RawValue
			Encap        asn1.RawValue
			Certificates asn1.RawValue `asn1:"optional,tag:0"`
			SignerInfos  []struct {
				Version            int
				SID                asn1.RawValue
				DigestAlgorithm    pkix.AlgorithmIdentifier
				SignedAttrs        []attribute `asn1:"tag:0,set"`
				SignatureAlgorithm pkix.AlgorithmIdentifier
				Signature          []byte
			} `asn1:"set"`
		} `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatalf("asn1.Unmarshal(SignedData) error = %v", err)
	}
	for _, a := range ci.SD.SignerInfos[0].SignedAttrs {
		types = append(types, a.Type.String())
		if a.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}) {
			var v struct {
				Certs []struct {
					Hash   pkix.AlgorithmIdentifier
					Digest []byte
				}
			}
			if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err != nil {
				t.Fatalf("signingCertificateV2: %v", err)
			}
			certHash = v.Certs[0].Digest
		}
	}
	slices.Sort(types)
	return types, certHash
}

func TestSignData(t *testing.T) {
	s := newTestSigner(t)
	content := []byte("документ для підпису")
	kupynaHash, gostHash := kupyna.Sum256(s.cert.Raw), gost34311.Sum(s.cert.Raw)
	tests := []struct {
		name     string
		opts     pki.SignOptions
		certHash []byte
	}{
		{"Kupyna attached", pki.SignOptions{}, kupynaHash[:]},
		{"Kupyna detached", pki.SignOptions{Detached: true}, kupynaHash[:]},
		{"GOST attached", pki.SignOptions{GOST34311: true}, gostHash[:]},
		{"GOST detached", pki.SignOptions{GOST34311: true, Detached: true}, gostHash[:]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := pki.SignData(rand.Reader, content, s.key, s.cert, tt.opts)
			if err != nil {
				t.Fatalf("SignData(%+v) error = %v", tt.opts, err)
			}
			var detached []byte
			if tt.opts.Detached {
				detached = content
			}
			got, signers, err := pki.VerifySignedData(der, detached, nil)
			if err != nil {
				t.Fatalf("VerifySignedData(SignData(%+v)) error = %v", tt.opts, err)
			}
			if !bytes.Equal(got, content) || len(signers) != 1 || !signers[0].Equal(s.cert) {
				t.Errorf("VerifySignedData(SignData(%+v)) = %q, %v, want the content and the test certificate", tt.opts, got, signers)
			}
			if tt.opts.Detached && bytes.Contains(der, content) {
				t.Errorf("SignData(%+v) carries the content", tt.opts)
			}

			types, certHash := signedAttrTypes(t, der)
			want := []string{"1.2.840.113549.1.9.16.2.47", "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4", "1.2.840.113549.1.9.5"}
			if !slices.Equal(types, want) {
				t.Errorf("SignData(%+v) signed attributes = %v, want contentType, messageDigest, signingTime, signingCertificateV2 %v", tt.opts, types, want)
			}
			if !bytes.Equal(certHash, tt.certHash) {
				t.Errorf("SignData(%+v) signingCertificateV2 hash = %x, want %x", tt.opts, certHash, tt.certHash)
			}
		})
	}
}

func TestSignDataRejectsOtherKey(t *testing.T) {
	s, other := newTestSigner(t), newTestSigner(t)
	if der, err := pki.SignData(rand.Reader, []byte("x"), other.key, s.cert, pki.SignOptions{}); err == nil {
		t.Errorf("SignData(key of another certificate) = %x, want error", der)
	}
}
