package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/pki"
)

func newKey(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	c, err := dstu4145.NamedCurve(6)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dstu4145.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func marshalKey(t *testing.T, key *dstu4145.PrivateKey) []byte {
	t.Helper()
	spki, err := pki.MarshalPublicKey(&pki.PublicKey{Key: key.Public(), DKE: gost28147.DKE1()})
	if err != nil {
		t.Fatalf("MarshalPublicKey() error = %v", err)
	}
	return spki
}

func TestMarshalPublicKey(t *testing.T) {
	key := newKey(t)
	point := key.Public().Bytes()
	slices.Reverse(point)
	// dstu4145le, DSTU4145Params with the OID of curve 6 and no DKE, the point LE in an OCTET STRING
	spki := marshalKey(t, key)
	var got struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Params    []asn1.RawValue
		}
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(spki, &got); err != nil || len(rest) != 0 {
		t.Fatalf("MarshalPublicKey() = %x: %v", spki, err)
	}
	if !got.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}) || len(got.Algorithm.Params) != 1 ||
		!bytes.Equal(got.Algorithm.Params[0].FullBytes, mustHex(t, "060d2a862402010101010301010206")) {
		t.Errorf("MarshalPublicKey() algorithm = %v with %d parameters, want dstu4145le with the OID of curve 6 alone", got.Algorithm.Algorithm, len(got.Algorithm.Params))
	}
	if want := append([]byte{0x04, 0x21}, point...); !bytes.Equal(got.PublicKey.Bytes, want) { // 33 bytes on curve 6
		t.Errorf("MarshalPublicKey() key bits = %x, want the point little-endian in an OCTET STRING %x", got.PublicKey.Bytes, want)
	}

	// a DKE other than ДКЕ №1 is kept
	other := gost28147.DKE1()
	other[0][0], other[0][1] = other[0][1], other[0][0]
	spki, err := pki.MarshalPublicKey(&pki.PublicKey{Key: key.Public(), DKE: other})
	if err != nil {
		t.Fatal(err)
	}
	back, err := pki.ParsePublicKey(spki)
	if err != nil || back.DKE != other || !bytes.Equal(back.Key.Bytes(), key.Public().Bytes()) {
		t.Errorf("ParsePublicKey(MarshalPublicKey(key with another DKE)) = %v, %v, want the key and DKE back", back, err)
	}
}

func extension(c *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	i := slices.IndexFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oid) })
	if i < 0 {
		return nil
	}
	return &c.Extensions[i]
}

// rootTemplate is a self-signed CA certificate template valid for an hour.
func rootTemplate() *x509.Certificate {
	now := time.Now().UTC().Truncate(time.Second)
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Тестовий ЦСК", Organization: []string{"Тестова організація"}},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// newTestRoot issues a self-signed CA certificate with CreateCertificate.
func newTestRoot(t *testing.T) (*x509.Certificate, *dstu4145.PrivateKey) {
	t.Helper()
	key := newKey(t)
	tmpl := rootTemplate()
	der, err := pki.CreateCertificate(rand.Reader, tmpl, tmpl, marshalKey(t, key), key)
	if err != nil {
		t.Fatalf("CreateCertificate(root) error = %v", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(root) error = %v", err)
	}
	return root, key
}

func TestCreateCertificateSelfSigned(t *testing.T) {
	rootKey := newKey(t)
	rootSPKI := marshalKey(t, rootKey)
	rootTemplate := rootTemplate()
	der, err := pki.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootSPKI, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(root) error = %v", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(root) error = %v", err)
	}
	if err := pki.CheckCertificateSignature(root, root); err != nil {
		t.Errorf("CheckCertificateSignature(root, root) = %v", err)
	}
	if !bytes.Equal(root.RawSubjectPublicKeyInfo, rootSPKI) {
		t.Errorf("CreateCertificate(root) key = %x, want pub as given %x", root.RawSubjectPublicKeyInfo, rootSPKI)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(rootSPKI, &spki); err != nil {
		t.Fatal(err)
	}
	ski := gost34311.Sum(spki.PublicKey.Bytes)
	if !bytes.Equal(root.SubjectKeyId, ski[:]) || !bytes.Equal(root.AuthorityKeyId, ski[:]) {
		t.Errorf("CreateCertificate(root) SKI %x, AKI %x, want both GOST 34.311 of the key bits %x", root.SubjectKeyId, root.AuthorityKeyId, ski)
	}
	if !root.IsCA || root.MaxPathLen != 0 || root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || root.Subject.CommonName != "Тестовий ЦСК" {
		t.Errorf("CreateCertificate(root) = CA %v pathlen %d key usage %v CN %q, want the template's", root.IsCA, root.MaxPathLen, root.KeyUsage, root.Subject.CommonName)
	}
	if want := (pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}}); !bytes.Contains(root.Raw, mustMarshal(t, want)) {
		t.Errorf("CreateCertificate(root) has no dstu4145le signature algorithm")
	}

	if _, err := pki.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootSPKI, newKey(t)); err == nil {
		t.Error("CreateCertificate(self-signed by another key) error = nil, want error")
	}
}

func TestCreateCertificateTSA(t *testing.T) {
	root, rootKey := newTestRoot(t)
	now := time.Now().UTC().Truncate(time.Second)
	// a TSA certificate under the root, with the subject as raw DER and an extension of the caller's
	tsaKey := newKey(t)
	tsaSPKI := marshalKey(t, tsaKey)
	rawSubject := mustMarshal(t, pkix.Name{CommonName: "TSP-сервер"}.ToRDNSequence())
	extra := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0x05, 0x00}}
	tsaTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		RawSubject:      rawSubject,
		NotBefore:       now,
		NotAfter:        now.Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		OCSPServer:      []string{"http://ca.example/services/ocsp/"},
		ExtraExtensions: []pkix.Extension{extra},
	}
	der, err := pki.CreateCertificate(rand.Reader, tsaTemplate, root, tsaSPKI, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(TSA) error = %v", err)
	}
	tsa, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(TSA) error = %v", err)
	}
	if err := pki.CheckCertificateSignature(tsa, root); err != nil {
		t.Errorf("CheckCertificateSignature(TSA, root) = %v", err)
	}
	if !bytes.Equal(tsa.RawSubject, rawSubject) || !bytes.Equal(tsa.RawIssuer, root.RawSubject) || !bytes.Equal(tsa.AuthorityKeyId, root.SubjectKeyId) {
		t.Errorf("CreateCertificate(TSA) subject %x issuer %x AKI %x, want the raw subject, the root's name and SKI", tsa.RawSubject, tsa.RawIssuer, tsa.AuthorityKeyId)
	}
	if e := extension(tsa, asn1.ObjectIdentifier{2, 5, 29, 37}); e == nil || !e.Critical || !slices.Equal(tsa.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}) {
		t.Errorf("CreateCertificate(TSA) extended key usage = %+v, want timeStamping alone and critical (RFC 3161, 2.3)", e)
	}
	if e := extension(tsa, extra.Id); e == nil || !bytes.Equal(e.Value, extra.Value) {
		t.Errorf("CreateCertificate(TSA) extension %v = %+v, want the caller's", extra.Id, e)
	}
	if !slices.Equal(tsa.OCSPServer, tsaTemplate.OCSPServer) {
		t.Errorf("CreateCertificate(TSA) OCSP servers = %q, want %q", tsa.OCSPServer, tsaTemplate.OCSPServer)
	}
	if len(tsaTemplate.ExtraExtensions) != 1 || tsaTemplate.SubjectKeyId != nil {
		t.Error("CreateCertificate changed the template")
	}

	// the key must be the issuer's, and the subject key DSTU 4145
	if _, err := pki.CreateCertificate(rand.Reader, tsaTemplate, root, tsaSPKI, tsaKey); err == nil {
		t.Error("CreateCertificate(signed by a key that is not the issuer's) error = nil, want error")
	}
	rsaSPKI := mustHex(t, "30133009060a2a864886f70d01010105000306003003020100")
	if _, err := pki.CreateCertificate(rand.Reader, tsaTemplate, root, rsaSPKI, rootKey); err == nil {
		t.Error("CreateCertificate(RSA key) error = nil, want error")
	}
}

func TestCreateCertificateOCSP(t *testing.T) {
	root, rootKey := newTestRoot(t)
	now := time.Now().UTC().Truncate(time.Second)
	// an OCSP certificate keeps a non-critical extended key usage, and ExtraExtensions replace a built one
	ocspTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "OCSP-сервер"},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 35}, // AKI with the issuer name and serial, as test-ca writes it
			Value: mustMarshal(t, struct {
				KeyID  []byte        `asn1:"tag:0"`
				Issuer asn1.RawValue `asn1:"tag:1"`
				Serial *big.Int      `asn1:"tag:2"`
			}{root.SubjectKeyId, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: root.RawSubject})}, root.SerialNumber}),
		}},
	}
	der, err := pki.CreateCertificate(rand.Reader, ocspTemplate, root, marshalKey(t, newKey(t)), rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(OCSP) error = %v", err)
	}
	ocsp, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if e := extension(ocsp, asn1.ObjectIdentifier{2, 5, 29, 37}); e == nil || e.Critical {
		t.Errorf("CreateCertificate(OCSP) extended key usage = %+v, want non-critical", e)
	}
	if e := extension(ocsp, asn1.ObjectIdentifier{2, 5, 29, 35}); e == nil || !bytes.Equal(e.Value, ocspTemplate.ExtraExtensions[0].Value) {
		t.Errorf("CreateCertificate(OCSP) authority key identifier = %+v, want the caller's", e)
	}
}

func TestPKCS8PrivateKey(t *testing.T) {
	key := newKey(t)
	der, err := pki.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	// the layout of Bouncy Castle that ca.java and test-ca share: dstu4145be with the curve OID,
	// ECPrivateKey {1, d, [0] curve, [1] the point big-endian in an OCTET STRING}
	curve := "060d2a862402010101010301010206"
	point := key.Public().Bytes() // 33 bytes on curve 6
	var got struct {
		Version   int
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Curve     asn1.ObjectIdentifier
		}
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &got); err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() = %x: %v", der, err)
	}
	if !got.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1}) ||
		!got.Algorithm.Curve.Equal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}) {
		t.Errorf("MarshalPKCS8PrivateKey() algorithm = %v %v, want dstu4145be with the OID of curve 6", got.Algorithm.Algorithm, got.Algorithm.Curve)
	}
	if want := mustHex(t, "305e"+"020101"+"0420"+hex.EncodeToString(key.Bytes())+"a00f"+curve+"a126"+"032400"+"0421"+hex.EncodeToString(point)); !bytes.Equal(got.PrivateKey, want) {
		t.Errorf("MarshalPKCS8PrivateKey() ECPrivateKey = %x, want %x", got.PrivateKey, want)
	}

	back, err := pki.ParsePKCS8PrivateKey(der)
	if err != nil || !bytes.Equal(back.Bytes(), key.Bytes()) || back.Public().Curve() != key.Public().Curve() {
		t.Errorf("ParsePKCS8PrivateKey(MarshalPKCS8PrivateKey(key)) = %v, %v, want key", back, err)
	}

	tampered := bytes.Clone(der)
	tampered[len(tampered)-1] ^= 1 // the public key no longer matches d
	if _, err := pki.ParsePKCS8PrivateKey(tampered); err == nil {
		t.Error("ParsePKCS8PrivateKey(public key of another d) error = nil, want error")
	}
	if _, err := pki.ParsePKCS8PrivateKey(mustHex(t, "300602010030003000")); err == nil {
		t.Error("ParsePKCS8PrivateKey(not a DSTU 4145 key) error = nil, want error")
	}
}

func TestCertificateBundle(t *testing.T) {
	certs := []*x509.Certificate{readCert(t, "czo-2601.der"), readCert(t, "vchasno-kupyna.der"), readCert(t, "czo-test-tsa.der")}
	p7b, err := pki.MarshalCertificateBundle(certs)
	if err != nil {
		t.Fatalf("MarshalCertificateBundle() error = %v", err)
	}
	// as openssl crl2pkcs7 -nocrl writes it: version 1, no digest algorithms, data, the certificates, no signers
	prefix := mustMarshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	if !bytes.HasPrefix(p7b[4:], prefix) || !bytes.HasSuffix(p7b, []byte{0x31, 0x00}) ||
		!bytes.Contains(p7b, mustHex(t, "0201013100300b06092a864886f70d010701")) {
		t.Errorf("MarshalCertificateBundle() = %x…, want a degenerate SignedData", p7b[:40])
	}

	for name, in := range map[string][]byte{"DER": p7b, "BER": toBER(t, p7b), "signed .p7s": mustSign(t, newTestSigner(t), []byte("x"))} {
		got, err := pki.ParseCertificateBundle(in)
		if err != nil {
			t.Fatalf("ParseCertificateBundle(%s) error = %v", name, err)
		}
		want := certs
		if name == "signed .p7s" {
			want = got[:min(1, len(got))]
		}
		if len(got) != len(want) {
			t.Fatalf("ParseCertificateBundle(%s) = %d certificates, want %d", name, len(got), len(want))
		}
		for i := range want {
			if !got[i].Equal(want[i]) {
				t.Errorf("ParseCertificateBundle(%s)[%d] = %s, want %s", name, i, got[i].Subject, want[i].Subject)
			}
		}
	}
	if _, err := pki.ParseCertificateBundle([]byte("not a bundle")); err == nil {
		t.Error("ParseCertificateBundle(garbage) error = nil, want error")
	}
}

// toBER re-encodes the outermost SEQUENCE of der with the indefinite length of BER.
func toBER(t *testing.T, der []byte) []byte {
	t.Helper()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatal(err)
	}
	return berSeq(seq.Bytes)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The subjectDirectoryAttributes of the ЦЗО test signer and of a CA server
// certificate from CACertificates.p7b, as their CAs wrote them.
func TestSubjectAttributes(t *testing.T) {
	p7s, err := os.ReadFile(filepath.Join("testdata", "czo-test-t-kupyna.p7s"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pki.ParseCertificateBundle(p7s)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(certs, func(c *x509.Certificate) bool {
		return c.Subject.CommonName == "ТЕСТ Тестовий Тест Тестович"
	})
	if i < 0 {
		t.Fatal("czo-test-t-kupyna.p7s has no signer certificate")
	}
	tests := []struct {
		name string
		cert *x509.Certificate
		want pki.SubjectAttributes
	}{
		{"ЦЗО test signer", certs[i], pki.SubjectAttributes{DRFO: "0000000000"}},
		{"ukrgasbank-tsp.der", readCert(t, "ukrgasbank-tsp.der"), pki.SubjectAttributes{EDRPOU: "23697280"}},
		{"czo-2601.der, no extension", readCert(t, "czo-2601.der"), pki.SubjectAttributes{}},
	}
	for _, tt := range tests {
		got, err := pki.ParseSubjectAttributes(tt.cert)
		if err != nil || got != tt.want {
			t.Errorf("ParseSubjectAttributes(%s) = %+v, %v, want %+v", tt.name, got, err, tt.want)
		}
		if tt.want == (pki.SubjectAttributes{}) {
			continue
		}
		ext, err := pki.MarshalSubjectAttributes(tt.want)
		j := slices.IndexFunc(tt.cert.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidSubjectDirectory) })
		if err != nil || !ext.Id.Equal(oidSubjectDirectory) || ext.Critical || !bytes.Equal(ext.Value, tt.cert.Extensions[j].Value) {
			t.Errorf("MarshalSubjectAttributes(%+v) = %+v, %v, want the extension of %s %x", tt.want, ext, err, tt.name, tt.cert.Extensions[j].Value)
		}
	}

	// both codes, DRFO first, as test-ca writes them for a user
	both := pki.SubjectAttributes{DRFO: "1234567890", EDRPOU: "12345678"}
	want, _ := hex.DecodeString("303a" +
		"301c060c2a8624020101010b01040101310c130a" + hex.EncodeToString([]byte("1234567890")) +
		"301a060c2a8624020101010b01040201310a1308" + hex.EncodeToString([]byte("12345678")))
	ext, err := pki.MarshalSubjectAttributes(both)
	if err != nil || !bytes.Equal(ext.Value, want) {
		t.Errorf("MarshalSubjectAttributes(%+v) = %x, %v, want %x", both, ext.Value, err, want)
	}
	if got, err := pki.ParseSubjectAttributes(&x509.Certificate{Extensions: []pkix.Extension{ext}}); err != nil || got != both {
		t.Errorf("ParseSubjectAttributes(MarshalSubjectAttributes(%+v)) = %+v, %v", both, got, err)
	}

	// other attributes, such as dateOfBirth (RFC 3739), are skipped
	dateOfBirth := mustHex(t, "301f301d06082b060105050709013111180f"+hex.EncodeToString([]byte("19900102000000Z")))
	if got, err := pki.ParseSubjectAttributes(withSubjectDirectory(dateOfBirth)); err != nil || got != (pki.SubjectAttributes{}) {
		t.Errorf("ParseSubjectAttributes(dateOfBirth only) = %+v, %v, want none", got, err)
	}

	for name, value := range map[string][]byte{
		"not a SEQUENCE":     {0x02, 0x01, 0x05},
		"DRFO as INTEGER":    mustHex(t, "30153013060c2a8624020101010b010401013103020105"),
		"trailing data":      append(slices.Clone(want), 0x00),
		"DRFO with no value": mustHex(t, "30123010060c2a8624020101010b010401013100"),
	} {
		if got, err := pki.ParseSubjectAttributes(withSubjectDirectory(value)); err == nil {
			t.Errorf("ParseSubjectAttributes(%s) = %+v, want error", name, got)
		}
	}
	for name, a := range map[string]pki.SubjectAttributes{
		"none":                            {},
		"Cyrillic, not a PrintableString": {DRFO: "ІПН1234567"},
	} {
		if ext, err := pki.MarshalSubjectAttributes(a); err == nil {
			t.Errorf("MarshalSubjectAttributes(%s) = %+v, want error", name, ext)
		}
	}
}

var oidSubjectDirectory = asn1.ObjectIdentifier{2, 5, 29, 9}

func withSubjectDirectory(value []byte) *x509.Certificate {
	return &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSubjectDirectory, Value: value}}}
}
