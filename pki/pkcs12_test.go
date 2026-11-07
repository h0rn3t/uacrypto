package pki_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/h0rn3t/uacrypto/dstu4145"
	"github.com/h0rn3t/uacrypto/gost28147"
	"github.com/h0rn3t/uacrypto/gost34311"
	"github.com/h0rn3t/uacrypto/pki"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// jkurwa-store-a040.dat is jkurwa's STORE_A040.dat: jkurwa-key40a0.der
// (Key40A0.pem) under the password "password", with the salt and IV of its
// test "should encrypt raw key and serialize into PBES2".
func TestDecryptPKCS8PrivateKey(t *testing.T) {
	store := readTestdata(t, "jkurwa-store-a040.dat")
	want := readTestdata(t, "jkurwa-key40a0.der")

	got, err := pki.DecryptPKCS8PrivateKey(store, "password")
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("DecryptPKCS8PrivateKey(STORE_A040, password) = %x, %v, want %x", got, err, want)
	}
	if _, err := pki.DecryptPKCS8PrivateKey(store, "passworD"); !errors.Is(err, pki.ErrIncorrectPassword) {
		t.Errorf("DecryptPKCS8PrivateKey(STORE_A040, wrong password) error = %v, want %v", err, pki.ErrIncorrectPassword)
	}
	if _, err := pki.DecryptPKCS8PrivateKey(want, "password"); err == nil {
		t.Error("DecryptPKCS8PrivateKey(an unencrypted key) error = nil, want error")
	}
}

func TestEncryptPKCS8PrivateKey(t *testing.T) {
	key := readTestdata(t, "jkurwa-key40a0.der")
	salt := mustHex(t, "31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876")
	iv := mustHex(t, "4bb10f5c2945d49e")
	random := bytes.NewReader(slices.Concat(salt, iv))

	got, err := pki.EncryptPKCS8PrivateKey(random, key, "password", 10000)
	if want := readTestdata(t, "jkurwa-store-a040.dat"); err != nil || !bytes.Equal(got, want) {
		t.Errorf("EncryptPKCS8PrivateKey(Key40A0, salt %x, IV %x) = %x, %v, want STORE_A040 %x", salt, iv, got, err, want)
	}
	if _, err := pki.EncryptPKCS8PrivateKey(rand.Reader, key, "password", 0); err == nil {
		t.Error("EncryptPKCS8PrivateKey(0 iterations) error = nil, want error")
	}
}

// Key40A0.pem keeps d little-endian in a bare OCTET STRING, as IIT and
// cryptonite do; SELF_SIGNED_ENC_40A0.cer is its certificate in jkurwa's
// test-box.js. Its authority key identifier is one crypto/x509 rejects, so
// the test takes the SubjectPublicKeyInfo by hand.
func TestParsePKCS8PrivateKeyIIT(t *testing.T) {
	pub, err := pki.ParsePublicKey(certSPKI(t, readTestdata(t, "jkurwa-self-signed-enc-40a0.cer")))
	if err != nil {
		t.Fatal(err)
	}

	key, err := pki.ParsePKCS8PrivateKey(readTestdata(t, "jkurwa-key40a0.der"))
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey(Key40A0) error = %v", err)
	}
	if !bytes.Equal(key.Public().Bytes(), pub.Key.Bytes()) {
		t.Errorf("ParsePKCS8PrivateKey(Key40A0) public key = %x, want the certificate's %x", key.Public().Bytes(), pub.Key.Bytes())
	}

	var zero struct {
		Version    int
		Algorithm  asn1.RawValue
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(readTestdata(t, "jkurwa-key40a0.der"), &zero); err != nil {
		t.Fatal(err)
	}
	zero.PrivateKey = make([]byte, len(zero.PrivateKey))
	if _, err := pki.ParsePKCS8PrivateKey(mustMarshal(t, zero)); err == nil {
		t.Error("ParsePKCS8PrivateKey(IIT key with d = 0) error = nil, want error")
	}
}

func TestParsePKCS8KeyAgreementKey(t *testing.T) {
	curveOID := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}
	params := mustMarshal(t, struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte
	}{curveOID, gost28147.PackDKE(gost28147.DKE1())})
	// d = 0x0102: little-endian 02 01 00…00, every bit of it reversed
	bits := make([]byte, 32)
	bits[30], bits[31] = 0x80, 0x40
	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	attrs := []attribute{
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3},
			[]asn1.RawValue{{FullBytes: mustMarshal(t, asn1.BitString{Bytes: bits, BitLength: 256})}}},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2},
			[]asn1.RawValue{{FullBytes: params}}},
	}
	withAttrs := func(attrs []attribute) []byte {
		return mustMarshal(t, struct {
			Version   int
			Algorithm struct {
				Algorithm asn1.ObjectIdentifier
				Params    asn1.RawValue
			}
			PrivateKey []byte
			Attributes []attribute `asn1:"optional,tag:0,set"`
		}{
			Algorithm: struct {
				Algorithm asn1.ObjectIdentifier
				Params    asn1.RawValue
			}{asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}, asn1.RawValue{FullBytes: params}},
			PrivateKey: []byte{7},
			Attributes: attrs,
		})
	}

	got, err := pki.ParsePKCS8KeyAgreementKey(withAttrs(attrs))
	if want := mustHex(t, "0102"); err != nil || !bytes.Equal(bytes.TrimLeft(got.Bytes(), "\x00"), want) {
		t.Errorf("ParsePKCS8KeyAgreementKey(bits %x) = %v, %v, want d = %x", bits, got, err, want)
	}
	if curve, _ := dstu4145.NamedCurve(6); err == nil && got.Public().Curve() != curve {
		t.Errorf("ParsePKCS8KeyAgreementKey() curve = %v, want named curve 6", got.Public().Curve())
	}
	if _, err := pki.ParsePKCS8KeyAgreementKey(withAttrs(nil)); !errors.Is(err, pki.ErrNoKeyAgreementKey) {
		t.Errorf("ParsePKCS8KeyAgreementKey(no attributes) error = %v, want %v", err, pki.ErrNoKeyAgreementKey)
	}
	if _, err := pki.ParsePKCS8KeyAgreementKey(withAttrs(attrs[:1])); err == nil {
		t.Error("ParsePKCS8KeyAgreementKey(key bits without curve) error = nil, want error")
	}
}

// iit-123456.pfx is cryptonite's storageUtest/resources/pkcs12_by_iit(123456).pfx:
// two keys IIT stored under the password 123456, one on a 257-bit curve and
// one on a 431-bit curve, both with explicit parameters.
func TestDecodePFXIIT(t *testing.T) {
	data := readTestdata(t, "iit-123456.pfx")

	pfx, err := pki.DecodePFX(data, "123456")
	if err != nil {
		t.Fatalf("DecodePFX(iit-123456.pfx) error = %v", err)
	}
	var bits []int
	for _, k := range pfx.Keys {
		bits = append(bits, k.Public().Curve().Order().BitLen())
	}
	if want := []int{256, 430}; !slices.Equal(bits, want) || len(pfx.Certificates) != 0 {
		t.Errorf("DecodePFX(iit-123456.pfx) = keys of orders %v bits and %d certificates, want %v and none", bits, len(pfx.Certificates), want)
	}

	if _, err := pki.DecodePFX(data, "654321"); !errors.Is(err, pki.ErrIncorrectPassword) {
		t.Errorf("DecodePFX(iit-123456.pfx, wrong password) error = %v, want %v", err, pki.ErrIncorrectPassword)
	}
	tampered := bytes.Clone(data)
	tampered[100] ^= 1
	if _, err := pki.DecodePFX(tampered, "123456"); err == nil {
		t.Error("DecodePFX(tampered content) error = nil, want error")
	}

	// The attributes IIT wrote on the two key bags of the file: a SET with
	// localKeyID, an OCTET STRING of 32 bytes, as read from the file.
	again, err := pki.EncodePFX(rand.Reader, pfx, "123456", 1)
	if err != nil {
		t.Fatalf("EncodePFX(keys of iit-123456.pfx) error = %v", err)
	}
	for _, id := range []string{
		"4b269ac55f477b40d8c8b7282b72a48e7aea4c609396532d24f7e89a127f357c",
		"46129181c259c5abe7efd2612cfe4e02508ccdde13f3d0c327ced8b8824380ed",
	} {
		attr := mustHex(t, "3131302f06092a864886f70d010915312204"+"20"+id)
		if !bytes.Contains(data, attr) {
			t.Fatalf("iit-123456.pfx has no localKeyID %s", id)
		}
		if !bytes.Contains(again, attr) {
			t.Errorf("EncodePFX(keys of iit-123456.pfx) has no localKeyID %s, as IIT writes", id)
		}
	}
}

// TestMarshalIITPrivateKey checks the PKCS#8 that EncodePFX encrypts against
// the two keys IIT encrypted in iit-123456.pfx: the curve in explicit
// parameters, b and G little-endian, ДКЕ №1, d little-endian, no attributes.
func TestMarshalIITPrivateKey(t *testing.T) {
	pfx, err := pki.DecodePFX(readTestdata(t, "iit-123456.pfx"), "123456")
	if err != nil {
		t.Fatal(err)
	}
	const dke1 = "a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17" +
		"f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904"
	// The plaintext of the two shrouded key bags of iit-123456.pfx: the DER
	// of DecryptPKCS8PrivateKey, written out with openssl asn1parse.
	want := []string{
		"3081f1020100" + "3081c9060b2a86240201010101030101" + "3081b9" +
			"3075" + "30070202010102010c" + "020100" +
			"042110bee3db6aea9e1f86578c45c12594ff942394a7d738f9187e6515017294f4ce01" +
			"0221" + "00800000000000000000000000000000006759213af182e987d3e17714907d470d" +
			"0421b60fd2d8dce8a93423c6101bca91c47a007e6c300b26cd556c9b0e7d20ef292a00" +
			"0440" + dke1 +
			"04204274f69811b61a76c5a0a8454d30c433312742b5c1826aa9d3ee65d03074984e",
		"30820151020100" + "30820112060b2a86240201010101030101" + "30820101" +
			"3081bc" + "300f" + "020201af" + "3009020101020103020105" + "020101" +
			"0436f3ca40c669a4da173149ca12c32dae186b53ac6bc6365997deaeae8ad2d888f9bfd53401694ef9c4273d8cfe6dc28f706a0f4910ce03" +
			"0236" + "3fffffffffffffffffffffffffffffffffffffffffffffffffffffba3175458009a8c0a724f02f81aa8a1fcbaf80d90c7a95110504cf" +
			"04367c857c94c5433bfd991e17c22684065850a9a249ed7bc249ae5a4e878689f872ef7ad524082ec3038e9aede7ba6ba13381d979ba621a" +
			"0440" + dke1 +
			"0436adc503606c5a88dca11b7095624a79b9194e3b3c96d55945e55542c94269cfb06338e1df4680fd0c75a54c1c39790e608ea49c6de91c",
	}
	for i, key := range pfx.Keys {
		got, err := pki.MarshalIITPrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalIITPrivateKey(key %d of iit-123456.pfx) error = %v", i, err)
		}
		if w := mustHex(t, want[i]); !bytes.Equal(got, w) {
			t.Errorf("MarshalIITPrivateKey(key %d of iit-123456.pfx) =\n%x\nwant IIT's\n%x", i, got, w)
		}
	}
}

func TestEncodePFX(t *testing.T) {
	key, other := newKey(t), newKey(t)
	template := rootTemplate()
	der, err := pki.CreateCertificate(rand.Reader, template, template, marshalKey(t, key), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	in := &pki.PFX{Keys: []*dstu4145.PrivateKey{other, key}, Certificates: []*x509.Certificate{cert}}

	data, err := pki.EncodePFX(rand.Reader, in, "пароль", 1024)
	if err != nil {
		t.Fatalf("EncodePFX() error = %v", err)
	}
	out, err := pki.DecodePFX(data, "пароль")
	if err != nil {
		t.Fatalf("DecodePFX(EncodePFX()) error = %v", err)
	}
	if len(out.Keys) != 2 || !bytes.Equal(out.Keys[0].Bytes(), other.Bytes()) || !bytes.Equal(out.Keys[1].Bytes(), key.Bytes()) {
		t.Errorf("DecodePFX(EncodePFX()) keys = %v, want the keys in order", out.Keys)
	}
	if len(out.Certificates) != 1 || !out.Certificates[0].Equal(cert) {
		t.Errorf("DecodePFX(EncodePFX()) certificates = %v, want the certificate", out.Certificates)
	}
	// The key bag and the certificate bag are tied by the same localKeyID,
	// the SKI of the certificate.
	if attr := append(mustHex(t, "302f06092a864886f70d010915312204"+"20"), cert.SubjectKeyId...); bytes.Count(data, attr) != 2 {
		t.Errorf("EncodePFX() has localKeyID %x %d times, want on the key and the certificate", cert.SubjectKeyId, bytes.Count(data, attr))
	}
	if _, err := pki.DecodePFX(data, "парол"); !errors.Is(err, pki.ErrIncorrectPassword) {
		t.Errorf("DecodePFX(EncodePFX(), wrong password) error = %v, want %v", err, pki.ErrIncorrectPassword)
	}

	got, err := out.KeyFor(cert)
	if err != nil || !bytes.Equal(got.Bytes(), key.Bytes()) {
		t.Errorf("KeyFor(certificate of the second key) = %v, %v, want the second key", got, err)
	}
	if _, err := out.KeyFor(newECDSACert(t)); err == nil {
		t.Error("KeyFor(ECDSA certificate) error = nil, want error")
	}
	stranger := &pki.PFX{Keys: []*dstu4145.PrivateKey{other}}
	if _, err := stranger.KeyFor(cert); err == nil {
		t.Error("KeyFor(certificate of no key) error = nil, want error")
	}
}

// testPBES2 mirrors the PBES2 parameters of IIT key files.
type testPBES2 struct {
	KDF struct {
		Algorithm asn1.ObjectIdentifier
		Params    struct {
			Salt       []byte
			Iterations int
			KeyLength  int `asn1:"optional"`
			PRF        pkix.AlgorithmIdentifier
		}
	}
	Scheme struct {
		Algorithm asn1.ObjectIdentifier
		Params    struct {
			IV  []byte
			DKE []byte `asn1:"optional"`
		}
	}
}

type testEncryptedKey struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// editPBES2 returns the EncryptedPrivateKeyInfo der after edit has changed
// its PBES2 parameters and encrypted data.
func editPBES2(t *testing.T, der []byte, edit func(p *testPBES2, data *[]byte)) []byte {
	t.Helper()
	var info testEncryptedKey
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		t.Fatal(err)
	}
	var p testPBES2
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &p); err != nil {
		t.Fatal(err)
	}
	edit(&p, &info.Data)
	info.Algorithm.Parameters = asn1.RawValue{FullBytes: mustMarshal(t, p)}
	return mustMarshal(t, info)
}

// The forms take one PBKDF2 iteration, the key of the jkurwa store
// encrypted again, so that the test stays fast.
func TestDecryptPKCS8PrivateKeyForms(t *testing.T) {
	store := readTestdata(t, "jkurwa-store-a040.dat")
	want := readTestdata(t, "jkurwa-key40a0.der")
	reencrypt := func(gamma bool) func(p *testPBES2, data *[]byte) {
		return func(p *testPBES2, data *[]byte) {
			p.KDF.Params.Iterations = 1
			key, err := pbkdf2.Key(gost34311.New, "password", p.KDF.Params.Salt, 1, 32)
			if err != nil {
				t.Fatal(err)
			}
			block, err := gost28147.NewCipher(key, gost28147.DKE1())
			if err != nil {
				t.Fatal(err)
			}
			stream := cipher.NewCFBEncrypter(block, p.Scheme.Params.IV) //nolint:staticcheck // SA1019: the mode of the key files
			if gamma {
				if stream, err = gost28147.NewCTR(block, p.Scheme.Params.IV); err != nil {
					t.Fatal(err)
				}
				p.Scheme.Algorithm = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 2}
			} else {
				p.Scheme.Params.DKE = nil
			}
			*data = make([]byte, len(want))
			stream.XORKeyStream(*data, want)
		}
	}
	tests := []struct {
		name string
		der  []byte
	}{
		{"ДКЕ №1 implied", editPBES2(t, store, reencrypt(false))},
		{"gamma mode", editPBES2(t, store, reencrypt(true))},
	}
	for _, tt := range tests {
		got, err := pki.DecryptPKCS8PrivateKey(tt.der, "password")
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("DecryptPKCS8PrivateKey(%s) = %x, %v, want %x", tt.name, got, err, want)
		}
	}
}

func TestDecryptPKCS8PrivateKeyMalformed(t *testing.T) {
	store := readTestdata(t, "jkurwa-store-a040.dat")
	edit := func(f func(p *testPBES2)) []byte {
		return editPBES2(t, store, func(p *testPBES2, _ *[]byte) {
			p.KDF.Params.Iterations = 1 // a case fails before or after PBKDF2, never on its result
			f(p)
		})
	}
	oid := asn1.ObjectIdentifier{1, 2, 3}
	tests := []struct {
		name string
		der  []byte
	}{
		{"truncated", store[:len(store)-1]},
		{"not PBES2", mustMarshal(t, testEncryptedKey{pkix.AlgorithmIdentifier{Algorithm: oid}, []byte{1}})},
		{"malformed PBES2 parameters", mustMarshal(t, testEncryptedKey{pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: asn1.NullRawValue}, []byte{1}})},
		{"another key derivation", edit(func(p *testPBES2) { p.KDF.Algorithm = oid })},
		{"another PRF", edit(func(p *testPBES2) { p.KDF.Params.PRF.Algorithm = oid })},
		{"0 iterations", edit(func(p *testPBES2) { p.KDF.Params.Iterations = 0 })},
		{"2^24+1 iterations", edit(func(p *testPBES2) { p.KDF.Params.Iterations = 1<<24 + 1 })},
		{"another cipher", edit(func(p *testPBES2) { p.Scheme.Algorithm = oid })},
		{"IV of 7 bytes", edit(func(p *testPBES2) { p.Scheme.Params.IV = p.Scheme.Params.IV[:7] })},
		{"malformed DKE", edit(func(p *testPBES2) { p.Scheme.Params.DKE = []byte{1, 2, 3} })},
	}
	for _, tt := range tests {
		if got, err := pki.DecryptPKCS8PrivateKey(tt.der, "password"); err == nil {
			t.Errorf("DecryptPKCS8PrivateKey(%s) = %x, want error", tt.name, got)
		}
	}
}

type testAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// withAttributes returns the PKCS#8 key der with attrs as its attributes.
func withAttributes(t *testing.T, der []byte, attrs []testAttribute) []byte {
	t.Helper()
	var key struct {
		Version    int
		Algorithm  asn1.RawValue
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		t.Fatal(err)
	}
	return mustMarshal(t, struct {
		Version    int
		Algorithm  asn1.RawValue
		PrivateKey []byte
		Attributes []testAttribute `asn1:"optional,tag:0,set"`
	}{key.Version, key.Algorithm, key.PrivateKey, attrs})
}

func TestParsePKCS8KeyAgreementKeyMalformed(t *testing.T) {
	key := readTestdata(t, "jkurwa-key40a0.der")
	keyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3}
	curveOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2}
	attr := func(oid asn1.ObjectIdentifier, values ...[]byte) testAttribute {
		a := testAttribute{Type: oid}
		for _, v := range values {
			a.Values = append(a.Values, asn1.RawValue{FullBytes: v})
		}
		return a
	}
	bits := func(b []byte) []byte { return mustMarshal(t, asn1.BitString{Bytes: b, BitLength: 8 * len(b)}) }
	curve6 := mustMarshal(t, struct{ Curve asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}})
	tests := []struct {
		name string
		der  []byte
	}{
		{"not PKCS#8", mustMarshal(t, 5)},
		{"key bits as an INTEGER", withAttributes(t, key, []testAttribute{attr(keyOID, mustMarshal(t, 5)), attr(curveOID, curve6)})},
		{"two values, so no key", withAttributes(t, key, []testAttribute{attr(keyOID, bits([]byte{1}), bits([]byte{2})), attr(curveOID, curve6)})},
		{"curve parameters as an INTEGER", withAttributes(t, key, []testAttribute{attr(keyOID, bits([]byte{1})), attr(curveOID, mustMarshal(t, 5))})},
		{"unknown curve", withAttributes(t, key, []testAttribute{attr(keyOID, bits([]byte{1})),
			attr(curveOID, mustMarshal(t, struct{ Curve asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 3}}))})},
		{"d = 0", withAttributes(t, key, []testAttribute{attr(keyOID, bits(make([]byte, 32))), attr(curveOID, curve6)})},
	}
	for _, tt := range tests {
		if got, err := pki.ParsePKCS8KeyAgreementKey(tt.der); err == nil {
			t.Errorf("ParsePKCS8KeyAgreementKey(%s) = %v, want error", tt.name, got)
		}
	}
}

// testContentInfo is a ContentInfo of the AuthenticatedSafe of a PFX.
type testContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue // the whole [0] element
}

var (
	oidTestData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidTestEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidTestShroudedKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidTestCertBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidTestX509Cert      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// pfxWithoutMAC returns a PFX without a MAC whose AuthenticatedSafe holds
// contents.
func pfxWithoutMAC(t *testing.T, contents ...testContentInfo) []byte {
	t.Helper()
	return mustMarshal(t, struct {
		Version  int
		AuthSafe testContentInfo
	}{3, testContentInfo{oidTestData, contextTag(0, mustMarshal(t, mustMarshal(t, contents)))}})
}

// dataContent returns the ContentInfo of type data with SafeContents der.
func dataContent(t *testing.T, der []byte) testContentInfo {
	t.Helper()
	return testContentInfo{oidTestData, contextTag(0, mustMarshal(t, der))}
}

// encryptedContent returns the ContentInfo of type encryptedData with
// SafeContents der encrypted under password.
func encryptedContent(t *testing.T, der []byte, password string) testContentInfo {
	t.Helper()
	encrypted, err := pki.EncryptPKCS8PrivateKey(rand.Reader, der, password, 1)
	if err != nil {
		t.Fatal(err)
	}
	var info testEncryptedKey
	if _, err := asn1.Unmarshal(encrypted, &info); err != nil {
		t.Fatal(err)
	}
	return testContentInfo{oidTestEncryptedData, contextTag(0, mustMarshal(t, struct {
		Version int
		Info    struct {
			ContentType asn1.ObjectIdentifier
			Algorithm   pkix.AlgorithmIdentifier
			Content     asn1.RawValue
		}
	}{Info: struct {
		ContentType asn1.ObjectIdentifier
		Algorithm   pkix.AlgorithmIdentifier
		Content     asn1.RawValue
	}{oidTestData, info.Algorithm, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: info.Data}}}))}
}

// safeBags returns SafeContents of bags, each an OID and its value.
func safeBags(t *testing.T, bags ...testContentInfo) []byte {
	t.Helper()
	return mustMarshal(t, bags)
}

func certBag(t *testing.T, oid asn1.ObjectIdentifier, value []byte) testContentInfo {
	t.Helper()
	return testContentInfo{oidTestCertBag, contextTag(0, mustMarshal(t, struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oid, contextTag(0, mustMarshal(t, value))}))}
}

func shroudedKey(t *testing.T, pkcs8 []byte, password string) testContentInfo {
	t.Helper()
	encrypted, err := pki.EncryptPKCS8PrivateKey(rand.Reader, pkcs8, password, 1)
	if err != nil {
		t.Fatal(err)
	}
	return testContentInfo{oidTestShroudedKey, contextTag(0, encrypted)}
}

func TestDecodePFXForms(t *testing.T) {
	cert := readCert(t, "czo-2020.der")
	tests := []struct {
		name      string
		data      []byte
		wantKeys  int
		wantCerts int
	}{
		{"certificate in encrypted SafeContents", pfxWithoutMAC(t,
			encryptedContent(t, safeBags(t, certBag(t, oidTestX509Cert, cert.Raw)), "пароль")), 0, 1},
		{"certificate of another kind skipped", pfxWithoutMAC(t,
			dataContent(t, safeBags(t, certBag(t, asn1.ObjectIdentifier{1, 2, 3}, []byte{1})))), 0, 0},
		{"IIT key with a key agreement key", pfxWithoutMAC(t,
			dataContent(t, safeBags(t, shroudedKey(t, withAttributes(t, readTestdata(t, "jkurwa-key40a0.der"), []testAttribute{
				{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3}, []asn1.RawValue{{FullBytes: mustMarshal(t, asn1.BitString{Bytes: []byte{0x80}, BitLength: 8})}}},
				{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2}, []asn1.RawValue{{FullBytes: mustMarshal(t,
					struct{ Curve asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}})}}},
			}), "пароль")))), 2, 0},
		{"IIT key with no key agreement key", pfxWithoutMAC(t,
			dataContent(t, safeBags(t, shroudedKey(t, readTestdata(t, "jkurwa-key40a0.der"), "пароль")))), 1, 0},
	}
	for _, tt := range tests {
		pfx, err := pki.DecodePFX(tt.data, "пароль")
		if err != nil || len(pfx.Keys) != tt.wantKeys || len(pfx.Certificates) != tt.wantCerts {
			t.Errorf("DecodePFX(%s) = %+v, %v, want %d keys and %d certificates", tt.name, pfx, err, tt.wantKeys, tt.wantCerts)
		}
	}
	if pfx, err := pki.DecodePFX(tests[0].data, "пароль"); err == nil && !pfx.Certificates[0].Equal(cert) {
		t.Errorf("DecodePFX(%s) certificate = %v, want %v", tests[0].name, pfx.Certificates[0].Subject, cert.Subject)
	}
}

func TestDecodePFXMalformed(t *testing.T) {
	iit := readTestdata(t, "iit-123456.pfx")
	key := readTestdata(t, "jkurwa-key40a0.der")
	withMAC := func(alg asn1.ObjectIdentifier, iterations int) []byte {
		return mustMarshal(t, struct {
			Version  int
			AuthSafe testContentInfo
			MacData  struct {
				Mac struct {
					Algorithm pkix.AlgorithmIdentifier
					Digest    []byte
				}
				Salt       []byte
				Iterations int
			}
		}{Version: 3, AuthSafe: testContentInfo{oidTestData, contextTag(0, mustMarshal(t, mustMarshal(t, []testContentInfo{})))},
			MacData: struct {
				Mac struct {
					Algorithm pkix.AlgorithmIdentifier
					Digest    []byte
				}
				Salt       []byte
				Iterations int
			}{Mac: struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}{pkix.AlgorithmIdentifier{Algorithm: alg}, make([]byte, 32)}, Salt: make([]byte, 32), Iterations: iterations}})
	}
	gost34311 := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 1}
	agreementWithoutCurve := withAttributes(t, key, []testAttribute{{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3},
		Values: []asn1.RawValue{{FullBytes: mustMarshal(t, asn1.BitString{Bytes: []byte{1}, BitLength: 8})}}}})
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated", iit[:10]},
		{"not a PFX", mustMarshal(t, 5)},
		{"content not data", mustMarshal(t, struct {
			Version  int
			AuthSafe testContentInfo
		}{3, testContentInfo{asn1.ObjectIdentifier{1, 2, 3}, contextTag(0, mustMarshal(t, []byte{}))}})},
		{"MAC on SHA-256", withMAC(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, 1)},
		{"MAC with 0 iterations", withMAC(gost34311, 0)},
		{"MAC with 2^24+1 iterations", withMAC(gost34311, 1<<24+1)},
		{"AuthenticatedSafe not a SEQUENCE", mustMarshal(t, struct {
			Version  int
			AuthSafe testContentInfo
		}{3, testContentInfo{oidTestData, contextTag(0, mustMarshal(t, mustMarshal(t, 5)))}})},
		{"data content not an OCTET STRING", pfxWithoutMAC(t, testContentInfo{oidTestData, contextTag(0, mustMarshal(t, 5))})},
		{"malformed EncryptedData", pfxWithoutMAC(t, testContentInfo{oidTestEncryptedData, contextTag(0, mustMarshal(t, 5))})},
		{"EncryptedData under another password", pfxWithoutMAC(t, encryptedContent(t, safeBags(t), "інший"))},
		{"content of another type", pfxWithoutMAC(t, testContentInfo{asn1.ObjectIdentifier{1, 2, 3}, contextTag(0, mustMarshal(t, 5))})},
		{"SafeContents not a SEQUENCE", pfxWithoutMAC(t, dataContent(t, mustMarshal(t, 5)))},
		{"key under another password", pfxWithoutMAC(t, dataContent(t, safeBags(t, shroudedKey(t, key, "інший"))))},
		{"key not DSTU 4145", pfxWithoutMAC(t, dataContent(t, safeBags(t, shroudedKey(t, mustMarshal(t, struct{ A int }{1}), "пароль"))))},
		{"key agreement key without a curve", pfxWithoutMAC(t, dataContent(t, safeBags(t, shroudedKey(t, agreementWithoutCurve, "пароль"))))},
		{"malformed CertBag", pfxWithoutMAC(t, dataContent(t, safeBags(t, testContentInfo{oidTestCertBag, contextTag(0, mustMarshal(t, 5))})))},
		{"malformed certificate", pfxWithoutMAC(t, dataContent(t, safeBags(t, certBag(t, oidTestX509Cert, []byte{0x30, 0}))))},
	}
	for _, tt := range tests {
		if got, err := pki.DecodePFX(tt.data, "пароль"); err == nil {
			t.Errorf("DecodePFX(%s) = %+v, want error", tt.name, got)
		}
	}
}

func TestEncodePFXErrors(t *testing.T) {
	named := &pki.PFX{Keys: []*dstu4145.PrivateKey{newKey(t)}}
	tests := []struct {
		name       string
		random     io.Reader
		pfx        *pki.PFX
		iterations int
	}{
		{"0 iterations", rand.Reader, named, 0},
		{"no randomness for the key salt", io.LimitReader(rand.Reader, 10), named, 1},
		{"no randomness for the key IV", io.LimitReader(rand.Reader, 32), named, 1},
		{"no randomness for the MAC salt", io.LimitReader(rand.Reader, 10), &pki.PFX{}, 1},
	}
	for _, tt := range tests {
		if _, err := pki.EncodePFX(tt.random, tt.pfx, "пароль", tt.iterations); err == nil {
			t.Errorf("EncodePFX(%s) error = nil, want error", tt.name)
		}
	}
}
