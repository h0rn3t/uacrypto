package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/h0rn3t/uacrypto/pki"
)

// tlv writes a DER value by hand: the tag, the definite length and the content.
func tlv(tag byte, content ...[]byte) []byte {
	body := slices.Concat(content...)
	switch n := len(body); {
	case n < 0x80:
		return slices.Concat([]byte{tag, byte(n)}, body)
	case n < 0x100:
		return slices.Concat([]byte{tag, 0x81, byte(n)}, body)
	case n < 0x10000:
		return slices.Concat([]byte{tag, 0x82, byte(n >> 8), byte(n & 0xff)}, body)
	default:
		panic("tlv: content longer than 64 KiB")
	}
}

func TestCreateCertificatePolicy(t *testing.T) {
	root, rootKey := newTestRoot(t)
	// the value DKSU writes, the policy alone without qualifiers
	want := extension(readCert(t, "dksu-ca.der"), asn1.ObjectIdentifier{2, 5, 29, 32}).Value
	if e := extension(root, asn1.ObjectIdentifier{2, 5, 29, 32}); e == nil || e.Critical || !bytes.Equal(e.Value, want) {
		t.Errorf("CreateCertificate(no policies) certificatePolicies = %+v, want non-critical %x", e, want)
	}

	own, err := x509.ParseOID("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "own policy"}, NotBefore: now, NotAfter: now.Add(time.Hour), Policies: []x509.OID{own}}
	der, err := pki.CreateCertificate(rand.Reader, tmpl, root, marshalKey(t, newKey(t)), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Policies) != 1 || !c.Policies[0].Equal(own) {
		t.Errorf("CreateCertificate(policy 1.2.3.4) policies = %v, want the template's alone", c.Policies)
	}
}

func TestMarshalName(t *testing.T) {
	oidOrganizationIdentifier := asn1.ObjectIdentifier{2, 5, 4, 97}
	for _, file := range []string{"czo-test-ocsp-ca.der", "vchasno-gost.der"} {
		t.Run(file, func(t *testing.T) {
			c := readCert(t, file)
			// the name of the ЦЗО and of Вчасно without its last RDN, organizationIdentifier
			var rdns []asn1.RawValue
			if _, err := asn1.Unmarshal(c.RawSubject, &rdns); err != nil {
				t.Fatal(err)
			}
			var last pkix.RelativeDistinguishedNameSET
			if _, err := asn1.Unmarshal(rdns[len(rdns)-1].FullBytes, &last); err != nil || !last[0].Type.Equal(oidOrganizationIdentifier) {
				t.Fatalf("%s: the last RDN is %v, want organizationIdentifier", file, last)
			}
			var body []byte
			for _, rdn := range rdns[:len(rdns)-1] {
				body = append(body, rdn.FullBytes...)
			}
			want := tlv(0x30, body)

			s := c.Subject
			name := pkix.Name{Organization: s.Organization, OrganizationalUnit: s.OrganizationalUnit, CommonName: s.CommonName, SerialNumber: s.SerialNumber, Country: s.Country, Locality: s.Locality, Names: s.Names}
			if got, err := pki.MarshalName(name); err != nil || !bytes.Equal(got, want) {
				t.Errorf("MarshalName(%s) = %x, %v, want %x", file, got, err, want)
			}
		})
	}

	for name, n := range map[string]pkix.Name{
		"province":              {CommonName: "Тест", Province: []string{"Київська"}},
		"extra names":           {CommonName: "Тест", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "NTRUA-00000000"}}},
		"serial not printable":  {CommonName: "Тест", SerialNumber: "ТІН-1"},
		"country not printable": {CommonName: "Тест", Country: []string{"УА"}},
	} {
		if got, err := pki.MarshalName(n); err == nil {
			t.Errorf("MarshalName(%s) = %x, want error", name, got)
		}
	}
}

func TestMarshalAuthorityKeyIdentifier(t *testing.T) {
	root, rootKey := newTestRoot(t)
	ext, err := pki.MarshalAuthorityKeyIdentifier(root)
	if err != nil {
		t.Fatal(err)
	}
	// keyIdentifier [0], authorityCertIssuer [1] { directoryName [4] }, authorityCertSerialNumber [2]
	want := tlv(0x30, tlv(0x80, root.SubjectKeyId), tlv(0xa1, tlv(0xa4, root.RawIssuer)), tlv(0x82, root.SerialNumber.Bytes()))
	if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) || ext.Critical || !bytes.Equal(ext.Value, want) {
		t.Errorf("MarshalAuthorityKeyIdentifier(root) = %v %v %x, want non-critical %x", ext.Id, ext.Critical, ext.Value, want)
	}

	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(6), Subject: pkix.Name{CommonName: "user"}, NotBefore: now, NotAfter: now.Add(time.Hour), ExtraExtensions: []pkix.Extension{ext}}
	der, err := pki.CreateCertificate(rand.Reader, tmpl, root, marshalKey(t, newKey(t)), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if e := extension(c, ext.Id); e == nil || !bytes.Equal(e.Value, want) || !bytes.Equal(c.AuthorityKeyId, root.SubjectKeyId) {
		t.Errorf("CreateCertificate(with MarshalAuthorityKeyIdentifier) AKI = %+v, want %x", e, want)
	}

	if ext, err := pki.MarshalAuthorityKeyIdentifier(&x509.Certificate{SerialNumber: big.NewInt(1)}); err == nil {
		t.Errorf("MarshalAuthorityKeyIdentifier(no SKI) = %+v, want error", ext)
	}
}

func TestMarshalSubjectInfoAccess(t *testing.T) {
	const url = "http://127.0.0.1:8899/services/tsp/"
	// SEQUENCE { SEQUENCE { id-ad-timeStamping, [6] url } }
	want := "3031302f06082b060105050730038623" + hex.EncodeToString([]byte(url))
	ext, err := pki.MarshalSubjectInfoAccess(url)
	if err != nil || !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}) || ext.Critical || hex.EncodeToString(ext.Value) != want {
		t.Errorf("MarshalSubjectInfoAccess(%q) = %v %v %x, %v, want non-critical %s", url, ext.Id, ext.Critical, ext.Value, err, want)
	}
	for _, url := range []string{"", "http://цск.укр/tsp"} {
		if ext, err := pki.MarshalSubjectInfoAccess(url); err == nil {
			t.Errorf("MarshalSubjectInfoAccess(%q) = %+v, want error", url, ext)
		}
	}
}

func TestOCSPResponderExtensions(t *testing.T) {
	got := pki.OCSPResponderExtensions()
	// the extended key usage DKSU writes in its OCSP responder certificate: OCSPSigning, critical
	eku := *extension(readCert(t, "dksu-ocsp-be.der"), asn1.ObjectIdentifier{2, 5, 29, 37})
	nocheck := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{0x05, 0x00}}
	if len(got) != 2 || !got[0].Id.Equal(eku.Id) || got[0].Critical != eku.Critical || !bytes.Equal(got[0].Value, eku.Value) ||
		!got[1].Id.Equal(nocheck.Id) || got[1].Critical || !bytes.Equal(got[1].Value, nocheck.Value) {
		t.Errorf("OCSPResponderExtensions() = %+v, want %+v and %+v", got, eku, nocheck)
	}
	got[0].Value[0] = 0
	if again := pki.OCSPResponderExtensions(); again[0].Value[0] != 0x30 {
		t.Error("OCSPResponderExtensions() shares its values between calls")
	}
}

func TestCertificatePublicKey(t *testing.T) {
	for _, tt := range []struct {
		name    string
		request string
	}{
		{"LE key", bcLEKeyBESig},
		{"BE key", bcBEKeyBESig},
	} {
		cr, err := pki.ParseCertificateRequest(mustHex(t, tt.request))
		if err != nil {
			t.Fatal(err)
		}
		spki, err := cr.CertificatePublicKey()
		if err != nil {
			t.Fatalf("CertificatePublicKey(%s) error = %v", tt.name, err)
		}
		var alg struct{ Algorithm pkix.AlgorithmIdentifier }
		if _, err := asn1.Unmarshal(spki, &alg); err != nil || !alg.Algorithm.Algorithm.Equal(oidDSTULE) {
			t.Errorf("CertificatePublicKey(%s) algorithm = %v, %v, want dstu4145le", tt.name, alg.Algorithm.Algorithm, err)
		}
		key, err := pki.ParsePublicKey(spki)
		if err != nil || key.Key.Curve() != cr.PublicKey.Key.Curve() || !bytes.Equal(key.Key.Bytes(), cr.PublicKey.Key.Bytes()) {
			t.Errorf("CertificatePublicKey(%s) = a key %v, %v, want the key of the request", tt.name, key, err)
		}
		if cr.PublicKeyAlgorithm.Equal(oidDSTULE) && !bytes.Equal(spki, cr.RawSubjectPublicKeyInfo) {
			t.Errorf("CertificatePublicKey(%s) = %x, want the key of the request as it is %x", tt.name, spki, cr.RawSubjectPublicKeyInfo)
		}
	}

	cr, err := pki.ParseCertificateRequest(mustHex(t, rsaRequest))
	if err != nil {
		t.Fatal(err)
	}
	if spki, err := cr.CertificatePublicKey(); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		t.Errorf("CertificatePublicKey(RSA) = %x, %v, want x509.ErrUnsupportedAlgorithm", spki, err)
	}
}

func TestCertificateSignatureAlgorithm(t *testing.T) {
	// the algorithms openssl asn1parse shows in these certificates
	for _, tt := range []struct {
		file string
		want asn1.ObjectIdentifier
	}{
		{"vchasno-gost.der", asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}},
		{"vchasno-kupyna.der", asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 1, 1}},
		{"monobank-cmp-kupyna512.der", asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 3, 1}},
	} {
		if got, err := pki.CertificateSignatureAlgorithm(readCert(t, tt.file)); err != nil || !got.Equal(tt.want) {
			t.Errorf("CertificateSignatureAlgorithm(%s) = %v, %v, want %v", tt.file, got, err, tt.want)
		}
	}
	if got, err := pki.CertificateSignatureAlgorithm(&x509.Certificate{Raw: []byte{0x30, 0x00}}); err == nil {
		t.Errorf("CertificateSignatureAlgorithm(empty SEQUENCE) = %v, want error", got)
	}
}
