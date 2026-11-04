package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/h0rn3t/uacrypto/pki"
)

// Requests that Bouncy Castle 1.86 signed (JcaPKCS10CertificationRequestBuilder,
// GOST3411WITHDSTU4145), which test-ca accepts as ca.java did: a dstu4145be key
// with a signature s||r big-endian, and a dstu4145le key with the same signature.
const (
	bcBEKeyBESig = "3081da30818102010030303113301106035504030c0a42432042452054657374310c300a060355040a0c034f7267310b300906035504061302554130483020060d2a862402010101010301010101300f060d2a8624020101010103010102060324000421017a55427e301b6568a7e631c70b8cc8143757e91ff8ddaac184ed04e31c8de7c5a000300f060d2a8624020101010103010101010343000440504950cadb402eb4a39b2e3e7d82d1e0bc6c20ea70c3c43f3bad70377fb9465c34704f32f2605f38385beae5db28093df2fece309528a76ecd7738cbdfffd141"
	bcLEKeyBESig = "3081cd307502010030263116301406035504030c0d4c45206b657920424520736967310c300a060355040a0c034f72673046301e060b2a86240201010101030101300f060d2a8624020101010103010102060324000421164d31e108d2a4451ce5f6cdcf32c0dab17ae534ba590fdfdaa3e6a3d6f0bc5900a000300f060d2a8624020101010103010101010343000440453ebcbf14045148eb0153832d978e1c1a7e3233d84a37d67016d743492d93820c2899a85b9379cd59c4e7855feb9bfdf25a830dce2ab870c7d175b6add3ba2d"
	// An RSA request: version 0, empty subject, rsaEncryption key, sha256WithRSAEncryption.
	rsaRequest = "3037" + "301d" + "020100" + "3000" + "3014" + "300d06092a864886f70d0101010500" + "0303003000" + "a000" +
		"300b06092a864886f70d01010b" + "030900" + "0000000000000000"
)

var (
	oidDSTULE    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	oidDSTUBE    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1}
	oidRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

func TestCreateCertificateRequest(t *testing.T) {
	key := newKey(t)
	der, err := pki.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Тест Тестович", SerialNumber: "TINUA-0000000000"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest() error = %v", err)
	}
	cr, err := pki.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest(CreateCertificateRequest()) error = %v", err)
	}
	if err := cr.CheckSignature(); err != nil {
		t.Errorf("CheckSignature() = %v, want nil", err)
	}
	if cr.Subject.CommonName != "Тест Тестович" || cr.Subject.SerialNumber != "TINUA-0000000000" {
		t.Errorf("ParseCertificateRequest() subject = %v, want the template's", cr.Subject)
	}
	if !bytes.Equal(cr.RawSubjectPublicKeyInfo, marshalKey(t, key)) || !cr.PublicKeyAlgorithm.Equal(oidDSTULE) || !cr.SignatureAlgorithm.Equal(oidDSTULE) {
		t.Errorf("ParseCertificateRequest() key %x, algorithms %v %v, want the key as MarshalPublicKey writes it and dstu4145le", cr.RawSubjectPublicKeyInfo, cr.PublicKeyAlgorithm, cr.SignatureAlgorithm)
	}
	if !bytes.Equal(cr.Raw, der) {
		t.Error("ParseCertificateRequest(DER) Raw is not the input")
	}

	// a changed byte of the subject breaks the proof of possession
	i := bytes.Index(der, []byte("TINUA"))
	tampered := bytes.Clone(der)
	tampered[i] ^= 1
	if cr, err := pki.ParseCertificateRequest(tampered); err != nil || !errors.Is(cr.CheckSignature(), pki.ErrInvalidSignature) {
		t.Errorf("CheckSignature(request with a changed subject) = %v, want ErrInvalidSignature", cr.CheckSignature())
	}

	// BER as Bouncy Castle accepts it: the outer SEQUENCE with an indefinite length
	cr, err = pki.ParseCertificateRequest(toBER(t, der))
	if err != nil {
		t.Fatalf("ParseCertificateRequest(BER) error = %v", err)
	}
	if !bytes.Equal(cr.Raw, der) || cr.CheckSignature() != nil {
		t.Errorf("ParseCertificateRequest(BER) = Raw %x, CheckSignature %v, want the DER request and nil", cr.Raw, cr.CheckSignature())
	}
}

func TestParseCertificateRequestBC(t *testing.T) {
	for _, tt := range []struct {
		name    string
		request string
		key     asn1.ObjectIdentifier
	}{
		{"BE key, BE signature", bcBEKeyBESig, oidDSTUBE},
		{"LE key, BE signature", bcLEKeyBESig, oidDSTULE},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := pki.ParseCertificateRequest(mustHex(t, tt.request))
			if err != nil {
				t.Fatalf("ParseCertificateRequest(BC %s) error = %v", tt.name, err)
			}
			if err := cr.CheckSignature(); err != nil {
				t.Errorf("CheckSignature(BC %s) = %v, want nil", tt.name, err)
			}
			if !cr.PublicKeyAlgorithm.Equal(tt.key) || !cr.SignatureAlgorithm.Equal(oidDSTUBE) || cr.PublicKey == nil {
				t.Errorf("ParseCertificateRequest(BC %s) key %v, signature %v, want %v and dstu4145be", tt.name, cr.PublicKeyAlgorithm, cr.SignatureAlgorithm, tt.key)
			}
		})
	}
}

func TestParseCertificateRequestRejects(t *testing.T) {
	// a key of another algorithm parses, so that a CA can name it, and fails the check
	cr, err := pki.ParseCertificateRequest(mustHex(t, rsaRequest))
	if err != nil {
		t.Fatalf("ParseCertificateRequest(RSA) error = %v, want the request", err)
	}
	if cr.PublicKey != nil || !cr.PublicKeyAlgorithm.Equal(oidRSA) || !cr.SignatureAlgorithm.Equal(oidSHA256RSA) {
		t.Errorf("ParseCertificateRequest(RSA) = key %v (%v), signature %v, want no DSTU key, rsaEncryption and sha256WithRSAEncryption", cr.PublicKey, cr.PublicKeyAlgorithm, cr.SignatureAlgorithm)
	}
	if err := cr.CheckSignature(); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		t.Errorf("CheckSignature(RSA) = %v, want x509.ErrUnsupportedAlgorithm", err)
	}

	// a DSTU key signed with an unknown algorithm
	der := mustHex(t, bcLEKeyBESig)
	i := bytes.LastIndex(der, oidBytes(t, oidDSTUBE))
	der[i+len(oidBytes(t, oidDSTUBE))-1] = 0x02 // 1.2.804.2.1.1.1.1.3.1.1.1.2
	cr, err = pki.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.CheckSignature(); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		t.Errorf("CheckSignature(signature algorithm %v) = %v, want x509.ErrUnsupportedAlgorithm", cr.SignatureAlgorithm, err)
	}

	for name, in := range map[string][]byte{
		"empty":   nil,
		"garbage": []byte("not a request"),
		"bad DSTU key": func() []byte {
			b := mustHex(t, bcBEKeyBESig)
			b[bytes.Index(b, mustHex(t, "0421017a55"))+2] = 0xff // x beyond the field
			return b
		}(),
	} {
		if cr, err := pki.ParseCertificateRequest(in); err == nil {
			t.Errorf("ParseCertificateRequest(%s) = %+v, want error", name, cr)
		}
	}
}

func oidBytes(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	return mustMarshal(t, oid)
}
