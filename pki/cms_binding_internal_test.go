package pki

import (
	"crypto/md5"  //nolint:gosec // G501: the binding must reject an MD5 reference
	"crypto/sha1" //nolint:gosec // G505: RFC 5035 SigningCertificate v1 uses SHA-1
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestCheckSignedAttrsCertificateBinding(t *testing.T) {
	marshal := func(v any) []byte {
		t.Helper()
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cert := &x509.Certificate{Raw: []byte("certificate DER"), SerialNumber: big.NewInt(7)}
	cert.RawIssuer = marshal(pkix.Name{CommonName: "issuer"}.ToRDNSequence())
	type certRef struct {
		Algorithm    pkix.AlgorithmIdentifier `asn1:"optional"`
		Digest       []byte
		IssuerSerial issuerSerial `asn1:"optional"`
	}
	hash := sha256.Sum256(cert.Raw)
	v2 := certRef{Digest: hash[:]}
	v1Hash := sha1.Sum(cert.Raw) //nolint:gosec // G401: exercise RFC 5035 v1 compatibility
	v1 := certRef{Digest: v1Hash[:]}
	value := func(refs ...certRef) []byte { return marshal(struct{ Certs []certRef }{refs}) }
	withIssuer := v2
	withIssuer.IssuerSerial = newIssuerSerial(cert)
	wrongIssuer := withIssuer
	wrongIssuer.IssuerSerial.Serial = big.NewInt(8)
	wrongHash := v2
	wrongHash.Digest = make([]byte, len(hash))
	explicit := v2
	explicit.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	md5Hash := md5.Sum(cert.Raw) //nolint:gosec // G401: the binding must reject an MD5 reference
	md5Ref := certRef{Digest: md5Hash[:]}
	md5Ref.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	unknown := v2
	unknown.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
	v1OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		value     []byte
		duplicate int
		wantErr   bool
	}{
		{"default SHA256", oidSigningCertV2, value(v2), -1, false},
		{"explicit SHA256", oidSigningCertV2, value(explicit), -1, false},
		{"issuer serial", oidSigningCertV2, value(withIssuer), -1, false},
		{"legacy SHA1", v1OID, value(v1), -1, false},
		{"wrong certificate hash", oidSigningCertV2, value(wrongHash), -1, true},
		{"first reference must match", oidSigningCertV2, value(wrongHash, v2), -1, true},
		{"wrong issuer serial", oidSigningCertV2, value(wrongIssuer), -1, true},
		{"MD5 digest", oidSigningCertV2, value(md5Ref), -1, true},
		{"unknown digest", oidSigningCertV2, value(unknown), -1, true},
		{"no certificate references", oidSigningCertV2, value(), -1, true},
		{"multiple values", oidSigningCertV2, append(value(v2), value(v2)...), -1, true},
		{"duplicate attribute", oidSigningCertV2, value(v2), 2, true},
		{"duplicate contentType", oidSigningCertV2, value(v2), 0, true},
		{"duplicate messageDigest", oidSigningCertV2, value(v2), 1, true},
		{"duplicate signingTime", oidSigningCertV2, value(v2), 3, true},
		{"malformed value", oidSigningCertV2, []byte{0x05, 0}, -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := func(oid asn1.ObjectIdentifier, data []byte) attribute {
				return attribute{Type: oid, Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: data}}
			}
			attrs := []attribute{attr(oidContentType, marshal(oidData)), attr(oidMessageDigest, marshal([]byte("digest"))), attr(tt.oid, tt.value), attr(oidSigningTime, marshal(time.Unix(1700000000, 0).UTC()))}
			if tt.duplicate >= 0 {
				attrs = append(attrs, attrs[tt.duplicate])
			}
			set, err := asn1.MarshalWithParams(attrs, "set")
			if err != nil {
				t.Fatal(err)
			}
			_, err = checkSignedAttrs(set, oidData, []byte("digest"), cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkSignedAttrs(%s) error = %v, want error %v", tt.name, err, tt.wantErr)
			}
		})
	}
}
