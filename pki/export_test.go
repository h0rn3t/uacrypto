package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"io"

	"github.com/h0rn3t/uacrypto/dstu4145"
)

// SignContent lets tests sign content types other than data, as a TSA signs TSTInfo.
func SignContent(random io.Reader, contentType asn1.ObjectIdentifier, content []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	sd, err := signContent(random, contentType, content, key, cert, opts)
	if err != nil {
		return nil, err
	}
	return sd.marshal()
}

// ToDER lets tests reach the BER normalization of the parsers.
var ToDER = toDER

// The steps of EnvelopedData, for the jkurwa envelope whose IV
// DecryptEnvelopedData rejects.
var (
	EnvelopeKEK     = envelopeKEK
	GOST28147Wrap   = gost28147Wrap
	GOST28147Unwrap = gost28147Unwrap
)
