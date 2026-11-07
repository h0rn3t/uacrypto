package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/h0rn3t/uacrypto/dstu4145"
)

// A TimeStampRequest is an RFC 3161 TimeStampReq as a TSA reads it.
type TimeStampRequest struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
	Policy        asn1.ObjectIdentifier // nil when the request names none
	Nonce         *big.Int              // nil when the request has none
	CertReq       bool
	Extensions    []pkix.Extension
}

// ParseTimeStampRequest parses an RFC 3161 TimeStampReq in DER or BER.
func ParseTimeStampRequest(der []byte) (*TimeStampRequest, error) {
	der, err := toDER(der)
	if err != nil {
		return nil, err
	}
	var req struct {
		Version    int
		Imprint    messageImprint
		Policy     asn1.ObjectIdentifier `asn1:"optional"`
		Nonce      *big.Int              `asn1:"optional"`
		CertReq    bool                  `asn1:"optional"`
		Extensions []pkix.Extension      `asn1:"optional,tag:0"`
	}
	if err := unmarshal(der, &req); err != nil {
		return nil, fmt.Errorf("pki: TimeStampReq: %w", err)
	}
	return &TimeStampRequest{
		HashAlgorithm: req.Imprint.Algorithm,
		HashedMessage: req.Imprint.Digest,
		Policy:        req.Policy,
		Nonce:         req.Nonce,
		CertReq:       req.CertReq,
		Extensions:    req.Extensions,
	}, nil
}

// oidTimeStampPolicy is the policy of Ukrainian TSAs that sign with
// GOST 34.311.
var oidTimeStampPolicy = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 2, 3, 1}

// timeStampDigests are the hashes of a message imprint that a TSA stamps,
// the ones the TSA of ca.java on Bouncy Castle accepted.
var timeStampDigests = []asn1.ObjectIdentifier{
	oidGOST34311, oidKupyna256, oidKupyna384, oidKupyna512,
	{2, 16, 840, 1, 101, 3, 4, 2, 1}, {2, 16, 840, 1, 101, 3, 4, 2, 2}, {2, 16, 840, 1, 101, 3, 4, 2, 3}, // SHA-256, SHA-384, SHA-512
}

// CreateTimeStampResponse answers req with a DER TimeStampResp granting a
// time-stamp token: TSTInfo with the policy of req, or ts.Policy when req
// names none, or 1.2.804.2.1.1.1.2.3.1, the policy of Ukrainian TSAs that
// sign with GOST 34.311 (PrivatBank, the tax service), when neither does;
// the message imprint of req, ts.SerialNumber, ts.Time to the second, an
// accuracy of one second, and the nonce and extensions of req,
// signed by key for ts.Certificate in the form of SignData with
// GOST 34.311, carrying the certificate when req.CertReq is set.
//
// A message imprint hashed with other than GOST 34.311, Kupyna or SHA-2
// gets a response with the status rejection and the failure badAlg, not an
// error, as Bouncy Castle's TimeStampResponseGenerator answers it.
func CreateTimeStampResponse(random io.Reader, req *TimeStampRequest, ts *TimeStamp, key *dstu4145.PrivateKey) ([]byte, error) {
	if !slices.ContainsFunc(timeStampDigests, req.HashAlgorithm.Algorithm.Equal) {
		return asn1.Marshal(struct {
			Status struct {
				Status   int
				Text     []asn1.RawValue
				FailInfo asn1.BitString
			}
		}{struct {
			Status   int
			Text     []asn1.RawValue
			FailInfo asn1.BitString
		}{
			2, // rejection
			[]asn1.RawValue{{Tag: asn1.TagUTF8String, Bytes: []byte("unsupported digest")}},
			asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}, // badAlg
		}})
	}
	policy := req.Policy
	if policy == nil {
		policy = ts.Policy
	}
	if policy == nil {
		policy = oidTimeStampPolicy
	}
	info := tstInfo{
		Version: 1,
		Policy:  policy,
		Imprint: messageImprint{req.HashAlgorithm, req.HashedMessage},
		Serial:  ts.SerialNumber,
		GenTime: ts.Time.UTC(),
		Nonce:   req.Nonce,
	}
	info.Accuracy.Seconds = 1
	if req.Extensions != nil {
		exts, err := asn1.Marshal(req.Extensions)
		if err != nil {
			return nil, fmt.Errorf("pki: TSTInfo extensions: %w", err)
		}
		info.Extensions = asn1.RawValue{FullBytes: append([]byte{0xa1}, exts[1:]...)} // [1] IMPLICIT
	}
	content, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("pki: TSTInfo: %w", err)
	}
	sd, err := signContent(random, oidTSTInfo, content, key, ts.Certificate, SignOptions{GOST34311: true}, true)
	if err != nil {
		return nil, err
	}
	if !req.CertReq {
		sd.Certificates = asn1.RawValue{}
	}
	token, err := sd.marshal()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Status struct{ Status int }
		Token  asn1.RawValue
	}{Token: asn1.RawValue{FullBytes: token}}) // granted
}
