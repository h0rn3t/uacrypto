package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"time"

	"github.com/h0rn3t/uacrypto/gost28147"
)

var (
	oidTSTInfo            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignatureTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

// A TimeStamp is a verified RFC 3161 time-stamp token.
type TimeStamp struct {
	Time         time.Time
	SerialNumber *big.Int
	Policy       asn1.ObjectIdentifier
	Certificate  *x509.Certificate // of the TSA
}

type messageImprint struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type tstInfo struct {
	Version  int
	Policy   asn1.ObjectIdentifier
	Imprint  messageImprint
	Serial   *big.Int
	GenTime  time.Time `asn1:"generalized"`
	Accuracy struct {
		Seconds int `asn1:"optional"`
		Millis  int `asn1:"optional,tag:0"`
		Micros  int `asn1:"optional,tag:1"`
	} `asn1:"optional"`
	Ordering   bool          `asn1:"optional"`
	Nonce      *big.Int      `asn1:"optional"`
	TSA        asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions asn1.RawValue `asn1:"optional,tag:1"`
}

// VerifyTimeStamp verifies the RFC 3161 time-stamp token over data: the
// DSTU 4145 signature of the token, a TSA certificate for time stamping, and
// the message imprint, a Kupyna or GOST 34.311 (ДКЕ №1) hash of data. A
// token over other data is ErrInvalidSignature.
func VerifyTimeStamp(token, data []byte) (*TimeStamp, error) {
	ts, _, err := verifyTimeStamp(token, data)
	return ts, err
}

// verifyTimeStamp is VerifyTimeStamp that also returns the nonce of the token.
func verifyTimeStamp(token, data []byte) (*TimeStamp, *big.Int, error) {
	contentType, content, signers, err := verifySignedData(token, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if !contentType.Equal(oidTSTInfo) || len(signers) != 1 {
		return nil, nil, fmt.Errorf("pki: not a time-stamp token: content type %v, %d signers", contentType, len(signers))
	}
	tsa := signers[0].Certificate
	if !slices.Contains(tsa.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
		return nil, nil, fmt.Errorf("pki: certificate %s is not for time stamping", tsa.Subject)
	}
	var info tstInfo
	if err := unmarshal(content, &info); err != nil {
		return nil, nil, fmt.Errorf("pki: TSTInfo: %w", err)
	}
	h, err := newHash(info.Imprint.Algorithm.Algorithm, gost28147.DKE1())
	if err != nil {
		return nil, nil, err
	}
	h.Write(data)
	if !bytes.Equal(h.Sum(nil), info.Imprint.Digest) {
		return nil, nil, fmt.Errorf("pki: the time-stamp is for other data: %w", ErrInvalidSignature)
	}
	return &TimeStamp{Time: info.GenTime, SerialNumber: info.Serial, Policy: info.Policy, Certificate: tsa}, info.Nonce, nil
}

// A TSAClient requests time-stamp tokens from a time-stamping authority over
// HTTP (RFC 3161), as Ukrainian TSAs serve them.
type TSAClient struct {
	URL        string
	HTTPClient *http.Client // nil: a client with a 30-second timeout
	GOST34311  bool         // TimeStamp hashes with GOST 34.311 instead of Kupyna-256
}

// TimeStamp asks the TSA to stamp data and returns the token after
// VerifyTimeStamp and a check that the TSA echoed the request nonce.
func (c *TSAClient) TimeStamp(ctx context.Context, data []byte) (token []byte, ts *TimeStamp, err error) {
	alg := oidKupyna256
	if c.GOST34311 {
		alg = oidGOST34311
	}
	return c.timeStamp(ctx, alg, data)
}

func (c *TSAClient) timeStamp(ctx context.Context, alg asn1.ObjectIdentifier, data []byte) ([]byte, *TimeStamp, error) {
	h, err := newHash(alg, gost28147.DKE1())
	if err != nil {
		return nil, nil, err
	}
	h.Write(data)
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, nil, fmt.Errorf("pki: nonce: %w", err)
	}
	req, err := asn1.Marshal(struct {
		Version int
		Imprint messageImprint
		Nonce   *big.Int
		CertReq bool
	}{1, messageImprint{pkix.AlgorithmIdentifier{Algorithm: alg}, h.Sum(nil)}, nonce, true})
	if err != nil {
		return nil, nil, fmt.Errorf("pki: TimeStampReq: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(req))
	if err != nil {
		return nil, nil, fmt.Errorf("pki: TSA request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: TSA: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("pki: TSA answered %s", resp.Status)
	}
	const maxResponse = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, nil, fmt.Errorf("pki: TSA response: %w", err)
	}
	if len(body) > maxResponse {
		return nil, nil, fmt.Errorf("pki: TSA response exceeds %d bytes", maxResponse)
	}

	var tsResp struct {
		Status struct {
			Status   int
			Text     asn1.RawValue  `asn1:"optional"`
			FailInfo asn1.BitString `asn1:"optional"`
		}
		Token asn1.RawValue `asn1:"optional"`
	}
	if err := unmarshal(body, &tsResp); err != nil {
		return nil, nil, fmt.Errorf("pki: TimeStampResp: %w", err)
	}
	if s := tsResp.Status.Status; s != 0 && s != 1 { // granted, grantedWithMods
		return nil, nil, fmt.Errorf("pki: TSA refused the request: status %d", s)
	}
	token := tsResp.Token.FullBytes
	if token == nil {
		return nil, nil, errors.New("pki: TSA granted the request but sent no token")
	}
	ts, echoed, err := verifyTimeStamp(token, data)
	if err != nil {
		return nil, nil, err
	}
	if echoed == nil || echoed.Cmp(nonce) != 0 {
		return nil, nil, errors.New("pki: the time-stamp token does not carry the request nonce")
	}
	return token, ts, nil
}

// AddSignatureTimeStamp turns a CAdES-BES SignedData into CAdES-T: it asks tsa
// to stamp the signature value of every signer, hashed with the signer's
// digest algorithm, and adds the token as the unsigned attribute
// signatureTimeStampToken. tsa.GOST34311 is not used.
func AddSignatureTimeStamp(ctx context.Context, signed []byte, tsa *TSAClient) ([]byte, error) {
	sd, err := parseSignedData(signed)
	if err != nil {
		return nil, err
	}
	for i := range sd.SignerInfos {
		si := &sd.SignerInfos[i]
		token, _, err := tsa.timeStamp(ctx, si.DigestAlgorithm.Algorithm, si.Signature)
		if err != nil {
			return nil, fmt.Errorf("pki: signer %d: %w", i, err)
		}
		attrs, err := parseAttributes(si.UnsignedAttrs)
		if err != nil {
			return nil, fmt.Errorf("pki: signer %d unsigned attributes: %w", i, err)
		}
		attrs = append(attrs, attribute{
			Type:   oidSignatureTimeStamp,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: token},
		})
		set, err := asn1.MarshalWithParams(attrs, "set")
		if err != nil {
			return nil, fmt.Errorf("pki: unsigned attributes: %w", err)
		}
		si.UnsignedAttrs = asn1.RawValue{FullBytes: append([]byte{0xa1}, set[1:]...)} // [1] IMPLICIT SET
	}
	return sd.marshal()
}
