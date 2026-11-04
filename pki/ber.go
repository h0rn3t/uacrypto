package pki

import (
	"encoding/asn1"
	"errors"
	"slices"
)

// maxBERDepth bounds the nesting toDER follows: deeper input is an error,
// not a stack overflow, which recover cannot catch.
const maxBERDepth = 64

var errBER = errors.New("pki: malformed BER")

// toDER re-encodes the BER value b in DER, as Bouncy Castle reads requests
// and CMS: indefinite lengths of constructed values and long or non-minimal
// length forms become minimal definite lengths, and a constructed OCTET
// STRING, the chunked eContent of a streamed SignedData, becomes one
// primitive OCTET STRING. The order of a SET OF and other constructed strings
// stay as they are, and DER input comes back byte for byte.
func toDER(b []byte) ([]byte, error) {
	der, rest, err := berValue(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("pki: trailing data after BER value")
	}
	return der, nil
}

// berValue reads the value at the start of b and returns it in DER and the
// rest of b.
func berValue(b []byte, depth int) (der, rest []byte, err error) {
	if depth > maxBERDepth {
		return nil, nil, errors.New("pki: BER nested too deep")
	}
	// identifier octets: a tag number of 31 or more continues in base 128
	n := 1
	if len(b) > 0 && b[0]&0x1f == 0x1f {
		for n < len(b) && b[n]&0x80 != 0 {
			n++
		}
		n++
	}
	if len(b) < n+1 || b[0] == 0 {
		return nil, nil, errBER // truncated, or end-of-contents outside an indefinite length
	}
	tag, constructed := b[:n], b[0]&0x20 != 0

	var content []byte
	if b[n] == 0x80 { // indefinite length, ended by 00 00
		if !constructed {
			return nil, nil, errBER
		}
		rest = b[n+1:]
		for {
			if len(rest) < 2 {
				return nil, nil, errBER
			}
			if rest[0] == 0 && rest[1] == 0 {
				rest = rest[2:]
				break
			}
			var child []byte
			if child, rest, err = berValue(rest, depth+1); err != nil {
				return nil, nil, err
			}
			content = append(content, child...)
		}
	} else {
		length, start := int(b[n]), n+1
		if length&0x80 != 0 {
			size := length & 0x7f
			if size > 4 || len(b) < start+size {
				return nil, nil, errBER
			}
			length = 0
			for _, c := range b[start : start+size] {
				length = length<<8 | int(c)
			}
			start += size
		}
		if len(b)-start < length {
			return nil, nil, errBER
		}
		body := b[start : start+length]
		rest = b[start+length:]
		if !constructed {
			content = body
		}
		for len(body) > 0 && constructed {
			var child []byte
			if child, body, err = berValue(body, depth+1); err != nil {
				return nil, nil, err
			}
			content = append(content, child...)
		}
	}
	if b[0] == 0x24 { // constructed OCTET STRING: its chunks, already DER, join into one
		var octets []byte
		for chunks := content; len(chunks) > 0; {
			var chunk asn1.RawValue
			if chunks, err = asn1.Unmarshal(chunks, &chunk); err != nil {
				return nil, nil, err
			}
			if chunk.Class != asn1.ClassUniversal || chunk.Tag != asn1.TagOctetString {
				return nil, nil, errBER
			}
			octets = append(octets, chunk.Bytes...)
		}
		tag, content = []byte{asn1.TagOctetString}, octets
	}
	return slices.Concat(tag, derLength(len(content)), content), rest, nil
}

// derLength returns the DER length octets of n.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)} //nolint:gosec // G115: n < 0x80
	}
	var octets []byte
	for ; n > 0; n >>= 8 {
		octets = append([]byte{byte(n)}, octets...)
	}
	return append([]byte{0x80 | byte(len(octets))}, octets...) //nolint:gosec // G115: an int has at most 8 octets
}
