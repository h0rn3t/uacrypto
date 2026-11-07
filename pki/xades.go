package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/h0rn3t/uacrypto/dstu4145"
)

// The URIs of XML signatures that XAdES of IIT uses.
const (
	nsXAdES    = "http://uri.etsi.org/01903/v1.3.2#"
	nsXAdES141 = "http://uri.etsi.org/01903/v1.4.1#"
	nsXML      = "http://www.w3.org/XML/1998/namespace"
	excC14N    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	enveloped  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

	signedPropertiesType = "http://uri.etsi.org/01903#SignedProperties"

	sigDSTU4145GOST34311 = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311"
	sigDSTU4145Kupyna256 = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256"
)

// maxXMLDepth bounds the nesting of a document VerifyXAdES reads, so that a
// crafted one cannot exhaust the stack of the canonicalization.
const maxXMLDepth = 256

// VerifyXAdES verifies every XAdES signature (ds:Signature) of the XML
// document doc as IIT writes them: XAdES-B-B, B-T, B-LT and B-LTA with
// Exclusive XML Canonicalization, DSTU 4145 with GOST 34.311 or Kupyna-256
// (http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311, …#dstu4145-dstu7564-256),
// the references digested as in ASiC manifests. It returns the URIs of the
// data objects the signatures sign, in the order they first appear, and the
// signers: "" is doc itself, an enveloped signature; any other URI is a
// detached file, taken from files by that URI or, percent-decoded, by name.
//
// Every reference must match its digest and every signature must verify, or
// VerifyXAdES fails with ErrInvalidSignature. The signer certificate is the
// one of ds:KeyInfo or certs whose digest the SigningCertificateV2 (or
// SigningCertificate) property names. A SignatureTimeStamp is verified over
// the canonical ds:SignatureValue and becomes Signer.TimeStamp; the
// CertificateValues and RevocationValues of B-LT, with certs, make
// Signer.Chain and Signer.OCSP, as for CAdES-X Long. Each ArchiveTimeStamp of
// B-LTA is verified over the input of ETSI EN 319 132-1, 5.5.2.2: the data of
// every reference, the canonical ds:SignedInfo, ds:SignatureValue and
// ds:KeyInfo, the unsigned signature properties before it, and the
// ds:Object elements other than the one of xades:QualifyingProperties; they
// become Signer.ArchiveTimeStamps. SigningTime is what the signer claims.
//
// Documents with a DOCTYPE, an Id that appears twice, or nesting deeper than
// 256 elements are rejected; transforms other than the enveloped signature
// and Exclusive XML Canonicalization are errors.ErrUnsupported.
func VerifyXAdES(doc []byte, files map[string][]byte, certs []*x509.Certificate) ([]string, []Signer, error) {
	root, ids, err := parseXML(doc)
	if err != nil {
		return nil, nil, err
	}
	signatures := root.signatures()
	if len(signatures) == 0 {
		return nil, nil, errors.New("pki: no XML signature in the document")
	}
	var signed []string
	var signers []Signer
	for i, sig := range signatures {
		uris, signer, err := verifyXMLSignature(root, ids, sig, files, certs)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: XML signature %d: %w", i, err)
		}
		for _, u := range uris {
			if !slices.Contains(signed, u) {
				signed = append(signed, u)
			}
		}
		signers = append(signers, signer)
	}
	return signed, signers, nil
}

func verifyXMLSignature(root *xmlElement, ids map[string]*xmlElement, sig *xmlElement, files map[string][]byte, certs []*x509.Certificate) ([]string, Signer, error) {
	var signer Signer
	signedInfo := sig.child(xmldsNamespace, "SignedInfo")
	if signedInfo == nil {
		return nil, signer, errors.New("no ds:SignedInfo")
	}
	if alg := signedInfo.child(xmldsNamespace, "CanonicalizationMethod").attr("Algorithm"); alg != excC14N {
		return nil, signer, fmt.Errorf("canonicalization %q: %w", alg, errors.ErrUnsupported)
	}
	digestAlg, err := signatureDigest(signedInfo)
	if err != nil {
		return nil, signer, err
	}

	var signedURIs []string
	var signedProps *xmlElement
	var referenced []byte // the first part of the input of an ArchiveTimeStamp
	for _, ref := range signedInfo.children(xmldsNamespace, "Reference") {
		uri := ref.attr("URI")
		target, err := referencedData(root, ids, sig, ref, files)
		if err != nil {
			return nil, signer, fmt.Errorf("reference %q: %w", uri, err)
		}
		referenced = append(referenced, target.data...)
		if err := checkDigest(ref.child(xmldsNamespace, "DigestMethod").attr("Algorithm"), ref.child(xmldsNamespace, "DigestValue").text(), target.data); err != nil {
			return nil, signer, fmt.Errorf("reference %q: %w", uri, err)
		}
		if ref.attr("Type") == signedPropertiesType {
			if signedProps != nil || target.element == nil || !target.element.is(nsXAdES, "SignedProperties") || !target.element.within(sig) {
				return nil, signer, errors.New("the SignedProperties reference is not to the signature's own one")
			}
			signedProps = target.element
			continue
		}
		signedURIs = append(signedURIs, uri)
	}
	if signedProps == nil {
		return nil, signer, errors.New("no reference to xades:SignedProperties")
	}
	if len(signedURIs) == 0 {
		return nil, signer, errors.New("no reference to signed data")
	}

	sigProps := signedProps.child(nsXAdES, "SignedSignatureProperties")
	cert, err := signingCertificate(sig, sigProps, certs)
	if err != nil {
		return nil, signer, err
	}
	signer.Certificate = cert
	if st := sigProps.child(nsXAdES, "SigningTime"); st != nil {
		if signer.SigningTime, err = time.Parse(time.RFC3339, strings.TrimSpace(st.text())); err != nil {
			return nil, signer, fmt.Errorf("xades:SigningTime: %w", err)
		}
	}

	key, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, signer, err
	}
	h, err := newHash(digestAlg, key.DKE)
	if err != nil {
		return nil, signer, err
	}
	h.Write(canonical(signedInfo, nil))
	sigValueElement := sig.child(xmldsNamespace, "SignatureValue")
	sigValue, err := base64Text(sigValueElement)
	if err != nil {
		return nil, signer, fmt.Errorf("ds:SignatureValue: %w", err)
	}
	if err := key.verify(h.Sum(nil), sigValue, true); err != nil {
		return nil, signer, err
	}

	unsigned := sig.find(nsXAdES, "UnsignedSignatureProperties")
	if unsigned == nil {
		return signedURIs, signer, nil
	}
	long, err := xmlLongTermData(unsigned)
	if err != nil {
		return nil, signer, err
	}
	pool := append(slices.Clone(certs), long.certs...)
	if ts := unsigned.child(nsXAdES, "SignatureTimeStamp"); ts != nil {
		if alg := ts.child(xmldsNamespace, "CanonicalizationMethod").attr("Algorithm"); alg != excC14N {
			return nil, signer, fmt.Errorf("time-stamp canonicalization %q: %w", alg, errors.ErrUnsupported)
		}
		token, err := base64Text(ts.child(nsXAdES, "EncapsulatedTimeStamp"))
		if err != nil {
			return nil, signer, fmt.Errorf("signature time-stamp: %w", err)
		}
		if signer.TimeStamp, _, err = verifyTimeStamp(token, canonical(sigValueElement, nil), pool); err != nil {
			return nil, signer, fmt.Errorf("signature time-stamp: %w", err)
		}
	}
	if signer.Chain, signer.OCSP, err = long.verify(cert, pool); err != nil {
		return nil, signer, fmt.Errorf("validation data: %w", err)
	}
	if signer.ArchiveTimeStamps, err = verifyArchiveTimeStamps(sig, unsigned, referenced, pool); err != nil {
		return nil, signer, err
	}
	return signedURIs, signer, nil
}

// verifyArchiveTimeStamps verifies the ArchiveTimeStamp properties among
// unsigned, the unsigned signature properties of sig, each over the input of
// ETSI EN 319 132-1, 5.5.2.2, that starts with referenced, the data of the
// references of sig.
func verifyArchiveTimeStamps(sig, unsigned *xmlElement, referenced []byte, pool []*x509.Certificate) ([]*TimeStamp, error) {
	signature, objects := archiveTimeStampParts(sig)
	input := slices.Concat(referenced, signature)
	var stamps []*TimeStamp
	for _, c := range unsigned.content {
		prop, ok := c.(*xmlElement)
		if !ok {
			continue
		}
		if !prop.is(nsXAdES141, "ArchiveTimeStamp") {
			input = append(input, canonical(prop, nil)...)
			continue
		}
		if alg := prop.child(xmldsNamespace, "CanonicalizationMethod").attr("Algorithm"); alg != excC14N {
			return nil, fmt.Errorf("archive time-stamp canonicalization %q: %w", alg, errors.ErrUnsupported)
		}
		token, err := base64Text(prop.child(nsXAdES, "EncapsulatedTimeStamp"))
		if err != nil {
			return nil, fmt.Errorf("archive time-stamp %d: %w", len(stamps), err)
		}
		ts, _, err := verifyTimeStamp(token, append(slices.Clone(input), objects...), pool)
		if err != nil {
			return nil, fmt.Errorf("archive time-stamp %d: %w", len(stamps), err)
		}
		stamps = append(stamps, ts)
		// A later ArchiveTimeStamp covers this one too.
		input = append(input, canonical(prop, nil)...)
	}
	return stamps, nil
}

// archiveTimeStampParts returns the parts of the input of an
// ArchiveTimeStamp of sig (ETSI EN 319 132-1, 5.5.2.2) on either side of the
// unsigned properties: the canonical ds:SignedInfo, ds:SignatureValue and
// ds:KeyInfo, and the ds:Object elements other than the qualifying
// properties.
func archiveTimeStampParts(sig *xmlElement) (signature, objects []byte) {
	for _, local := range []string{"SignedInfo", "SignatureValue", "KeyInfo"} {
		if e := sig.child(xmldsNamespace, local); e != nil {
			signature = append(signature, canonical(e, nil)...)
		}
	}
	for _, obj := range sig.children(xmldsNamespace, "Object") {
		if obj.child(nsXAdES, "QualifyingProperties") == nil {
			objects = append(objects, canonical(obj, nil)...)
		}
	}
	return signature, objects
}

// signatureDigest returns the hash of the ds:SignatureMethod of signedInfo.
func signatureDigest(signedInfo *xmlElement) (asn1.ObjectIdentifier, error) {
	switch alg := signedInfo.child(xmldsNamespace, "SignatureMethod").attr("Algorithm"); alg {
	case sigDSTU4145GOST34311:
		return oidGOST34311, nil
	case sigDSTU4145Kupyna256:
		return oidKupyna256, nil
	default:
		return nil, fmt.Errorf("signature method %q: %w", alg, errors.ErrUnsupported)
	}
}

// SignXAdES signs the XML document doc with key and returns it with an
// enveloped XAdES-B-B signature as IIT writes it, the last child of the
// document element: Exclusive XML Canonicalization, DSTU 4145 with
// Kupyna-256 or, when opts.GOST34311 is set, GOST 34.311 (the references
// digested as in ASiC manifests, ds:SignedInfo with the DKE of cert), the
// properties SigningTime (now) and SigningCertificateV2, and cert in
// ds:KeyInfo. opts.Detached is ignored. random, normally crypto/rand.Reader,
// provides the per-signature secret and the signature Id.
// AddXAdESSignatureTimeStamp turns the result into B-T.
//
// SignXAdES fails if VerifyXAdES would not read doc or key does not belong
// to cert.
func SignXAdES(random io.Reader, doc []byte, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	root, _, err := parseXML(doc)
	if err != nil {
		return nil, err
	}
	sig, err := signXML(random, []xmlReference{{enveloped: true, data: canonical(root, nil), mimeType: "text/xml"}}, key, cert, opts)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(doc[root.end:], []byte("</")) {
		return slices.Concat(doc[:root.end], sig, doc[root.end:]), nil
	}
	// <a/> becomes <a>signature</a>, the same canonical document
	name := root.local
	if root.prefix != "" {
		name = root.prefix + ":" + name
	}
	return slices.Concat(doc[:root.end-len("/>")], []byte(">"), sig, []byte("</"+name+">"), doc[root.end:]), nil
}

// SignXAdESDetached returns a detached XAdES-B-B signature of files: an XML
// document whose element is the ds:Signature, signed as by SignXAdES, with a
// reference to each file by its name as a relative URI. As IIT does, it
// gives a file named *.xml the MIME type text/xml and any other
// application/octet-stream. VerifyXAdES verifies it with the files by name.
func SignXAdESDetached(random io.Reader, files []ASiCFile, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	if len(files) == 0 {
		return nil, errors.New("pki: XAdES needs at least one file")
	}
	refs := make([]xmlReference, len(files))
	for i, f := range files {
		if f.Name == "" {
			return nil, errors.New("pki: XAdES file without a name")
		}
		refs[i] = xmlReference{uri: (&url.URL{Path: f.Name}).EscapedPath(), data: f.Data, mimeType: xadesMimeType(f.Name)}
	}
	sig, err := signXML(random, refs, key, cert, opts)
	if err != nil {
		return nil, err
	}
	return append([]byte(`<?xml version="1.0" encoding="utf-8" standalone="no" ?>`), sig...), nil
}

// xadesMimeType returns the MIME type IIT gives the file name: text/xml for
// *.xml, application/octet-stream for any other.
func xadesMimeType(name string) string {
	if strings.HasSuffix(strings.ToLower(name), ".xml") {
		return "text/xml"
	}
	return "application/octet-stream"
}

// AddXAdESSignatureTimeStamp turns the XAdES-B-B signatures of doc, as
// SignXAdES and SignXAdESDetached write them, into XAdES-B-T as IIT writes
// it: for every ds:Signature it asks tsa to stamp the canonical
// ds:SignatureValue, hashed with the hash of the signature method, and adds
// xades:UnsignedProperties with the token as SignatureTimeStamp.
// tsa.GOST34311 is not used.
//
// Every signature must have xades:QualifyingProperties with the prefixes ds
// and xades, as IIT writes them, and no unsigned properties yet.
func AddXAdESSignatureTimeStamp(ctx context.Context, doc []byte, tsa *TSAClient) ([]byte, error) {
	return addXAdESProperties(doc, func(_ *xmlElement, _ map[string]*xmlElement, sig, props *xmlElement) (int, string, error) {
		if props.child(nsXAdES, "UnsignedProperties") != nil {
			return 0, "", errors.New("already has unsigned properties")
		}
		alg, err := signatureDigest(sig.child(xmldsNamespace, "SignedInfo"))
		if err != nil {
			return 0, "", err
		}
		value := sig.child(xmldsNamespace, "SignatureValue")
		if value == nil {
			return 0, "", errors.New("no ds:SignatureValue")
		}
		token, _, err := tsa.timeStamp(ctx, alg, canonical(value, nil))
		if err != nil {
			return 0, "", err
		}
		var idBytes [16]byte
		_, _ = rand.Read(idBytes[:]) // never fails since Go 1.24
		id := hex.EncodeToString(idBytes[:])
		return props.end, `<xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp Id="TS-` + id +
			`"><ds:CanonicalizationMethod Algorithm="` + excC14N + `"/><xades:EncapsulatedTimeStamp Id="ETS-` + id + `">` +
			base64.StdEncoding.EncodeToString(token) +
			`</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties>`, nil
	})
}

// AddXAdESValidationData turns the XAdES-B-T signatures of doc into
// XAdES-B-LT as IIT writes it: for every ds:Signature it builds the path
// from the signer certificate to a self-signed root out of certs, asks ocsp
// about the signer certificate, and adds to the unsigned signature
// properties CertificateValues with the CA certificates of the path and the
// OCSP responder certificate when it is not one of them, then
// RevocationValues with the OCSP response. Unlike AddValidationData with
// "full CA data", it asks about the signer only, as the ЦЗО example does.
//
// Every signature must have a SignatureTimeStamp, added by
// AddXAdESSignatureTimeStamp, and no validation data yet, and the signer
// certificate must be good. With ocsp.URL empty, the certificate is checked
// at the OCSP server it names.
func AddXAdESValidationData(ctx context.Context, doc []byte, certs []*x509.Certificate, ocsp *OCSPClient) ([]byte, error) {
	return addXAdESProperties(doc, func(_ *xmlElement, _ map[string]*xmlElement, sig, props *xmlElement) (int, string, error) {
		unsigned := props.child(nsXAdES, "UnsignedProperties").child(nsXAdES, "UnsignedSignatureProperties")
		if unsigned.child(nsXAdES, "SignatureTimeStamp") == nil {
			return 0, "", errors.New("no signature time-stamp: add it with AddXAdESSignatureTimeStamp")
		}
		if unsigned.child(nsXAdES, "CertificateValues") != nil || unsigned.child(nsXAdES, "RevocationValues") != nil {
			return 0, "", errors.New("already has validation data")
		}
		signedProps := props.child(nsXAdES, "SignedProperties").child(nsXAdES, "SignedSignatureProperties")
		cert, err := signingCertificate(sig, signedProps, certs)
		if err != nil {
			return 0, "", err
		}
		path, err := certificatePath(cert, certs)
		if err != nil {
			return 0, "", err
		}
		if len(path) < 2 {
			return 0, "", errors.New("the signer certificate is self-signed")
		}
		resp, err := ocsp.Check(ctx, cert, path[1])
		if err != nil {
			return 0, "", err
		}
		if err := goodStatus(resp, cert); err != nil {
			return 0, "", err
		}
		values := path[1:]
		if !slices.ContainsFunc(path, resp.Certificate.Equal) {
			values = append(slices.Clone(values), resp.Certificate)
		}
		var b strings.Builder
		b.WriteString(`<xades:CertificateValues>`)
		for _, c := range values {
			b.WriteString(`<xades:EncapsulatedX509Certificate>` + base64.StdEncoding.EncodeToString(c.Raw) + `</xades:EncapsulatedX509Certificate>`)
		}
		b.WriteString(`</xades:CertificateValues><xades:RevocationValues><xades:OCSPValues><xades:EncapsulatedOCSPValue>` +
			base64.StdEncoding.EncodeToString(resp.Raw) + `</xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues>`)
		return unsigned.end, b.String(), nil
	})
}

// AddXAdESArchiveTimeStamp turns the XAdES-B-LT signatures of doc into
// XAdES-B-LTA as IIT writes it: for every ds:Signature it asks tsa to stamp
// the input of ETSI EN 319 132-1, 5.5.2.2 (the referenced data, the
// canonical ds:SignedInfo, ds:SignatureValue and ds:KeyInfo, the unsigned
// signature properties so far and the other ds:Object elements), hashed with
// the hash of the signature method, and appends the token as
// xadesv141:ArchiveTimeStamp. Called on B-LTA, it adds another
// ArchiveTimeStamp that covers the earlier ones. tsa.GOST34311 is not used.
//
// files holds the data of a detached signature by URI, as for VerifyXAdES;
// the digests of the references must match it. Every signature must have
// the validation data AddXAdESValidationData adds.
func AddXAdESArchiveTimeStamp(ctx context.Context, doc []byte, files map[string][]byte, tsa *TSAClient) ([]byte, error) {
	return addXAdESProperties(doc, func(root *xmlElement, ids map[string]*xmlElement, sig, props *xmlElement) (int, string, error) {
		unsigned := props.child(nsXAdES, "UnsignedProperties").child(nsXAdES, "UnsignedSignatureProperties")
		if unsigned.child(nsXAdES, "CertificateValues") == nil || unsigned.child(nsXAdES, "RevocationValues") == nil {
			return 0, "", errors.New("no validation data: add it with AddXAdESValidationData")
		}
		signedInfo := sig.child(xmldsNamespace, "SignedInfo")
		alg, err := signatureDigest(signedInfo)
		if err != nil {
			return 0, "", err
		}
		var input []byte
		for _, ref := range signedInfo.children(xmldsNamespace, "Reference") {
			uri := ref.attr("URI")
			target, err := referencedData(root, ids, sig, ref, files)
			if err != nil {
				return 0, "", fmt.Errorf("reference %q: %w", uri, err)
			}
			if err := checkDigest(ref.child(xmldsNamespace, "DigestMethod").attr("Algorithm"), ref.child(xmldsNamespace, "DigestValue").text(), target.data); err != nil {
				return 0, "", fmt.Errorf("reference %q: %w", uri, err)
			}
			input = append(input, target.data...)
		}
		signature, objects := archiveTimeStampParts(sig)
		input = append(input, signature...)
		for _, c := range unsigned.content {
			if prop, ok := c.(*xmlElement); ok {
				input = append(input, canonical(prop, nil)...)
			}
		}
		token, _, err := tsa.timeStamp(ctx, alg, append(input, objects...))
		if err != nil {
			return 0, "", err
		}
		return unsigned.end, `<xadesv141:ArchiveTimeStamp xmlns:xadesv141="` + nsXAdES141 + `"><ds:CanonicalizationMethod Algorithm="` + excC14N +
			`"/><xades:EncapsulatedTimeStamp>` + base64.StdEncoding.EncodeToString(token) +
			`</xades:EncapsulatedTimeStamp></xadesv141:ArchiveTimeStamp>`, nil
	})
}

// addXAdESProperties inserts into doc, for every ds:Signature with its
// xades:QualifyingProperties props, the markup that add returns at the
// offset it returns.
func addXAdESProperties(doc []byte, add func(root *xmlElement, ids map[string]*xmlElement, sig, props *xmlElement) (int, string, error)) ([]byte, error) {
	root, ids, err := parseXML(doc)
	if err != nil {
		return nil, err
	}
	signatures := root.signatures()
	if len(signatures) == 0 {
		return nil, errors.New("pki: no XML signature in the document")
	}
	type insertion struct {
		at     int
		markup string
	}
	var insertions []insertion
	for i, sig := range signatures {
		props := sig.child(xmldsNamespace, "Object").child(nsXAdES, "QualifyingProperties")
		if props == nil {
			return nil, fmt.Errorf("pki: XML signature %d: no xades:QualifyingProperties", i)
		}
		if sig.prefix != "ds" || props.prefix != "xades" || props.namespace("ds") != xmldsNamespace {
			return nil, fmt.Errorf("pki: XML signature %d: prefixes other than ds and xades: %w", i, errors.ErrUnsupported)
		}
		at, markup, err := add(root, ids, sig, props)
		if err != nil {
			return nil, fmt.Errorf("pki: XML signature %d: %w", i, err)
		}
		if !bytes.HasPrefix(doc[at:], []byte("</")) {
			return nil, fmt.Errorf("pki: XML signature %d: an empty element where the properties go", i)
		}
		insertions = append(insertions, insertion{at, markup})
	}
	slices.SortFunc(insertions, func(a, b insertion) int { return b.at - a.at }) // from the end, so the offsets stay
	out := doc
	for _, ins := range insertions {
		out = slices.Concat(out[:ins.at], []byte(ins.markup), out[ins.at:])
	}
	return out, nil
}

// An xmlReference is a data object signXML signs: the document the
// signature is in (data canonical) or a file.
type xmlReference struct {
	enveloped bool
	uri       string
	data      []byte
	mimeType  string
}

// signXML returns the ds:Signature of refs in the layout of IIT XAdES-B-B.
func signXML(random io.Reader, refs []xmlReference, key *dstu4145.PrivateKey, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	if !pub.belongsTo(key) {
		return nil, errors.New("pki: the private key does not belong to the certificate")
	}
	digestURI, method, hashAlg := digestKupyna256, sigDSTU4145Kupyna256, oidKupyna256
	if opts.GOST34311 {
		digestURI, method, hashAlg = digestGOST34311, sigDSTU4145GOST34311, oidGOST34311
	}
	digest := func(data []byte) string {
		sum, _ := asicDigest(digestURI, data) // never fails: the algorithm is one of the two above
		return base64.StdEncoding.EncodeToString(sum)
	}
	var idBytes [16]byte
	if _, err := io.ReadFull(random, idBytes[:]); err != nil {
		return nil, fmt.Errorf("pki: signature Id: %w", err)
	}
	id := "id-" + hex.EncodeToString(idBytes[:])
	digestMethod := `<ds:DigestMethod Algorithm="` + digestURI + `"/>`

	var props strings.Builder
	props.WriteString(`<xades:SignedProperties Id="xades-` + id + `"><xades:SignedSignatureProperties>`)
	props.WriteString(`<xades:SigningTime>` + time.Now().UTC().Format("2006-01-02T15:04:05Z") + `</xades:SigningTime>`)
	props.WriteString(`<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>` + digestMethod +
		`<ds:DigestValue>` + digest(cert.Raw) + `</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2>`)
	props.WriteString(`</xades:SignedSignatureProperties><xades:SignedDataObjectProperties>`)
	for i, r := range refs {
		fmt.Fprintf(&props, `<xades:DataObjectFormat ObjectReference="#%s-%d"><xades:MimeType>%s</xades:MimeType></xades:DataObjectFormat>`, id, i+1, r.mimeType)
	}
	props.WriteString(`</xades:SignedDataObjectProperties></xades:SignedProperties>`)
	propsCanonical, err := canonicalFragment(props.String())
	if err != nil {
		return nil, err
	}

	var info strings.Builder
	info.WriteString(`<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="` + excC14N + `"/><ds:SignatureMethod Algorithm="` + method + `"/>`)
	for i, r := range refs {
		fmt.Fprintf(&info, `<ds:Reference Id="%s-%d" Type="" URI="`, id, i+1)
		_ = xml.EscapeText(&info, []byte(r.uri)) // never fails: strings.Builder does not
		info.WriteString(`">`)
		if r.enveloped {
			info.WriteString(`<ds:Transforms><ds:Transform Algorithm="` + enveloped + `"/><ds:Transform Algorithm="` + excC14N + `"/></ds:Transforms>`)
		}
		info.WriteString(digestMethod + `<ds:DigestValue>` + digest(r.data) + `</ds:DigestValue></ds:Reference>`)
	}
	info.WriteString(`<ds:Reference Type="` + signedPropertiesType + `" URI="#xades-` + id + `"><ds:Transforms><ds:Transform Algorithm="` + excC14N +
		`"/></ds:Transforms>` + digestMethod + `<ds:DigestValue>` + digest(propsCanonical) + `</ds:DigestValue></ds:Reference></ds:SignedInfo>`)
	infoCanonical, err := canonicalFragment(info.String())
	if err != nil {
		return nil, err
	}

	h, err := newHash(hashAlg, pub.DKE)
	if err != nil {
		return nil, err
	}
	h.Write(infoCanonical)
	r, s, err := dstu4145.Sign(random, key, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}

	var sig strings.Builder
	sig.WriteString(`<ds:Signature xmlns:ds="` + xmldsNamespace + `" Id="` + id + `">` + info.String())
	sig.WriteString(`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(dstu4145.MarshalSignature(key.Public().Curve(), r, s)) + `</ds:SignatureValue>`)
	sig.WriteString(`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)
	sig.WriteString(`<ds:Object><xades:QualifyingProperties xmlns:xades="` + nsXAdES + `" Target="#` + id + `">` + props.String())
	sig.WriteString(`</xades:QualifyingProperties></ds:Object></ds:Signature>`)
	return []byte(sig.String()), nil
}

// canonicalFragment returns the Exclusive XML Canonicalization of the
// element written in fragment with the prefixes ds and xades undeclared.
// Exclusive canonicalization renders the declarations an element uses
// wherever its ancestors make them, so this is its form in the signature.
func canonicalFragment(fragment string) ([]byte, error) {
	root, _, err := parseXML([]byte(`<w xmlns:ds="` + xmldsNamespace + `" xmlns:xades="` + nsXAdES + `">` + fragment + `</w>`))
	if err != nil {
		return nil, err
	}
	return canonical(root.content[0].(*xmlElement), nil), nil
}

// xmlTarget is what a ds:Reference points to: the octets to digest and, for
// a reference within the document, the element.
type xmlTarget struct {
	data    []byte
	element *xmlElement
}

// referencedData returns the data of ref of the signature sig: the
// canonical document or element of a same-document URI after its
// transforms, or the file of any other URI.
func referencedData(root *xmlElement, ids map[string]*xmlElement, sig, ref *xmlElement, files map[string][]byte) (xmlTarget, error) {
	uri := ref.attr("URI")
	var transforms []string
	for _, t := range ref.child(xmldsNamespace, "Transforms").children(xmldsNamespace, "Transform") {
		transforms = append(transforms, t.attr("Algorithm"))
	}
	if uri != "" && !strings.HasPrefix(uri, "#") {
		if len(transforms) > 0 {
			return xmlTarget{}, fmt.Errorf("transforms of a file: %w", errors.ErrUnsupported)
		}
		data, ok := files[uri]
		if !ok {
			if name, err := url.PathUnescape(uri); err == nil {
				data, ok = files[name]
			}
		}
		if !ok {
			return xmlTarget{}, errors.New("no such file")
		}
		return xmlTarget{data: data}, nil
	}

	element := root
	if uri != "" {
		if element = ids[uri[1:]]; element == nil {
			return xmlTarget{}, errors.New("no element with that Id")
		}
	}
	var exclude *xmlElement
	switch {
	case slices.Equal(transforms, []string{enveloped, excC14N}):
		exclude = sig
	case slices.Equal(transforms, []string{excC14N}):
	default:
		return xmlTarget{}, fmt.Errorf("transforms %q: %w", transforms, errors.ErrUnsupported)
	}
	return xmlTarget{data: canonical(element, exclude), element: element}, nil
}

// checkDigest compares the digest of data by the algorithm URI alg with
// value, base64.
func checkDigest(alg, value string, data []byte) error {
	digest, err := asicDigest(alg, data)
	if err != nil {
		return err
	}
	want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || !bytes.Equal(digest, want) {
		return fmt.Errorf("digest: %w", ErrInvalidSignature)
	}
	return nil
}

// signingCertificate returns the certificate of ds:KeyInfo of sig or of certs
// that the SigningCertificateV2 or SigningCertificate property of props
// names by digest.
func signingCertificate(sig, props *xmlElement, certs []*x509.Certificate) (*x509.Certificate, error) {
	ref := props.child(nsXAdES, "SigningCertificateV2")
	if ref == nil {
		ref = props.child(nsXAdES, "SigningCertificate")
	}
	if ref == nil {
		return nil, errors.New("no xades:SigningCertificateV2")
	}
	var candidates []*x509.Certificate
	for _, e := range sig.child(xmldsNamespace, "KeyInfo").child(xmldsNamespace, "X509Data").children(xmldsNamespace, "X509Certificate") {
		der, err := base64Text(e)
		if err != nil {
			return nil, fmt.Errorf("ds:X509Certificate: %w", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("ds:X509Certificate: %w", err)
		}
		candidates = append(candidates, c)
	}
	candidates = append(candidates, certs...)
	for _, certRef := range ref.children(nsXAdES, "Cert") {
		digest := certRef.child(nsXAdES, "CertDigest")
		alg := digest.child(xmldsNamespace, "DigestMethod").attr("Algorithm")
		value := digest.child(xmldsNamespace, "DigestValue").text()
		for _, c := range candidates {
			if checkDigest(alg, value, c.Raw) == nil {
				return c, nil
			}
		}
	}
	return nil, errors.New("no certificate matches xades:SigningCertificateV2")
}

// xmlLongTermData reads the CertificateValues and RevocationValues of
// XAdES-B-LT among the unsigned signature properties.
func xmlLongTermData(unsigned *xmlElement) (longTermData, error) {
	var d longTermData
	for _, e := range unsigned.child(nsXAdES, "CertificateValues").children(nsXAdES, "EncapsulatedX509Certificate") {
		der, err := base64Text(e)
		if err != nil {
			return d, fmt.Errorf("xades:CertificateValues: %w", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return d, fmt.Errorf("xades:CertificateValues: %w", err)
		}
		d.rawCerts = append(d.rawCerts, der)
		d.certs = append(d.certs, c)
	}
	ocsp := unsigned.child(nsXAdES, "RevocationValues").child(nsXAdES, "OCSPValues")
	for _, e := range ocsp.children(nsXAdES, "EncapsulatedOCSPValue") {
		der, err := base64Text(e)
		if err != nil {
			return d, fmt.Errorf("xades:OCSPValues: %w", err)
		}
		basic, err := basicOCSPResponse(der)
		if err != nil {
			return d, fmt.Errorf("xades:OCSPValues: %w", err)
		}
		d.basics = append(d.basics, basic)
	}
	return d, nil
}

// basicOCSPResponse returns the BasicOCSPResponse of the OCSPResponse der.
func basicOCSPResponse(der []byte) ([]byte, error) {
	var resp struct {
		Status asn1.Enumerated
		Bytes  struct {
			Type     asn1.ObjectIdentifier
			Response []byte
		} `asn1:"explicit,tag:0"`
	}
	if err := unmarshal(der, &resp); err != nil {
		return nil, err
	}
	if !resp.Bytes.Type.Equal(oidOCSPBasic) {
		return nil, fmt.Errorf("OCSP response of type %v", resp.Bytes.Type)
	}
	return resp.Bytes.Response, nil
}

// base64Text decodes the base64 text of e, which may hold white space.
func base64Text(e *xmlElement) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(e.text()), ""))
}

// An xmlElement is an element of a parsed document. Names keep their
// prefixes; namespace declarations are among the attributes.
type xmlElement struct {
	prefix, local string
	attrs         []xml.Attr // Name.Space is the prefix, "xmlns" for a declaration
	content       []any      // *xmlElement or string
	parent        *xmlElement
	// start and inner are the offsets in the document of the start tag and
	// just past it; end is the offset of the end tag, or inner for an
	// empty-element tag <a/>.
	start, inner, end int
}

// parseXML parses doc into its document element and the elements by Id.
// Comments and processing instructions are dropped, as canonicalization
// without comments drops them; text outside the document element is too.
func parseXML(doc []byte) (*xmlElement, map[string]*xmlElement, error) {
	d := xml.NewDecoder(bytes.NewReader(doc))
	var root, cur *xmlElement
	ids := make(map[string]*xmlElement)
	depth := 0
	for {
		offset := d.InputOffset()
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("pki: XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if cur == nil && root != nil {
				return nil, nil, errors.New("pki: XML: two document elements")
			}
			if depth++; depth > maxXMLDepth {
				return nil, nil, errors.New("pki: XML nested too deep")
			}
			attrs, err := normalizedAttrs(doc[offset:d.InputOffset()], t.Attr)
			if err != nil {
				return nil, nil, err
			}
			e := &xmlElement{prefix: t.Name.Space, local: t.Name.Local, attrs: attrs, parent: cur, start: int(offset), inner: int(d.InputOffset())}
			for _, a := range e.attrs {
				if a.Name.Space == "" && (a.Name.Local == "Id" || a.Name.Local == "ID" || a.Name.Local == "id") {
					if _, dup := ids[a.Value]; dup {
						return nil, nil, fmt.Errorf("pki: XML Id %q appears twice", a.Value)
					}
					ids[a.Value] = e
				}
			}
			if cur == nil {
				root = e
			} else {
				cur.content = append(cur.content, e)
			}
			cur = e
		case xml.EndElement:
			if cur == nil || t.Name.Space != cur.prefix || t.Name.Local != cur.local {
				return nil, nil, fmt.Errorf("pki: XML: unexpected </%s>", t.Name.Local)
			}
			cur.end = int(offset)
			cur, depth = cur.parent, depth-1
		case xml.CharData:
			if cur != nil {
				cur.content = append(cur.content, string(t))
			}
		case xml.Directive:
			return nil, nil, errors.New("pki: XML with a DOCTYPE or other directive")
		}
	}
	if root == nil || cur != nil {
		return nil, nil, errors.New("pki: XML: no complete document element")
	}
	return root, ids, nil
}

// normalizedAttrs returns the attributes of the start tag tag, which
// encoding/xml decoded as attrs, with the white space written in their
// values replaced by spaces, as XML 1.0 (3.3.3) normalizes attribute values
// and encoding/xml does not; white space written as a character reference
// stays.
func normalizedAttrs(tag []byte, attrs []xml.Attr) ([]xml.Attr, error) {
	if !bytes.ContainsAny(tag, "\t\n\r") {
		return slices.Clone(attrs), nil
	}
	b := bytes.ReplaceAll(tag, []byte("\r\n"), []byte("\n")) // a line end is one character (XML 1.0, 2.11)
	changed := false
	var quote byte
	for i, c := range b {
		switch {
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case c == quote:
			quote = 0
		case quote != 0 && (c == '\t' || c == '\n' || c == '\r'):
			b[i], changed = ' ', true
		}
	}
	if !changed {
		return slices.Clone(attrs), nil
	}
	tok, err := xml.NewDecoder(bytes.NewReader(b)).RawToken()
	start, ok := tok.(xml.StartElement)
	if err != nil || !ok {
		return nil, fmt.Errorf("pki: XML: start tag %q", tag)
	}
	return start.Attr, nil
}

// namespace returns the URI that prefix is bound to at e, "" for the
// default namespace when none is declared.
func (e *xmlElement) namespace(prefix string) string {
	if prefix == "xml" {
		return nsXML
	}
	for ; e != nil; e = e.parent {
		for _, a := range e.attrs {
			if prefix == "" && a.Name.Space == "" && a.Name.Local == "xmlns" || prefix != "" && a.Name.Space == "xmlns" && a.Name.Local == prefix {
				return a.Value
			}
		}
	}
	return ""
}

func (e *xmlElement) is(ns, local string) bool {
	return e != nil && e.local == local && e.namespace(e.prefix) == ns
}

// child returns the first child element of e named ns and local, nil when
// there is none or e is nil.
func (e *xmlElement) child(ns, local string) *xmlElement {
	if c := e.children(ns, local); len(c) > 0 {
		return c[0]
	}
	return nil
}

func (e *xmlElement) children(ns, local string) []*xmlElement {
	if e == nil {
		return nil
	}
	var out []*xmlElement
	for _, c := range e.content {
		if c, ok := c.(*xmlElement); ok && c.is(ns, local) {
			out = append(out, c)
		}
	}
	return out
}

// find returns the first element under e, depth first, named ns and local.
func (e *xmlElement) find(ns, local string) *xmlElement {
	var found *xmlElement
	e.walk(func(c *xmlElement) {
		if found == nil && c.is(ns, local) {
			found = c
		}
	})
	return found
}

// signatures returns the ds:Signature elements under e, in document order.
func (e *xmlElement) signatures() []*xmlElement {
	var out []*xmlElement
	e.walk(func(c *xmlElement) {
		if c.is(xmldsNamespace, "Signature") {
			out = append(out, c)
		}
	})
	return out
}

// walk calls f for e and every element under it, in document order.
func (e *xmlElement) walk(f func(*xmlElement)) {
	f(e)
	for _, c := range e.content {
		if c, ok := c.(*xmlElement); ok {
			c.walk(f)
		}
	}
}

// within reports whether e is a or under it.
func (e *xmlElement) within(a *xmlElement) bool {
	for ; e != nil; e = e.parent {
		if e == a {
			return true
		}
	}
	return false
}

// attr returns the value of the attribute local without a prefix, "" when e
// is nil or has none.
func (e *xmlElement) attr(local string) string {
	if e == nil {
		return ""
	}
	for _, a := range e.attrs {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

// text returns the text directly inside e.
func (e *xmlElement) text() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range e.content {
		if s, ok := c.(string); ok {
			b.WriteString(s)
		}
	}
	return b.String()
}

// canonical returns e and its content, without the element exclude and its
// content, in Exclusive XML Canonicalization 1.0 without comments and
// without an InclusiveNamespaces prefix list.
func canonical(e, exclude *xmlElement) []byte {
	var b bytes.Buffer
	writeCanonical(&b, e, exclude, map[string]string{})
	return b.Bytes()
}

// writeCanonical writes e; rendered holds the namespace declarations in
// effect in the output at e's parent.
func writeCanonical(b *bytes.Buffer, e, exclude *xmlElement, rendered map[string]string) {
	if e == exclude {
		return
	}
	// Exclusive canonicalization declares the namespaces the element and
	// its attributes use, where the output does not already have them.
	used := []string{e.prefix}
	var attrs []xml.Attr
	for _, a := range e.attrs {
		if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
			continue
		}
		attrs = append(attrs, a)
		if a.Name.Space != "" && a.Name.Space != "xml" {
			used = append(used, a.Name.Space)
		}
	}
	var decls []string
	for _, p := range used {
		uri := e.namespace(p)
		if rendered[p] == uri || slices.Contains(decls, p) {
			continue
		}
		if len(decls) == 0 {
			rendered = maps.Clone(rendered)
		}
		rendered[p] = uri
		decls = append(decls, p)
	}
	slices.Sort(decls) // "" sorts first, as the default declaration must

	b.WriteByte('<')
	writeQName(b, e.prefix, e.local)
	for _, p := range decls {
		if p == "" {
			b.WriteString(` xmlns="`)
		} else {
			b.WriteString(" xmlns:" + p + `="`)
		}
		escapeCanonical(b, rendered[p], true)
		b.WriteByte('"')
	}
	slices.SortFunc(attrs, func(x, y xml.Attr) int {
		nx, ny := "", ""
		if x.Name.Space != "" {
			nx = e.namespace(x.Name.Space)
		}
		if y.Name.Space != "" {
			ny = e.namespace(y.Name.Space)
		}
		if c := strings.Compare(nx, ny); c != 0 {
			return c
		}
		return strings.Compare(x.Name.Local, y.Name.Local)
	})
	for _, a := range attrs {
		b.WriteByte(' ')
		writeQName(b, a.Name.Space, a.Name.Local)
		b.WriteString(`="`)
		escapeCanonical(b, a.Value, true)
		b.WriteByte('"')
	}
	b.WriteByte('>')
	for _, c := range e.content {
		switch c := c.(type) {
		case string:
			escapeCanonical(b, c, false)
		case *xmlElement:
			writeCanonical(b, c, exclude, rendered)
		}
	}
	b.WriteString("</")
	writeQName(b, e.prefix, e.local)
	b.WriteByte('>')
}

func writeQName(b *bytes.Buffer, prefix, local string) {
	if prefix != "" {
		b.WriteString(prefix)
		b.WriteByte(':')
	}
	b.WriteString(local)
}

// escapeCanonical writes s escaped as canonical XML escapes text or, with
// attr, an attribute value.
func escapeCanonical(b *bytes.Buffer, s string, attr bool) {
	for _, r := range s {
		switch {
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>' && !attr:
			b.WriteString("&gt;")
		case r == '"' && attr:
			b.WriteString("&quot;")
		case r == '\t' && attr:
			b.WriteString("&#x9;")
		case r == '\n' && attr:
			b.WriteString("&#xA;")
		case r == '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
}
