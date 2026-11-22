// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package cms parses, verifies and builds the subset of PKCS#7 / CMS
// SignedData (RFC 2315, RFC 5652) used by Authenticode signatures and
// RFC 3161 timestamp tokens.
//
// Parsing accepts DER only (definite, minimal lengths) and is bounded: the
// number of certificates, signers, attributes and attribute values is
// limited, and every failure is reported as an error. Only SHA-256, SHA-384
// and SHA-512 digests are recognised; anything else, SHA-1 included, is
// rejected.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Object identifiers.
var (
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// Parsing limits.
const (
	maxCertificates = 32
	maxSigners      = 8
	maxAttributes   = 32
	maxValues       = 16
)

var hashes = []struct {
	h   crypto.Hash
	oid asn1.ObjectIdentifier
}{
	{crypto.SHA256, oidSHA256},
	{crypto.SHA384, oidSHA384},
	{crypto.SHA512, oidSHA512},
}

// HashForOID maps a digest algorithm OID to a hash. Only SHA-256, SHA-384
// and SHA-512 are known.
func HashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for _, e := range hashes {
		if e.oid.Equal(oid) {
			return e.h, nil
		}
	}
	return 0, fmt.Errorf("cms: digest algorithm %v not accepted", oid)
}

// OIDForHash maps a hash to its digest algorithm OID.
func OIDForHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	for _, e := range hashes {
		if e.h == h {
			return e.oid, nil
		}
	}
	return nil, fmt.Errorf("cms: hash %v not supported", h)
}

// Attribute is a CMS attribute. Values holds the DER of each value.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values [][]byte
}

// Count returns how many attributes in attrs have type oid.
func Count(attrs []Attribute, oid asn1.ObjectIdentifier) int {
	n := 0
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			n++
		}
	}
	return n
}

// Single returns the value of the attribute of type oid, which must appear
// exactly once with exactly one value.
func Single(attrs []Attribute, oid asn1.ObjectIdentifier) ([]byte, error) {
	if Count(attrs, oid) != 1 {
		return nil, fmt.Errorf("cms: attribute %v must appear exactly once", oid)
	}
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			if len(a.Values) != 1 {
				return nil, fmt.Errorf("cms: attribute %v must have exactly one value", oid)
			}
			return a.Values[0], nil
		}
	}
	panic("unreachable")
}

// SignerInfo is a parsed CMS SignerInfo.
type SignerInfo struct {
	// Signer identifier: issuer and serial number, or a subject key
	// identifier.
	Issuer       []byte
	SerialNumber *big.Int
	SubjectKeyID []byte

	Hash               crypto.Hash
	SignatureAlgorithm asn1.ObjectIdentifier
	Signature          []byte

	// signedAttrs is the DER of the signed attributes with the SET tag the
	// signature is computed over; nil when absent.
	signedAttrs   []byte
	SignedAttrs   []Attribute
	UnsignedAttrs []Attribute
}

// SignedData is a parsed SignedData from a ContentInfo.
type SignedData struct {
	ContentType asn1.ObjectIdentifier
	// Content is the DER of the encapsulated content element; nil for
	// detached content.
	Content []byte
	// ContentOctets are the contents octets of that element, which the
	// message digest attribute covers: for an OCTET STRING its value, for
	// Authenticode's SpcIndirectDataContent the SEQUENCE body.
	ContentOctets []byte
	Certificates  []*x509.Certificate
	Signers       []*SignerInfo
}

var (
	tagCtx0      = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagImplicit1 = cbasn1.Tag(1).Constructed().ContextSpecific()
	tagSKI       = cbasn1.Tag(0).ContextSpecific()
)

func errMalformed(what string) error { return fmt.Errorf("cms: malformed %s", what) }

// Parse parses a DER ContentInfo holding SignedData.
func Parse(der []byte) (*SignedData, error) {
	in := cryptobyte.String(der)
	var ci, wrapped, sd cryptobyte.String
	var ct asn1.ObjectIdentifier
	if !in.ReadASN1(&ci, cbasn1.SEQUENCE) || !in.Empty() ||
		!ci.ReadASN1ObjectIdentifier(&ct) ||
		!ci.ReadASN1(&wrapped, tagCtx0) || !ci.Empty() ||
		!wrapped.ReadASN1(&sd, cbasn1.SEQUENCE) || !wrapped.Empty() {
		return nil, errMalformed("ContentInfo")
	}
	if !ct.Equal(OIDSignedData) {
		return nil, fmt.Errorf("cms: content type %v is not signedData", ct)
	}

	var version int
	var digestAlgs, eci cryptobyte.String
	if !sd.ReadASN1Integer(&version) || version < 1 || version > 5 ||
		!sd.ReadASN1(&digestAlgs, cbasn1.SET) ||
		!sd.ReadASN1(&eci, cbasn1.SEQUENCE) {
		return nil, errMalformed("SignedData")
	}
	out := &SignedData{}
	if !eci.ReadASN1ObjectIdentifier(&out.ContentType) {
		return nil, errMalformed("encapsulated content")
	}
	var econtent cryptobyte.String
	var present bool
	if !eci.ReadOptionalASN1(&econtent, &present, tagCtx0) || !eci.Empty() {
		return nil, errMalformed("encapsulated content")
	}
	if present {
		var elem cryptobyte.String
		if !econtent.ReadAnyASN1Element(&elem, nil) || !econtent.Empty() {
			return nil, errMalformed("encapsulated content")
		}
		var octets cryptobyte.String
		var tag cbasn1.Tag
		if e := elem; !e.ReadAnyASN1(&octets, &tag) {
			return nil, errMalformed("encapsulated content")
		}
		if tag == cbasn1.OCTET_STRING.Constructed() {
			return nil, errors.New("cms: constructed OCTET STRING content")
		}
		out.Content, out.ContentOctets = elem, octets
	}

	var certs cryptobyte.String
	if !sd.ReadOptionalASN1(&certs, &present, tagCtx0) {
		return nil, errMalformed("certificates")
	}
	for !certs.Empty() {
		var c cryptobyte.String
		if !certs.ReadASN1Element(&c, cbasn1.SEQUENCE) {
			return nil, errors.New("cms: unsupported certificate choice")
		}
		if len(out.Certificates) == maxCertificates {
			return nil, errors.New("cms: too many certificates")
		}
		cert, err := x509.ParseCertificate(c)
		if err != nil {
			return nil, fmt.Errorf("cms: certificate: %w", err)
		}
		out.Certificates = append(out.Certificates, cert)
	}
	if !sd.SkipOptionalASN1(tagImplicit1) { // CRLs are not used
		return nil, errMalformed("crls")
	}
	var signers cryptobyte.String
	if !sd.ReadASN1(&signers, cbasn1.SET) || !sd.Empty() {
		return nil, errMalformed("SignedData")
	}
	for !signers.Empty() {
		var s cryptobyte.String
		if !signers.ReadASN1(&s, cbasn1.SEQUENCE) {
			return nil, errMalformed("SignerInfo")
		}
		if len(out.Signers) == maxSigners {
			return nil, errors.New("cms: too many signers")
		}
		si, err := parseSignerInfo(s)
		if err != nil {
			return nil, err
		}
		out.Signers = append(out.Signers, si)
	}
	return out, nil
}

func parseSignerInfo(s cryptobyte.String) (*SignerInfo, error) {
	si := &SignerInfo{}
	var version int
	if !s.ReadASN1Integer(&version) {
		return nil, errMalformed("SignerInfo")
	}
	switch {
	case s.PeekASN1Tag(cbasn1.SEQUENCE):
		var ias, issuer cryptobyte.String
		si.SerialNumber = new(big.Int)
		if !s.ReadASN1(&ias, cbasn1.SEQUENCE) ||
			!ias.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
			!ias.ReadASN1Integer(si.SerialNumber) || !ias.Empty() {
			return nil, errMalformed("issuerAndSerialNumber")
		}
		si.Issuer = issuer
	case s.PeekASN1Tag(tagSKI):
		var ski cryptobyte.String
		if !s.ReadASN1(&ski, tagSKI) || len(ski) == 0 {
			return nil, errMalformed("subjectKeyIdentifier")
		}
		si.SubjectKeyID = ski
	default:
		return nil, errors.New("cms: unsupported signer identifier")
	}
	digestAlg, err := readAlgorithm(&s)
	if err != nil {
		return nil, err
	}
	if si.Hash, err = HashForOID(digestAlg); err != nil {
		return nil, err
	}
	if s.PeekASN1Tag(tagCtx0) {
		var raw, body cryptobyte.String
		if !s.ReadASN1Element(&raw, tagCtx0) {
			return nil, errMalformed("signed attributes")
		}
		if r := raw; !r.ReadASN1(&body, tagCtx0) {
			return nil, errMalformed("signed attributes")
		}
		if si.SignedAttrs, err = parseAttributes(body); err != nil {
			return nil, fmt.Errorf("cms: signed attributes: %w", err)
		}
		// The signature covers the attributes encoded as a SET.
		si.signedAttrs = append([]byte{byte(cbasn1.SET)}, raw[1:]...)
	}
	if si.SignatureAlgorithm, err = readAlgorithm(&s); err != nil {
		return nil, err
	}
	var sig cryptobyte.String
	if !s.ReadASN1(&sig, cbasn1.OCTET_STRING) || len(sig) == 0 {
		return nil, errMalformed("signature")
	}
	si.Signature = sig
	var unsigned cryptobyte.String
	var present bool
	if !s.ReadOptionalASN1(&unsigned, &present, tagImplicit1) || !s.Empty() {
		return nil, errMalformed("SignerInfo")
	}
	if present {
		if si.UnsignedAttrs, err = parseAttributes(unsigned); err != nil {
			return nil, fmt.Errorf("cms: unsigned attributes: %w", err)
		}
	}
	return si, nil
}

// readAlgorithm reads an AlgorithmIdentifier whose parameters are absent or
// NULL.
func readAlgorithm(s *cryptobyte.String) (asn1.ObjectIdentifier, error) {
	var seq cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&oid) {
		return nil, errMalformed("AlgorithmIdentifier")
	}
	if !seq.Empty() {
		var null cryptobyte.String
		if !seq.ReadASN1(&null, cbasn1.NULL) || len(null) != 0 || !seq.Empty() {
			return nil, fmt.Errorf("cms: algorithm %v: unsupported parameters", oid)
		}
	}
	return oid, nil
}

func parseAttributes(set cryptobyte.String) ([]Attribute, error) {
	var out []Attribute
	for !set.Empty() {
		if len(out) == maxAttributes {
			return nil, errors.New("too many attributes")
		}
		var a, vals cryptobyte.String
		var attr Attribute
		if !set.ReadASN1(&a, cbasn1.SEQUENCE) ||
			!a.ReadASN1ObjectIdentifier(&attr.Type) ||
			!a.ReadASN1(&vals, cbasn1.SET) || !a.Empty() {
			return nil, errors.New("malformed attribute")
		}
		for !vals.Empty() {
			if len(attr.Values) == maxValues {
				return nil, errors.New("too many attribute values")
			}
			var v cryptobyte.String
			if !vals.ReadAnyASN1Element(&v, nil) {
				return nil, errors.New("malformed attribute value")
			}
			attr.Values = append(attr.Values, v)
		}
		if len(attr.Values) == 0 {
			return nil, errors.New("attribute without values")
		}
		out = append(out, attr)
	}
	return out, nil
}

// FindCertificate returns the embedded certificate identified by si.
func (sd *SignedData) FindCertificate(si *SignerInfo) *x509.Certificate {
	for _, c := range sd.Certificates {
		if si.SerialNumber != nil {
			if c.SerialNumber.Cmp(si.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, si.Issuer) {
				return c
			}
		} else if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, si.SubjectKeyID) {
			return c
		}
	}
	return nil
}

// Verify checks that si has exactly one content-type attribute equal to
// sd's content type and one message-digest attribute matching sd's content,
// and that its signature over the signed attributes is valid. It does not
// verify the certificate chain. It returns the signer certificate.
func (sd *SignedData) Verify(si *SignerInfo) (*x509.Certificate, error) {
	cert := sd.FindCertificate(si)
	if cert == nil {
		return nil, errors.New("cms: signer certificate not embedded")
	}
	if si.signedAttrs == nil {
		return nil, errors.New("cms: signer has no signed attributes")
	}
	if sd.Content == nil {
		return nil, errors.New("cms: no encapsulated content")
	}
	v, err := Single(si.SignedAttrs, OIDContentType)
	if err != nil {
		return nil, err
	}
	var ct asn1.ObjectIdentifier
	if s := cryptobyte.String(v); !s.ReadASN1ObjectIdentifier(&ct) || !s.Empty() || !ct.Equal(sd.ContentType) {
		return nil, errors.New("cms: content-type attribute does not match the content")
	}
	if v, err = Single(si.SignedAttrs, OIDMessageDigest); err != nil {
		return nil, err
	}
	var md cryptobyte.String
	if s := cryptobyte.String(v); !s.ReadASN1(&md, cbasn1.OCTET_STRING) || !s.Empty() {
		return nil, errMalformed("message-digest attribute")
	}
	if !bytes.Equal(md, Digest(si.Hash, sd.ContentOctets)) {
		return nil, errors.New("cms: message digest does not match the content")
	}
	if err := verifySignature(cert.PublicKey, si.SignatureAlgorithm, si.Hash, Digest(si.Hash, si.signedAttrs), si.Signature); err != nil {
		return nil, err
	}
	return cert, nil
}

// Digest returns the h digest of data.
func Digest(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

func verifySignature(pub any, alg asn1.ObjectIdentifier, h crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if !algMatches(alg, h, oidRSAEncryption, oidSHA256WithRSA, oidSHA384WithRSA, oidSHA512WithRSA) {
			return fmt.Errorf("cms: signature algorithm %v does not match an RSA key and %v", alg, h)
		}
		if rsa.VerifyPKCS1v15(k, h, digest, sig) != nil {
			return errors.New("cms: invalid signature")
		}
	case *ecdsa.PublicKey:
		if !algMatches(alg, h, oidECPublicKey, oidECDSAWithSHA256, oidECDSAWithSHA384, oidECDSAWithSHA512) {
			return fmt.Errorf("cms: signature algorithm %v does not match an ECDSA key and %v", alg, h)
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("cms: invalid signature")
		}
	default:
		return fmt.Errorf("cms: unsupported public key type %T", pub)
	}
	return nil
}

// algMatches accepts the key algorithm OID alone, or the combined OID of
// hash h.
func algMatches(alg asn1.ObjectIdentifier, h crypto.Hash, key, with256, with384, with512 asn1.ObjectIdentifier) bool {
	switch {
	case alg.Equal(key):
		return true
	case alg.Equal(with256):
		return h == crypto.SHA256
	case alg.Equal(with384):
		return h == crypto.SHA384
	case alg.Equal(with512):
		return h == crypto.SHA512
	}
	return false
}

// SignOptions describes a SignedData with a single signer to build.
type SignOptions struct {
	ContentType asn1.ObjectIdentifier
	// Content is the DER of the encapsulated content element.
	Content []byte
	Key     crypto.Signer
	Cert    *x509.Certificate
	// Extra certificates embedded after Cert.
	Extra []*x509.Certificate
	Hash  crypto.Hash
	// SignedAttrs are added to content-type and message-digest.
	SignedAttrs []Attribute
}

// Signed is the result of Sign: the parts needed to add unsigned
// attributes later.
type Signed struct {
	opts       *SignOptions
	signedBody []byte // contents of the signed attributes SET
	Signature  []byte
}

// Sign signs the content. Encode produces the ContentInfo.
func Sign(opts *SignOptions) (*Signed, error) {
	if _, err := OIDForHash(opts.Hash); err != nil {
		return nil, err
	}
	var octets cryptobyte.String
	if c := cryptobyte.String(opts.Content); !c.ReadAnyASN1(&octets, nil) || !c.Empty() {
		return nil, errMalformed("content")
	}
	attrs := append([]Attribute{
		{Type: OIDContentType, Values: [][]byte{mustBuild(func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(opts.ContentType) })}},
		{Type: OIDMessageDigest, Values: [][]byte{mustBuild(func(b *cryptobyte.Builder) { b.AddASN1OctetString(Digest(opts.Hash, octets)) })}},
	}, opts.SignedAttrs...)
	body := mustBuild(func(b *cryptobyte.Builder) { addSortedAttributes(b, attrs) })
	signed := mustBuild(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(body) })
	})
	sig, err := opts.Key.Sign(rand.Reader, Digest(opts.Hash, signed), opts.Hash)
	if err != nil {
		return nil, fmt.Errorf("cms: sign: %w", err)
	}
	return &Signed{opts: opts, signedBody: body, Signature: sig}, nil
}

// Encode returns the DER ContentInfo with the given unsigned attributes.
func (s *Signed) Encode(unsigned []Attribute) ([]byte, error) {
	o := s.opts
	hashOID, _ := OIDForHash(o.Hash)
	var sigAlg asn1.ObjectIdentifier
	switch o.Key.Public().(type) {
	case *rsa.PublicKey:
		sigAlg = oidRSAEncryption
	case *ecdsa.PublicKey:
		sigAlg = map[crypto.Hash]asn1.ObjectIdentifier{
			crypto.SHA256: oidECDSAWithSHA256, crypto.SHA384: oidECDSAWithSHA384, crypto.SHA512: oidECDSAWithSHA512,
		}[o.Hash]
	default:
		return nil, fmt.Errorf("cms: unsupported key type %T", o.Key.Public())
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDSignedData)
		b.AddASN1(tagCtx0, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { addAlgorithm(b, hashOID, true) })
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(o.ContentType)
					b.AddASN1(tagCtx0, func(b *cryptobyte.Builder) { b.AddBytes(o.Content) })
				})
				b.AddASN1(tagCtx0, func(b *cryptobyte.Builder) {
					b.AddBytes(o.Cert.Raw)
					for _, c := range o.Extra {
						if !bytes.Equal(c.Raw, o.Cert.Raw) {
							b.AddBytes(c.Raw)
						}
					}
				})
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1Int64(1)
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddBytes(o.Cert.RawIssuer)
							b.AddASN1BigInt(o.Cert.SerialNumber)
						})
						addAlgorithm(b, hashOID, true)
						b.AddASN1(tagCtx0, func(b *cryptobyte.Builder) { b.AddBytes(s.signedBody) })
						addAlgorithm(b, sigAlg, sigAlg.Equal(oidRSAEncryption))
						b.AddASN1OctetString(s.Signature)
						if len(unsigned) > 0 {
							b.AddASN1(tagImplicit1, func(b *cryptobyte.Builder) { addSortedAttributes(b, unsigned) })
						}
					})
				})
			})
		})
	})
	return b.Bytes()
}

func addAlgorithm(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, null bool) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if null {
			b.AddASN1NULL()
		}
	})
}

// addSortedAttributes adds attrs in DER SET OF order. Verifiers that
// re-encode the attributes (OpenSSL) depend on it.
func addSortedAttributes(b *cryptobyte.Builder, attrs []Attribute) {
	enc := make([][]byte, len(attrs))
	for i, a := range attrs {
		enc[i] = mustBuild(func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(a.Type)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					vals := slices.Clone(a.Values)
					slices.SortFunc(vals, bytes.Compare)
					for _, v := range vals {
						b.AddBytes(v)
					}
				})
			})
		})
	}
	slices.SortFunc(enc, bytes.Compare)
	for _, e := range enc {
		b.AddBytes(e)
	}
}

// Build runs f on a new builder and returns the bytes. It panics on a
// builder error, which only happens for invalid input built by this
// package's callers (an invalid OID).
func Build(f func(b *cryptobyte.Builder)) []byte { return mustBuild(f) }

func mustBuild(f func(b *cryptobyte.Builder)) []byte {
	b := cryptobyte.NewBuilder(nil)
	f(b)
	return b.BytesOrPanic()
}
