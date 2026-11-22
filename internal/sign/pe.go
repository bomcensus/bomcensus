// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/bomcensus/bomcensus/internal/sign/internal/cms"
)

// Authenticode object identifiers.
var (
	oidSpcIndirectData       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcStatementType      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	oidSpcSpOpusInfo         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidSpcPEImageData        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidSpcIndividualSPKeyPur = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}
	oidNestedSignature       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidRFC3161Timestamp      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

const (
	// maxPECertTable bounds the attribute certificate table. Real
	// signatures with a timestamp are around 10 KiB.
	maxPECertTable = 1 << 20
	// maxNestedSignatures bounds the signatures nested in the primary one.
	maxNestedSignatures = 4

	winCertRevision2       = 0x0200
	winCertTypePKCSSigned  = 0x0002
	peCertificateDirectory = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
)

var le = binary.LittleEndian

// IsPE reports whether data starts with an MZ header that points to a PE
// signature.
func IsPE(data []byte) bool {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	off := uint64(le.Uint32(data[0x3c:]))
	return off+4 <= uint64(len(data)) && string(data[off:off+4]) == "PE\x00\x00"
}

// peFile holds the offsets of a PE image that Authenticode needs.
type peFile struct {
	machine     uint16
	checksumOff int
	certDirOff  int // offset of the certificate table data directory entry
	certOff     int // file offset of the certificate table (0: none)
	certSize    int
	// imageEnd is the end of the headers, the section table and all
	// section data. Nothing the loader maps lies beyond it.
	imageEnd int
}

func parsePE(data []byte) (*peFile, error) {
	if !IsPE(data) {
		return nil, errors.New("sign: not a PE file")
	}
	n := uint64(len(data))
	coff := uint64(le.Uint32(data[0x3c:])) + 4
	if coff+20 > n {
		return nil, errors.New("sign: PE: truncated COFF header")
	}
	nsect := uint64(le.Uint16(data[coff+2:]))
	optSize := uint64(le.Uint16(data[coff+16:]))
	opt := coff + 20
	if optSize < 2 || opt+optSize > n {
		return nil, errors.New("sign: PE: truncated optional header")
	}
	var numDirsOff, dirsOff uint64
	switch le.Uint16(data[opt:]) {
	case 0x10b: // PE32
		numDirsOff, dirsOff = 92, 96
	case 0x20b: // PE32+
		numDirsOff, dirsOff = 108, 112
	default:
		return nil, errors.New("sign: PE: unknown optional header magic")
	}
	if dirsOff > optSize {
		return nil, errors.New("sign: PE: truncated optional header")
	}
	numDirs := uint64(le.Uint32(data[opt+numDirsOff:]))
	if numDirs <= peCertificateDirectory || dirsOff+8*(peCertificateDirectory+1) > optSize {
		return nil, errors.New("sign: PE: no certificate table directory entry")
	}
	p := &peFile{
		machine:     le.Uint16(data[coff:]),
		checksumOff: int(opt + 64),
		certDirOff:  int(opt + dirsOff + 8*peCertificateDirectory),
	}
	p.certOff = int(le.Uint32(data[p.certDirOff:]))
	p.certSize = int(le.Uint32(data[p.certDirOff+4:]))

	sects := opt + optSize
	if sects+40*nsect > n {
		return nil, errors.New("sign: PE: truncated section table")
	}
	end := max(sects+40*nsect, uint64(le.Uint32(data[opt+60:]))) // SizeOfHeaders
	for i := range nsect {
		s := data[sects+40*i:]
		if size := uint64(le.Uint32(s[16:])); size != 0 {
			end = max(end, uint64(le.Uint32(s[20:]))+size)
		}
	}
	if end > n {
		return nil, errors.New("sign: PE: section data extends beyond the end of the file")
	}
	p.imageEnd = int(end)
	return p, nil
}

// digest returns the Authenticode image hash of data[:end]: everything
// except the checksum, the certificate table directory entry and whatever
// follows end (the certificate table).
func (p *peFile) digest(data []byte, h crypto.Hash, end int) []byte {
	hh := h.New()
	hh.Write(data[:p.checksumOff])
	hh.Write(data[p.checksumOff+4 : p.certDirOff])
	hh.Write(data[p.certDirOff+8 : end])
	return hh.Sum(nil)
}

// signature returns the PKCS#7 blob of a signed file. The certificate
// table must hold exactly one WIN_CERTIFICATE of type PKCS_SIGNED_DATA,
// lie after all image data and end the file, so that every byte outside
// the table is covered by the image hash.
func (p *peFile) signature(data []byte) ([]byte, error) {
	if p.certOff == 0 && p.certSize == 0 {
		return nil, errors.New("sign: code signature: file is not signed")
	}
	switch {
	case p.certSize < 8 || p.certSize > maxPECertTable:
		return nil, fmt.Errorf("sign: code signature: certificate table size %d out of range", p.certSize)
	case p.certOff%8 != 0 || p.certSize%8 != 0:
		return nil, errors.New("sign: code signature: certificate table is not 8-byte aligned")
	case p.certOff < p.imageEnd:
		return nil, errors.New("sign: code signature: certificate table overlaps the image")
	case p.certOff+p.certSize != len(data):
		return nil, errors.New("sign: code signature: certificate table does not end the file")
	}
	entry := data[p.certOff:]
	length := int(le.Uint32(entry))
	if le.Uint16(entry[4:]) != winCertRevision2 || le.Uint16(entry[6:]) != winCertTypePKCSSigned {
		return nil, errors.New("sign: code signature: not a WIN_CERT_TYPE_PKCS_SIGNED_DATA revision 2 entry")
	}
	if length < 8 || length > p.certSize || (length+7)&^7 != p.certSize {
		return nil, errors.New("sign: code signature: certificate table must hold exactly one entry")
	}
	rest := cryptobyte.String(entry[8:length])
	var der cryptobyte.String
	if !rest.ReadASN1Element(&der, cbasn1.SEQUENCE) {
		return nil, errors.New("sign: code signature: malformed PKCS#7 data")
	}
	if len(rest) >= 8 || !allZero(rest) || !allZero(entry[length:p.certSize]) {
		return nil, errors.New("sign: code signature: unexpected data after the PKCS#7 data")
	}
	return der, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// VerifyPE verifies the Authenticode signature of a PE image held in
// memory against the compiled-in code-signing roots.
//
// The rules are those of VerifyELF:
//   - the file must carry exactly one attribute certificate, of type
//     PKCS_SIGNED_DATA, placed after all image data at the end of the file,
//     and the image hash must match (an unsigned or modified file, or one
//     with data appended after the signature, is rejected);
//   - every signature uses SHA-256, SHA-384 or SHA-512, with an RSA
//     (PKCS #1 v1.5) or ECDSA key;
//   - every signer certificate chains to a compiled-in root, the chain
//     allows code signing, and the signer certificate itself lists the
//     code-signing extended key usage explicitly;
//   - a timestamp is optional. It must be an RFC 3161 token in the
//     unsigned attribute 1.3.6.1.4.1.311.3.3.1 over the signature, whose
//     TSA chain verifies against the system roots plus the code-signing
//     roots and whose TSA certificate lists the time-stamping usage. The
//     signer chain is then validated at the timestamp time, otherwise at
//     the current time.
//
// Signatures nested in the primary one (1.3.6.1.4.1.311.2.4.1, as added by
// signtool /as) are verified the same way and must all be valid, like
// multiple AuthentiELF signatures. Any other unsigned attribute, including
// legacy Authenticode counter-signatures, is rejected because it cannot be
// verified.
func VerifyPE(data []byte) error {
	roots, err := ParseCodeSigningRoots(currentTrust().codeSigningRoots)
	if err != nil {
		return err
	}
	return verifyPE(data, roots, time.Time{})
}

func verifyPE(data []byte, rootCerts []*x509.Certificate, now time.Time) error {
	if len(rootCerts) == 0 {
		return ErrNoCodeSigningRoots
	}
	roots := x509.NewCertPool()
	tsRoots, err := x509.SystemCertPool()
	if err != nil || tsRoots == nil {
		tsRoots = x509.NewCertPool()
	}
	for _, c := range rootCerts {
		roots.AddCert(c)
		tsRoots.AddCert(c)
	}
	_, err = verifyPEPools(data, roots, tsRoots, now)
	return err
}

// peSignature is the outcome of one verified signature.
type peSignature struct {
	hash      crypto.Hash
	signer    *x509.Certificate
	timestamp time.Time // zero without a timestamp
}

func verifyPEPools(data []byte, roots, tsRoots *x509.CertPool, now time.Time) ([]peSignature, error) {
	p, err := parsePE(data)
	if err != nil {
		return nil, err
	}
	der, err := p.signature(data)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	v := &peVerifier{data: data, pe: p, roots: roots, tsRoots: tsRoots, now: now, digests: map[crypto.Hash][]byte{}}
	nested, err := v.verify(der, true)
	if err != nil {
		return nil, fmt.Errorf("sign: code signature #0: %w", err)
	}
	if len(nested) > maxNestedSignatures {
		return nil, fmt.Errorf("sign: code signature: %d nested signatures, maximum is %d", len(nested), maxNestedSignatures)
	}
	for i, n := range nested {
		if _, err := v.verify(n, false); err != nil {
			return nil, fmt.Errorf("sign: code signature #%d: %w", i+1, err)
		}
	}
	return v.results, nil
}

type peVerifier struct {
	data    []byte
	pe      *peFile
	roots   *x509.CertPool
	tsRoots *x509.CertPool
	now     time.Time
	digests map[crypto.Hash][]byte
	results []peSignature
}

// verify checks one signature and returns the signatures nested in it,
// which only the primary signature may carry.
func (v *peVerifier) verify(der []byte, primary bool) (nested [][]byte, err error) {
	sd, err := cms.Parse(der)
	if err != nil {
		return nil, err
	}
	if !sd.ContentType.Equal(oidSpcIndirectData) {
		return nil, fmt.Errorf("content type %v is not SpcIndirectDataContent", sd.ContentType)
	}
	if len(sd.Signers) != 1 {
		return nil, fmt.Errorf("%d signers, want exactly one", len(sd.Signers))
	}
	si := sd.Signers[0]
	h, digest, err := parseIndirectData(sd.ContentOctets)
	if err != nil {
		return nil, err
	}
	if h != si.Hash {
		return nil, errors.New("signer digest algorithm differs from the image digest algorithm")
	}
	want, ok := v.digests[h]
	if !ok {
		want = v.pe.digest(v.data, h, v.pe.certOff)
		v.digests[h] = want
	}
	if !bytes.Equal(digest, want) {
		return nil, errors.New("image digest mismatch (file was modified after signing)")
	}
	cert, err := sd.Verify(si)
	if err != nil {
		return nil, err
	}

	var stamp []byte
	for _, a := range si.UnsignedAttrs {
		switch {
		case a.Type.Equal(oidRFC3161Timestamp):
			if stamp != nil || len(a.Values) != 1 {
				return nil, errors.New("more than one timestamp")
			}
			stamp = a.Values[0]
		case a.Type.Equal(oidNestedSignature) && primary:
			nested = append(nested, a.Values...)
		default:
			return nil, fmt.Errorf("unsupported unsigned attribute %v", a.Type)
		}
	}
	res := peSignature{hash: h, signer: cert}
	at := v.now
	if stamp != nil {
		tok, err := cms.ParseToken(stamp)
		if err != nil {
			return nil, fmt.Errorf("timestamp: %w", err)
		}
		if !bytes.Equal(tok.HashedMessage, cms.Digest(tok.Hash, si.Signature)) {
			return nil, errors.New("timestamp does not cover this signature")
		}
		if err := tok.Verify(v.tsRoots); err != nil {
			return nil, err
		}
		at, res.timestamp = tok.GenTime, tok.GenTime
	}

	inter := x509.NewCertPool()
	for _, c := range sd.Certificates {
		inter.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return nil, errors.New("signer certificate lacks the code-signing usage")
	}
	v.results = append(v.results, res)
	return nested, nil
}

// parseIndirectData parses the body of an SpcIndirectDataContent for a PE
// image and returns its image digest.
func parseIndirectData(body []byte) (crypto.Hash, []byte, error) {
	in := cryptobyte.String(body)
	var data, digestInfo, alg, digest cryptobyte.String
	var typ, algOID asn1.ObjectIdentifier
	if !in.ReadASN1(&data, cbasn1.SEQUENCE) || !in.ReadASN1(&digestInfo, cbasn1.SEQUENCE) || !in.Empty() ||
		!data.ReadASN1ObjectIdentifier(&typ) ||
		!digestInfo.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&algOID) ||
		!digestInfo.ReadASN1(&digest, cbasn1.OCTET_STRING) || !digestInfo.Empty() {
		return 0, nil, errors.New("malformed SpcIndirectDataContent")
	}
	if !typ.Equal(oidSpcPEImageData) {
		return 0, nil, fmt.Errorf("indirect data type %v is not SPC_PE_IMAGE_DATAOBJ", typ)
	}
	if !alg.Empty() {
		var null cryptobyte.String
		if !alg.ReadASN1(&null, cbasn1.NULL) || len(null) != 0 || !alg.Empty() {
			return 0, nil, errors.New("malformed image digest algorithm")
		}
	}
	h, err := cms.HashForOID(algOID)
	if err != nil {
		return 0, nil, err
	}
	if len(digest) != h.Size() {
		return 0, nil, errors.New("image digest has the wrong length")
	}
	return h, digest, nil
}

// SignPE returns data with an Authenticode signature (SHA-256), replacing
// any existing signature. A TSA is contacted only when TimestampURL is set;
// the timestamp is an RFC 3161 counter-signature. The PE checksum is
// updated. It is meant for development and tests: release builds are
// signed by the release pipeline.
func SignPE(ctx context.Context, data []byte, s *CodeSigner) ([]byte, error) {
	if s == nil || s.Key == nil || s.Certificate == nil {
		return nil, errors.New("sign: signing key and certificate are required")
	}
	if k, ok := s.Key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !k.Equal(s.Certificate.PublicKey) {
		return nil, errors.New("sign: private key does not match the certificate")
	}
	p, err := parsePE(data)
	if err != nil {
		return nil, err
	}
	end := len(data)
	if p.certOff != 0 || p.certSize != 0 {
		if p.certOff < p.imageEnd || p.certOff+p.certSize != len(data) {
			return nil, errors.New("sign: PE: existing certificate table is not at the end of the file")
		}
		end = p.certOff
	}
	out := make([]byte, (end+7)&^7, (end+7)&^7+16<<10)
	copy(out, data[:end])
	clear(out[p.certDirOff : p.certDirOff+8])

	const h = crypto.SHA256
	content, err := indirectData(h, p.digest(out, h, len(out)))
	if err != nil {
		return nil, err
	}
	signed, err := cms.Sign(&cms.SignOptions{
		ContentType: oidSpcIndirectData,
		Content:     content,
		Key:         s.Key,
		Cert:        s.Certificate,
		Extra:       s.Intermediates,
		Hash:        h,
		SignedAttrs: []cms.Attribute{
			{Type: oidSpcStatementType, Values: [][]byte{cms.Build(func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidSpcIndividualSPKeyPur) })
			})}},
			{Type: oidSpcSpOpusInfo, Values: [][]byte{opusInfo(s.ProgramName)}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	var unsigned []cms.Attribute
	if s.TimestampURL != "" {
		tok, err := cms.RequestTimestamp(ctx, s.TimestampURL, h, cms.Digest(h, signed.Signature))
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		unsigned = []cms.Attribute{{Type: oidRFC3161Timestamp, Values: [][]byte{tok}}}
	}
	der, err := signed.Encode(unsigned)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	size := (8 + len(der) + 7) &^ 7
	if size > maxPECertTable {
		return nil, errors.New("sign: PE: signature too large")
	}
	certOff := len(out)
	out = append(out, make([]byte, size)...)
	le.PutUint32(out[certOff:], uint32(size))
	le.PutUint16(out[certOff+4:], winCertRevision2)
	le.PutUint16(out[certOff+6:], winCertTypePKCSSigned)
	copy(out[certOff+8:], der)
	le.PutUint32(out[p.certDirOff:], uint32(certOff))
	le.PutUint32(out[p.certDirOff+4:], uint32(size))
	clear(out[p.checksumOff : p.checksumOff+4])
	le.PutUint32(out[p.checksumOff:], peChecksum(out))
	return out, nil
}

// indirectData encodes an SpcIndirectDataContent with SpcPeImageData in the
// form signtool writes.
func indirectData(h crypto.Hash, digest []byte) ([]byte, error) {
	hashOID, err := cms.OIDForHash(h)
	if err != nil {
		return nil, err
	}
	obsolete := bmpString("<<<Obsolete>>>")
	return cms.Build(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidSpcPEImageData)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SpcPeImageData
					b.AddASN1BitString(nil) // flags
					b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(obsolete) })
						})
					})
				})
			})
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(hashOID)
					b.AddASN1NULL()
				})
				b.AddASN1OctetString(digest)
			})
		})
	}), nil
}

// opusInfo encodes SpcSpOpusInfo with an optional program name.
func opusInfo(name string) []byte {
	return cms.Build(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if name == "" {
				return
			}
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(bmpString(name)) })
			})
		})
	})
}

func bmpString(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.BigEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// peChecksum computes the PE image checksum. The checksum field must be
// zero.
func peChecksum(data []byte) uint32 {
	var sum uint64
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint64(le.Uint16(data[i:]))
		} else {
			sum += uint64(data[i])
		}
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	return uint32(sum) + uint32(len(data))
}
