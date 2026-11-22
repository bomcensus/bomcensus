// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OIDTSTInfo is id-ct-TSTInfo, the content type of an RFC 3161 token.
var OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

// Token is a parsed RFC 3161 TimeStampToken.
type Token struct {
	SignedData    *SignedData
	Hash          crypto.Hash // of the message imprint
	HashedMessage []byte
	GenTime       time.Time
	Nonce         *big.Int // nil when absent
}

// ParseToken parses a DER TimeStampToken.
func ParseToken(der []byte) (*Token, error) {
	sd, err := Parse(der)
	if err != nil {
		return nil, err
	}
	if !sd.ContentType.Equal(OIDTSTInfo) {
		return nil, fmt.Errorf("cms: timestamp content type %v is not TSTInfo", sd.ContentType)
	}
	if sd.Content == nil || !cryptobyte.String(sd.Content).PeekASN1Tag(cbasn1.OCTET_STRING) {
		return nil, errMalformed("TSTInfo")
	}
	in := cryptobyte.String(sd.ContentOctets)
	var info, imprint cryptobyte.String
	var version int
	var policy asn1.ObjectIdentifier
	if !in.ReadASN1(&info, cbasn1.SEQUENCE) || !in.Empty() ||
		!info.ReadASN1Integer(&version) || version != 1 ||
		!info.ReadASN1ObjectIdentifier(&policy) ||
		!info.ReadASN1(&imprint, cbasn1.SEQUENCE) {
		return nil, errMalformed("TSTInfo")
	}
	alg, err := readAlgorithm(&imprint)
	if err != nil {
		return nil, err
	}
	t := &Token{SignedData: sd}
	if t.Hash, err = HashForOID(alg); err != nil {
		return nil, err
	}
	var hashed, genTime cryptobyte.String
	serial := new(big.Int)
	if !imprint.ReadASN1(&hashed, cbasn1.OCTET_STRING) || !imprint.Empty() || len(hashed) != t.Hash.Size() ||
		!info.ReadASN1Integer(serial) ||
		!info.ReadASN1(&genTime, cbasn1.GeneralizedTime) {
		return nil, errMalformed("TSTInfo")
	}
	t.HashedMessage = hashed
	if t.GenTime, err = parseGeneralizedTime(string(genTime)); err != nil {
		return nil, err
	}
	// accuracy, ordering, nonce, tsa and extensions follow; only the nonce
	// is used.
	if !info.SkipOptionalASN1(cbasn1.SEQUENCE) || !info.SkipOptionalASN1(cbasn1.BOOLEAN) {
		return nil, errMalformed("TSTInfo")
	}
	if info.PeekASN1Tag(cbasn1.INTEGER) {
		t.Nonce = new(big.Int)
		if !info.ReadASN1Integer(t.Nonce) {
			return nil, errMalformed("TSTInfo")
		}
	}
	return t, nil
}

// parseGeneralizedTime parses YYYYMMDDHHMMSS[.f*]Z. cryptobyte rejects
// fractional seconds, which some TSAs emit.
func parseGeneralizedTime(s string) (time.Time, error) {
	bad := fmt.Errorf("cms: invalid genTime %q", s)
	body, ok := strings.CutSuffix(s, "Z")
	if !ok {
		return time.Time{}, bad
	}
	base, frac, hasFrac := strings.Cut(body, ".")
	if len(base) != 14 {
		return time.Time{}, bad
	}
	t, err := time.Parse("20060102150405", base)
	if err != nil {
		return time.Time{}, bad
	}
	if hasFrac {
		if frac == "" || len(frac) > 9 || strings.Trim(frac, "0123456789") != "" {
			return time.Time{}, bad
		}
		n, err := strconv.Atoi(frac + strings.Repeat("0", 9-len(frac)))
		if err != nil {
			return time.Time{}, bad
		}
		t = t.Add(time.Duration(n))
	}
	return t.UTC(), nil
}

// Verify checks that the token has exactly one signer, that its signature
// is valid, and that the TSA certificate chains to roots at the token's
// genTime and lists the time-stamping extended key usage itself.
func (t *Token) Verify(roots *x509.CertPool) error {
	sd := t.SignedData
	if len(sd.Signers) != 1 {
		return errors.New("cms: timestamp must have exactly one signer")
	}
	cert, err := sd.Verify(sd.Signers[0])
	if err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	inter := x509.NewCertPool()
	for _, c := range sd.Certificates {
		inter.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   t.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return fmt.Errorf("cms: timestamp authority certificate: %w", err)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
		return errors.New("cms: timestamp authority certificate lacks the time-stamping usage")
	}
	return nil
}

// RequestTimestamp obtains a token over digest (computed with h) from an
// RFC 3161 HTTP TSA and checks that the token answers the request.
func RequestTimestamp(ctx context.Context, url string, h crypto.Hash, digest []byte) ([]byte, error) {
	oid, err := OIDForHash(h)
	if err != nil {
		return nil, err
	}
	nb := make([]byte, 8)
	if _, err := rand.Read(nb); err != nil {
		return nil, err
	}
	nonce := new(big.Int).SetBytes(nb)
	req := Build(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				addAlgorithm(b, oid, true)
				b.AddASN1OctetString(digest)
			})
			b.AddASN1BigInt(nonce)
			b.AddASN1Boolean(true) // certReq
		})
	})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("cms: timestamp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cms: timestamp: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("cms: timestamp: %w", err)
	}
	in := cryptobyte.String(body)
	var tsr, status cryptobyte.String
	var code int
	var token cryptobyte.String
	if !in.ReadASN1(&tsr, cbasn1.SEQUENCE) || !in.Empty() ||
		!tsr.ReadASN1(&status, cbasn1.SEQUENCE) || !status.ReadASN1Integer(&code) {
		return nil, errors.New("cms: timestamp: malformed response")
	}
	if code != 0 && code != 1 { // granted, grantedWithMods
		return nil, fmt.Errorf("cms: timestamp: request rejected with status %d", code)
	}
	if !tsr.ReadASN1Element(&token, cbasn1.SEQUENCE) || !tsr.Empty() {
		return nil, errors.New("cms: timestamp: response has no token")
	}
	tok, err := ParseToken(token)
	if err != nil {
		return nil, err
	}
	if tok.Hash != h || !bytes.Equal(tok.HashedMessage, digest) {
		return nil, errors.New("cms: timestamp: token does not match the request")
	}
	if tok.Nonce == nil || tok.Nonce.Cmp(nonce) != 0 {
		return nil, errors.New("cms: timestamp: token nonce does not match the request")
	}
	return token, nil
}
