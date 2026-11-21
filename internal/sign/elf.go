// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jc-lab/authentielf"
)

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// IsELF reports whether data starts with the ELF magic.
func IsELF(data []byte) bool { return bytes.HasPrefix(data, elfMagic) }

// VerifyELF verifies the AuthentiELF signatures of an ELF image held in
// memory against the compiled-in code-signing roots.
//
// The image is accepted only if all of these hold:
//   - it is a canonical AuthentiELF file with at least one signature, and
//     every signature is valid (an unsigned or modified file is rejected);
//   - every signature uses SHA-256, SHA-384 or SHA-512;
//   - every signer certificate chains to a compiled-in root, the chain
//     allows code signing, and the signer certificate itself lists the
//     code-signing extended key usage explicitly;
//   - a timestamp is optional. When present it must be a valid RFC 3161
//     token over the signature whose TSA chain verifies against the system
//     roots plus the code-signing roots, and the signer chain is then
//     validated at the timestamp time. Without a timestamp the chain is
//     validated at the current time, so an unstamped signature stops
//     verifying when the signing certificate expires. Release builds should
//     be timestamped; development builds need not be.
func VerifyELF(data []byte) error {
	roots, err := ParseCodeSigningRoots(currentTrust().codeSigningRoots)
	if err != nil {
		return err
	}
	return verifyELF(data, roots, time.Time{})
}

func verifyELF(data []byte, rootCerts []*x509.Certificate, now time.Time) error {
	if len(rootCerts) == 0 {
		return ErrNoCodeSigningRoots
	}
	if !IsELF(data) {
		return errors.New("sign: not an ELF file")
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
	results, err := authentielf.Verify(data, &authentielf.VerifyOptions{
		Roots:          roots,
		TimestampRoots: tsRoots,
		CurrentTime:    now,
	})
	if err != nil {
		return fmt.Errorf("sign: code signature: %w", err)
	}
	if len(results) == 0 {
		return fmt.Errorf("sign: code signature: %w", authentielf.ErrNotSigned)
	}
	for _, r := range results {
		switch r.Signature.HashAlgorithm {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		default:
			return fmt.Errorf("sign: code signature #%d: digest algorithm %v not accepted", r.Index, r.Signature.HashAlgorithm)
		}
		if len(r.Chains) == 0 || len(r.Chains[0]) == 0 {
			return fmt.Errorf("sign: code signature #%d: no verified chain", r.Index)
		}
		if !slices.Contains(r.Chains[0][0].ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
			return fmt.Errorf("sign: code signature #%d: signer certificate lacks the code-signing usage", r.Index)
		}
	}
	return nil
}

// ELFSigner holds the key material for SignELF.
type ELFSigner struct {
	Key         crypto.Signer
	Certificate *x509.Certificate
	// Intermediates are embedded so verifiers can build the chain.
	Intermediates []*x509.Certificate
	// TimestampURL is an RFC 3161 TSA. Empty means no timestamp.
	TimestampURL string
	ProgramName  string
}

// SignELF returns data with an AuthentiELF signature, replacing any existing
// signatures. A TSA is contacted only when TimestampURL is set.
func SignELF(ctx context.Context, data []byte, s *ELFSigner) ([]byte, error) {
	if s == nil || s.Key == nil || s.Certificate == nil {
		return nil, errors.New("sign: signing key and certificate are required")
	}
	if !IsELF(data) {
		return nil, errors.New("sign: not an ELF file")
	}
	opts := &authentielf.SignOptions{
		Signer:        s.Key,
		Certificate:   s.Certificate,
		Intermediates: s.Intermediates,
		Hash:          crypto.SHA256,
		ProgramName:   s.ProgramName,
	}
	if s.TimestampURL != "" {
		opts.Timestamper = authentielf.NewRFC3161Timestamper(s.TimestampURL)
	}
	out, err := authentielf.Sign(ctx, data, opts)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return out, nil
}
