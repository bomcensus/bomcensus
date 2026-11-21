// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	pemTypePKCS8 = "PRIVATE KEY"
	pemTypeEC    = "EC PRIVATE KEY"
	pemTypeRSA   = "RSA PRIVATE KEY"
)

// EncodeCertificatesPEM returns the certificates as consecutive CERTIFICATE
// blocks, in the given order.
func EncodeCertificatesPEM(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		// Writing to a bytes.Buffer without headers cannot fail.
		_ = pem.Encode(&buf, &pem.Block{Type: pemTypeCertificate, Bytes: c.Raw})
	}
	return buf.Bytes()
}

// ParseCertificatesPEM parses CERTIFICATE blocks in order. Text outside
// blocks (such as openssl comments) is ignored; another block type or a
// truncated block is an error.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != pemTypeCertificate {
			return nil, fmt.Errorf("pki: unexpected PEM block %q", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: certificate %d: %w", len(certs), err)
		}
		certs = append(certs, c)
	}
	if bytes.Contains(rest, []byte("-----BEGIN")) {
		return nil, errors.New("pki: malformed PEM block")
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no PEM certificates found")
	}
	return certs, nil
}

func parseSingleCertPEM(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("pki: %d certificates, want 1", len(certs))
	}
	return certs[0], nil
}

// EncodePrivateKeyPEM encodes key as a PKCS#8 "PRIVATE KEY" block.
func EncodePrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: der}), nil
}

// ParsePrivateKeyPEM parses exactly one private key block. PKCS#8 is the
// native format; SEC 1 ("EC PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY")
// are accepted for administrator-supplied keys. An "EC PARAMETERS" block as
// written by openssl is skipped. Encrypted keys are refused.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	var blk *pem.Block
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "EC PARAMETERS" {
			continue
		}
		if blk != nil {
			return nil, errors.New("pki: more than one private key block")
		}
		blk = b
	}
	if bytes.Contains(rest, []byte("-----BEGIN")) {
		return nil, errors.New("pki: malformed PEM block")
	}
	if blk == nil {
		return nil, errors.New("pki: no PEM private key found")
	}
	if _, ok := blk.Headers["Proc-Type"]; ok {
		return nil, errors.New("pki: encrypted private keys are not supported")
	}
	var (
		key any
		err error
	)
	switch blk.Type {
	case pemTypePKCS8:
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case pemTypeEC:
		key, err = x509.ParseECPrivateKey(blk.Bytes)
	case pemTypeRSA:
		key, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("pki: unexpected PEM block %q", blk.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("pki: parse private key: %w", err)
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("pki: unsupported private key type %T", key)
	}
	return s, nil
}
