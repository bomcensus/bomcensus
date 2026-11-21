// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package hpkebox seals short secrets to a scanner's encryption public key
// with HPKE (RFC 9180) in base mode, single shot.
//
// Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (KEM 0x0020,
// KDF 0x0001, AEAD 0x0002). Format, version 1:
//
//	0x01 | enc (32 bytes) | ciphertext
//
// The version byte is not authenticated by itself; it only selects the
// suite, and a value sealed under another suite does not open. The info
// string binds a sealed value to its recipient, its job and its field
// (SecretInfo), so a value copied into another directive does not open.
//
// Public keys are the 32-byte X25519 encoding (RFC 9180 SerializePublicKey).
// Private keys are stored as PKCS#8 PEM.
package hpkebox

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
)

// Version is the first byte of a sealed value.
const Version byte = 1

// PublicKeySize is the length of an encoded public key.
const PublicKeySize = 32

const encSize = 32

// ErrOpen is returned when a sealed value cannot be opened: wrong key,
// wrong info, tampered or malformed.
var ErrOpen = errors.New("hpkebox: cannot open sealed value")

var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// GenerateKey returns a new key pair: the private key in the RFC 9180
// serialization and the encoded public key.
func GenerateKey() (priv, pub []byte, err error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("hpkebox: generate key: %w", err)
	}
	priv, err = k.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("hpkebox: encode key: %w", err)
	}
	return priv, k.PublicKey().Bytes(), nil
}

// PublicKey returns the encoded public key of priv.
func PublicKey(priv []byte) ([]byte, error) {
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: invalid private key: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}

// CheckPublicKey reports whether pub is a valid encoded public key.
func CheckPublicKey(pub []byte) error {
	if len(pub) != PublicKeySize {
		return fmt.Errorf("hpkebox: public key has %d bytes, want %d", len(pub), PublicKeySize)
	}
	if _, err := kem.NewPublicKey(pub); err != nil {
		return fmt.Errorf("hpkebox: invalid public key: %w", err)
	}
	return nil
}

// Seal encrypts plaintext to the recipient's public key, bound to info.
func Seal(recipientPublicKey, plaintext, info []byte) ([]byte, error) {
	if err := CheckPublicKey(recipientPublicKey); err != nil {
		return nil, err
	}
	pk, err := kem.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: invalid public key: %w", err)
	}
	ct, err := hpke.Seal(pk, kdf, aead, info, plaintext)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: seal: %w", err)
	}
	return append([]byte{Version}, ct...), nil
}

// Open decrypts a value sealed by Seal. Every failure yields ErrOpen.
func Open(privateKey, sealed, info []byte) ([]byte, error) {
	if len(sealed) < 1+encSize || sealed[0] != Version {
		return nil, ErrOpen
	}
	k, err := kem.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: invalid private key: %w", err)
	}
	pt, err := hpke.Open(k, kdf, aead, info, sealed[1:])
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// secretInfoLabel starts every info string made by SecretInfo.
const secretInfoLabel = "bomcensus directive secret v1"

// SecretInfo is the info of a secret sent in a directive: the scanner it is
// sealed to, the job it belongs to and the directive field that carries it
// ("credential", "kubeconfig"). Each part is length-prefixed (two bytes,
// big endian) after the label.
func SecretInfo(scannerID, jobID, field string) []byte {
	out := []byte(secretInfoLabel)
	for _, s := range []string{scannerID, jobID, field} {
		n := min(len(s), 0xffff)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, s[:n]...)
	}
	return out
}

const pemType = "PRIVATE KEY"

// EncodePrivateKeyPEM encodes priv as a PKCS#8 PEM block.
func EncodePrivateKeyPEM(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: invalid private key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a key written by EncodePrivateKeyPEM.
func ParsePrivateKeyPEM(b []byte) ([]byte, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemType {
		return nil, errors.New("hpkebox: no PKCS#8 private key PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hpkebox: parse private key: %w", err)
	}
	ek, ok := k.(*ecdh.PrivateKey)
	if !ok || ek.Curve() != ecdh.X25519() {
		return nil, errors.New("hpkebox: private key is not an X25519 key")
	}
	return ek.Bytes(), nil
}
