// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package token implements the enrollment string
//
//	bc1.<ca-hash>.<key-id>.<secret>
//
// Each field is unpadded base64url. ca-hash is the SHA-256 of the Agent TLS
// trust anchor's SPKI, key-id identifies the Register Key and secret is the
// Ed25519 seed of the Register Key.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

const (
	// Prefix is the format version of the enrollment string.
	Prefix = "bc1"

	// CAHashSize is the length of the trust anchor SPKI hash in bytes.
	CAHashSize = 32
	// KeyIDSize is the length of a Register Key identifier in bytes.
	KeyIDSize = 8
	// SecretSize is the length of the Register Key seed in bytes.
	SecretSize = ed25519.SeedSize

	caHashLen = 43
	keyIDLen  = 11
	secretLen = 43

	// Len is the length of an encoded enrollment string.
	Len = len(Prefix) + 1 + caHashLen + 1 + keyIDLen + 1 + secretLen
)

var (
	// ErrMalformed is returned for any string that is not a valid enrollment string.
	ErrMalformed = errors.New("token: malformed enrollment string")

	enc = base64.RawURLEncoding.Strict()
)

// KeyID identifies a Register Key. It is not secret.
type KeyID [KeyIDSize]byte

// String returns the unpadded base64url form used in the enrollment string.
func (k KeyID) String() string { return enc.EncodeToString(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k KeyID) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *KeyID) UnmarshalText(b []byte) error {
	id, err := ParseKeyID(string(b))
	if err != nil {
		return err
	}
	*k = id
	return nil
}

// ParseKeyID parses the base64url form of a key id.
func ParseKeyID(s string) (KeyID, error) {
	var k KeyID
	if err := decodeField(k[:], s, keyIDLen); err != nil {
		return KeyID{}, fmt.Errorf("token: key id: %w", err)
	}
	return k, nil
}

// Token is a decoded enrollment string.
type Token struct {
	CAHash [CAHashSize]byte
	KeyID  KeyID
	Secret [SecretSize]byte
}

// New creates a token for the given trust anchor hash with a random key id
// and secret.
func New(caHash [CAHashSize]byte) (Token, error) {
	t := Token{CAHash: caHash}
	if _, err := rand.Read(t.KeyID[:]); err != nil {
		return Token{}, fmt.Errorf("token: key id: %w", err)
	}
	if _, err := rand.Read(t.Secret[:]); err != nil {
		return Token{}, fmt.Errorf("token: secret: %w", err)
	}
	return t, nil
}

// Parse decodes an enrollment string. It accepts only the exact canonical
// form: version prefix, four fields, unpadded base64url with exact lengths.
func Parse(s string) (Token, error) {
	if len(s) != Len {
		return Token{}, fmt.Errorf("%w: length %d, want %d", ErrMalformed, len(s), Len)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return Token{}, fmt.Errorf("%w: %d fields, want 4", ErrMalformed, len(parts))
	}
	if parts[0] != Prefix {
		return Token{}, fmt.Errorf("%w: unknown version", ErrMalformed)
	}
	var t Token
	if err := decodeField(t.CAHash[:], parts[1], caHashLen); err != nil {
		return Token{}, fmt.Errorf("%w: ca-hash: %w", ErrMalformed, err)
	}
	if err := decodeField(t.KeyID[:], parts[2], keyIDLen); err != nil {
		return Token{}, fmt.Errorf("%w: key-id: %w", ErrMalformed, err)
	}
	if err := decodeField(t.Secret[:], parts[3], secretLen); err != nil {
		return Token{}, fmt.Errorf("%w: secret: %w", ErrMalformed, err)
	}
	return t, nil
}

// String returns the enrollment string. It contains the secret.
func (t Token) String() string {
	var b strings.Builder
	b.Grow(Len)
	b.WriteString(Prefix)
	b.WriteByte('.')
	b.WriteString(enc.EncodeToString(t.CAHash[:]))
	b.WriteByte('.')
	b.WriteString(t.KeyID.String())
	b.WriteByte('.')
	b.WriteString(enc.EncodeToString(t.Secret[:]))
	return b.String()
}

// Format returns the enrollment string of t.
func Format(t Token) string { return t.String() }

// LogValue keeps the secret out of structured logs.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key_id", t.KeyID.String()),
		slog.String("ca_hash", enc.EncodeToString(t.CAHash[:])),
	)
}

// PrivateKey returns the Register Key private key derived from the secret.
func (t Token) PrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(t.Secret[:])
}

// PublicKey returns the Register Key public key derived from the secret.
func (t Token) PublicKey() ed25519.PublicKey {
	return t.PrivateKey().Public().(ed25519.PublicKey)
}

// decodeField decodes an unpadded base64url field of exactly wantLen
// characters into dst, which must have the decoded length.
func decodeField(dst []byte, s string, wantLen int) error {
	if len(s) != wantLen {
		return fmt.Errorf("length %d, want %d", len(s), wantLen)
	}
	// The decoder skips CR and LF; reject anything outside the alphabet first.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("invalid character at offset %d", i)
		}
	}
	n, err := enc.Decode(dst, []byte(s))
	if err != nil {
		return err
	}
	if n != len(dst) {
		return fmt.Errorf("decoded %d bytes, want %d", n, len(dst))
	}
	return nil
}
