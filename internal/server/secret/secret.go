// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package secret encrypts values at rest with the server master key.
//
// Seal uses envelope encryption: every value gets a fresh random data key,
// the value is encrypted with the data key and the data key is encrypted
// with the master key, both with AES-256-GCM. The associated data binds a
// ciphertext to the record it belongs to (for example "credential:<id>"), so
// a ciphertext copied into another record does not open.
//
// Format, version 1:
//
//	0x01 | key nonce (12) | sealed data key (32+16) | data nonce (12) | sealed value
//
// The version byte and the caller's associated data are authenticated by both
// GCM operations.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KeySize is the size of the master key in bytes.
const KeySize = 32

const (
	version1    = 1
	nonceSize   = 12
	tagSize     = 16
	wrappedSize = KeySize + tagSize
	headerSize  = 1 + nonceSize + wrappedSize + nonceSize
)

// ErrDecrypt is returned when a ciphertext does not open: wrong key, wrong
// associated data, tampering or an unknown format.
var ErrDecrypt = errors.New("secret: cannot decrypt")

// Box seals and opens values with one master key. It is safe for concurrent
// use.
type Box struct {
	master cipher.AEAD
}

// New returns a Box for a KeySize-byte master key.
func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret: master key must be %d bytes, got %d", KeySize, len(key))
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &Box{master: aead}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return aead, nil
}

func fullAAD(aad []byte) []byte {
	out := make([]byte, 0, 1+len(aad))
	out = append(out, version1)
	return append(out, aad...)
}

// Seal encrypts plaintext and binds it to aad.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	var dek [KeySize]byte
	if _, err := rand.Read(dek[:]); err != nil {
		return nil, fmt.Errorf("secret: data key: %w", err)
	}
	defer clear(dek[:])
	data, err := newGCM(dek[:])
	if err != nil {
		return nil, err
	}
	ad := fullAAD(aad)

	out := make([]byte, 1+nonceSize, headerSize+len(plaintext)+tagSize)
	out[0] = version1
	if _, err := rand.Read(out[1 : 1+nonceSize]); err != nil {
		return nil, fmt.Errorf("secret: nonce: %w", err)
	}
	out = b.master.Seal(out, out[1:1+nonceSize], dek[:], ad)

	dataNonce := make([]byte, nonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, fmt.Errorf("secret: nonce: %w", err)
	}
	out = append(out, dataNonce...)
	return data.Seal(out, dataNonce, plaintext, ad), nil
}

// Open decrypts a value produced by Seal with the same aad. Any failure is
// reported as ErrDecrypt.
func (b *Box) Open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < headerSize+tagSize || ciphertext[0] != version1 {
		return nil, ErrDecrypt
	}
	ad := fullAAD(aad)
	keyNonce := ciphertext[1 : 1+nonceSize]
	wrapped := ciphertext[1+nonceSize : 1+nonceSize+wrappedSize]
	dataNonce := ciphertext[1+nonceSize+wrappedSize : headerSize]

	dek, err := b.master.Open(nil, keyNonce, wrapped, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer clear(dek)
	data, err := newGCM(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	plain, err := data.Open(nil, dataNonce, ciphertext[headerSize:], ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// ParseKey decodes a base64 master key (standard or URL alphabet, padded or
// not, surrounding white space ignored) and checks its size.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var key []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("secret: master key is not valid base64")
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret: master key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

// LoadKey returns the master key from value (BOMCENSUS_MASTER_KEY) or from
// the file named by file (BOMCENSUS_MASTER_KEY_FILE). Exactly one must be
// set.
func LoadKey(value, file string) ([]byte, error) {
	switch {
	case value != "" && file != "":
		return nil, errors.New("secret: set either the master key or the master key file, not both")
	case value != "":
		return ParseKey(value)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("secret: read master key file: %w", err)
		}
		defer clear(b)
		return ParseKey(string(b))
	default:
		return nil, errors.New("secret: no master key configured")
	}
}
