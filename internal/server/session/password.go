// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrUnsupportedHash is returned for a password hash that is not an argon2id
// PHC string with acceptable parameters.
var ErrUnsupportedHash = errors.New("auth: password hash is not a supported argon2id PHC string")

// Parameters of new hashes: the second recommended option of RFC 9106.
const (
	hashMemory  = 64 * 1024 // KiB
	hashTime    = 3
	hashThreads = 4
	hashSaltLen = 16
	hashKeyLen  = 32
)

// Limits on stored hashes, so that a mistyped configuration cannot make every
// login allocate gigabytes or run for minutes.
const (
	maxMemory  = 1 << 20 // KiB (1 GiB)
	maxTime    = 64
	minSaltLen = 8
	maxSaltLen = 64
	minKeyLen  = 16
	maxKeyLen  = 128
)

var phcB64 = base64.RawStdEncoding

// passwordHash is a parsed argon2id hash.
type passwordHash struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// HashPassword returns an argon2id PHC string for password:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth: empty password")
	}
	salt := make([]byte, hashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	h := passwordHash{memory: hashMemory, time: hashTime, threads: hashThreads, salt: salt}
	h.key = h.derive(password, hashKeyLen)
	return h.String(), nil
}

// CheckPasswordHash reports whether encoded is an acceptable argon2id PHC
// string.
func CheckPasswordHash(encoded string) error {
	_, err := parsePasswordHash(encoded)
	return err
}

// String formats h as a PHC string.
func (h *passwordHash) String() string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		h.memory, h.time, h.threads, phcB64.EncodeToString(h.salt), phcB64.EncodeToString(h.key))
}

func (h *passwordHash) derive(password string, keyLen uint32) []byte {
	return argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, keyLen)
}

// verify compares in constant time.
func (h *passwordHash) verify(password string) bool {
	return subtle.ConstantTimeCompare(h.derive(password, uint32(len(h.key))), h.key) == 1
}

// parsePasswordHash accepts exactly $argon2id$v=19$m=M,t=T,p=P$salt$key with
// unpadded standard base64 salt and key. Plaintext, other algorithms and
// other versions are rejected. Errors never quote the input, which may be a
// plaintext password put in the wrong place.
func parsePasswordHash(s string) (*passwordHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		return nil, ErrUnsupportedHash
	}
	if parts[1] != "argon2id" {
		return nil, fmt.Errorf("%w: algorithm is not argon2id", ErrUnsupportedHash)
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return nil, fmt.Errorf("%w: version is not 19", ErrUnsupportedHash)
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, fmt.Errorf("%w: parameters", ErrUnsupportedHash)
	}
	var vals [3]uint64
	for i, name := range []string{"m", "t", "p"} {
		v, ok := strings.CutPrefix(params[i], name+"=")
		if !ok || v == "" || v[0] < '0' || v[0] > '9' {
			return nil, fmt.Errorf("%w: parameters", ErrUnsupportedHash)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: parameters", ErrUnsupportedHash)
		}
		vals[i] = n
	}
	h := &passwordHash{memory: uint32(vals[0]), time: uint32(vals[1])}
	if vals[2] < 1 || vals[2] > 255 {
		return nil, fmt.Errorf("%w: p=%d", ErrUnsupportedHash, vals[2])
	}
	h.threads = uint8(vals[2])
	if h.memory < 8*uint32(h.threads) || h.memory > maxMemory {
		return nil, fmt.Errorf("%w: m=%d", ErrUnsupportedHash, h.memory)
	}
	if h.time < 1 || h.time > maxTime {
		return nil, fmt.Errorf("%w: t=%d", ErrUnsupportedHash, h.time)
	}
	var err error
	if h.salt, err = phcB64.Strict().DecodeString(parts[4]); err != nil ||
		len(h.salt) < minSaltLen || len(h.salt) > maxSaltLen {
		return nil, fmt.Errorf("%w: salt", ErrUnsupportedHash)
	}
	if h.key, err = phcB64.Strict().DecodeString(parts[5]); err != nil ||
		len(h.key) < minKeyLen || len(h.key) > maxKeyLen {
		return nil, fmt.Errorf("%w: hash", ErrUnsupportedHash)
	}
	return h, nil
}
