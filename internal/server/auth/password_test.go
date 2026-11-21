// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// cheapHash returns a valid hash with small parameters so tests run fast.
func cheapHash(t *testing.T, password string) string {
	t.Helper()
	h := passwordHash{memory: 64, time: 1, threads: 1, salt: []byte("0123456789abcdef")}
	h.key = h.derive(password, 32)
	return h.String()
}

func TestHashPasswordRoundTrip(t *testing.T) {
	enc, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected format %q", enc)
	}
	h, err := parsePasswordHash(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !h.verify("correct horse") || h.verify("correct horsE") {
		t.Fatal("verify mismatch")
	}
	if h.String() != enc {
		t.Fatalf("String() = %q, want %q", h.String(), enc)
	}
	if _, err := HashPassword(""); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestParsePasswordHash(t *testing.T) {
	good := cheapHash(t, "pw")
	salt := "MDEyMzQ1Njc4OWFiY2RlZg"
	key := good[strings.LastIndexByte(good, '$')+1:]
	if err := CheckPasswordHash(good); err != nil {
		t.Fatalf("good hash rejected: %v", err)
	}
	bad := map[string]string{
		"plaintext":       "hunter2",
		"empty":           "",
		"bcrypt":          "$2b$12$abcdefghijklmnopqrstuuJqD9Jq3sNn2WcJ4fXc9yX1i5h3a0b1e",
		"argon2i":         "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"argon2d":         "$argon2d$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"no version":      "$argon2id$m=64,t=1,p=1$" + salt + "$" + key,
		"old version":     "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"param order":     "$argon2id$v=19$t=1,m=64,p=1$" + salt + "$" + key,
		"negative":        "$argon2id$v=19$m=-64,t=1,p=1$" + salt + "$" + key,
		"plus sign":       "$argon2id$v=19$m=+64,t=1,p=1$" + salt + "$" + key,
		"zero time":       "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key,
		"zero threads":    "$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key,
		"low memory":      "$argon2id$v=19$m=7,t=1,p=1$" + salt + "$" + key,
		"huge memory":     "$argon2id$v=19$m=4194304,t=1,p=1$" + salt + "$" + key,
		"padded salt":     "$argon2id$v=19$m=64,t=1,p=1$" + salt + "==$" + key,
		"short salt":      "$argon2id$v=19$m=64,t=1,p=1$YWJj$" + key,
		"short key":       "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$YWJj",
		"bad base64":      "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$!!!!",
		"extra field":     good + "$x",
		"trailing junk":   "x" + good,
		"missing key":     "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"extra parameter": "$argon2id$v=19$m=64,t=1,p=1,k=2$" + salt + "$" + key,
	}
	for name, s := range bad {
		err := CheckPasswordHash(s)
		if !errors.Is(err, ErrUnsupportedHash) {
			t.Errorf("%s: got %v, want ErrUnsupportedHash", name, err)
		}
		if s != "" && err != nil && strings.Contains(err.Error(), s) {
			t.Errorf("%s: error quotes the input", name)
		}
	}
}

func TestEnvProvider(t *testing.T) {
	ctx := context.Background()
	p, err := NewEnvProvider(nil, "admin", cheapHash(t, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Authenticate(ctx, "admin", "secret")
	if err != nil || got != (Principal{ID: "env:admin", Name: "admin"}) {
		t.Fatalf("Authenticate = %v, %v", got, err)
	}
	for _, c := range [][2]string{{"admin", "wrong"}, {"root", "secret"}, {"", ""}} {
		if _, err := p.Authenticate(ctx, c[0], c[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Authenticate(%q, %q) = %v", c[0], c[1], err)
		}
	}

	if _, err := NewEnvProvider(nil, "admin", "plain-password"); !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("plaintext hash: %v", err)
	}
	disabled, err := NewEnvProvider(nil, "", "")
	if err != nil || disabled.Enabled() {
		t.Fatalf("unset variables: %v, enabled %v", err, disabled.Enabled())
	}
	if _, err := disabled.Authenticate(ctx, "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled provider: %v", err)
	}
}
