// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	b := newBox(t)
	for _, plain := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("secret"), 1000)} {
		ct, err := b.Seal(plain, []byte("pki:agent-ca"))
		if err != nil {
			t.Fatal(err)
		}
		if len(plain) > 16 && bytes.Contains(ct, plain) {
			t.Fatal("ciphertext contains the plaintext")
		}
		got, err := b.Open(ct, []byte("pki:agent-ca"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round trip: got %q", got)
		}
	}
	a, _ := b.Seal([]byte("same"), nil)
	c, _ := b.Seal([]byte("same"), nil)
	if bytes.Equal(a, c) {
		t.Fatal("two seals of the same value are equal")
	}
}

func TestWrongAAD(t *testing.T) {
	b := newBox(t)
	ct, err := b.Seal([]byte("value"), []byte("credential:1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, aad := range [][]byte{nil, []byte("credential:2"), []byte("credential:1 ")} {
		if _, err := b.Open(ct, aad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("aad %q: err %v", aad, err)
		}
	}
}

func TestTamper(t *testing.T) {
	b := newBox(t)
	ct, err := b.Seal([]byte("value"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ct {
		mod := bytes.Clone(ct)
		mod[i] ^= 0x01
		if _, err := b.Open(mod, []byte("a")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("byte %d flipped: err %v", i, err)
		}
	}
	for _, n := range []int{0, 1, headerSize, len(ct) - 1} {
		if _, err := b.Open(ct[:n], []byte("a")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("truncated to %d: err %v", n, err)
		}
	}
}

func TestWrongKey(t *testing.T) {
	ct, err := newBox(t).Seal([]byte("value"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newBox(t).Open(ct, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err %v", err)
	}
}

func TestNewRejectsBadKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Fatalf("key of %d bytes accepted", n)
		}
	}
}

func TestLoadKey(t *testing.T) {
	key := make([]byte, KeySize)
	_, _ = rand.Read(key)
	std := base64.StdEncoding.EncodeToString(key)
	for _, s := range []string{std, base64.RawURLEncoding.EncodeToString(key), " " + std + "\n"} {
		got, err := ParseKey(s)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("ParseKey(%q): %v", s, err)
		}
	}
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(key[:16])); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParseKey("not base64!"); err == nil {
		t.Fatal("invalid base64 accepted")
	}

	file := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(file, []byte(std+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey("", file)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("LoadKey file: %v", err)
	}
	if _, err := LoadKey(std, file); err == nil {
		t.Fatal("both sources accepted")
	}
	if _, err := LoadKey("", ""); err == nil {
		t.Fatal("no source accepted")
	}
}

func TestCredential(t *testing.T) {
	b := newBox(t)
	in := CredentialSecret{PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----", Passphrase: "pw"}
	ct, err := b.SealCredential("id-1", in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.OpenCredential("id-1", ct)
	if err != nil || out != in {
		t.Fatalf("got %+v, %v", out, err)
	}
	if _, err := b.OpenCredential("id-2", ct); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other id: %v", err)
	}
}
