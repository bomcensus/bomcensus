// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package hpkebox

import (
	"bytes"
	"errors"
	"testing"
)

func mustKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestRoundTrip(t *testing.T) {
	priv, pub := mustKey(t)
	if len(pub) != PublicKeySize {
		t.Fatalf("public key size %d", len(pub))
	}
	info := SecretInfo("scanner-1", "ssh.t1.abc", "credential")
	for _, msg := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("secret"), 10000)} {
		sealed, err := Seal(pub, msg, info)
		if err != nil {
			t.Fatal(err)
		}
		if sealed[0] != Version || len(sealed) != 1+32+len(msg)+16 {
			t.Fatalf("unexpected sealed layout: version %d, len %d", sealed[0], len(sealed))
		}
		got, err := Open(priv, sealed, info)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatal("plaintext differs")
		}
	}
	// Two seals of the same value differ (fresh encapsulation).
	a, _ := Seal(pub, []byte("v"), info)
	b, _ := Seal(pub, []byte("v"), info)
	if bytes.Equal(a, b) {
		t.Fatal("sealing is deterministic")
	}
}

func TestOpenFailures(t *testing.T) {
	priv, pub := mustKey(t)
	other, _ := mustKey(t)
	info := SecretInfo("scanner-1", "job-1", "credential")
	sealed, err := Seal(pub, []byte("password"), info)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() ([]byte, error){
		"wrong key":     func() ([]byte, error) { return Open(other, sealed, info) },
		"wrong scanner": func() ([]byte, error) { return Open(priv, sealed, SecretInfo("scanner-2", "job-1", "credential")) },
		"wrong job":     func() ([]byte, error) { return Open(priv, sealed, SecretInfo("scanner-1", "job-2", "credential")) },
		"wrong field":   func() ([]byte, error) { return Open(priv, sealed, SecretInfo("scanner-1", "job-1", "kubeconfig")) },
		"tampered body": func() ([]byte, error) {
			c := bytes.Clone(sealed)
			c[len(c)-1] ^= 1
			return Open(priv, c, info)
		},
		"tampered enc": func() ([]byte, error) {
			c := bytes.Clone(sealed)
			c[5] ^= 0x80
			return Open(priv, c, info)
		},
		"bad version": func() ([]byte, error) {
			c := bytes.Clone(sealed)
			c[0] = 2
			return Open(priv, c, info)
		},
		"truncated": func() ([]byte, error) { return Open(priv, sealed[:20], info) },
		"empty":     func() ([]byte, error) { return Open(priv, nil, info) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			pt, err := f()
			if !errors.Is(err, ErrOpen) || pt != nil {
				t.Fatalf("got %q, %v; want ErrOpen", pt, err)
			}
		})
	}
}

func TestSecretInfoUnambiguous(t *testing.T) {
	if bytes.Equal(SecretInfo("ab", "c", "f"), SecretInfo("a", "bc", "f")) {
		t.Fatal("info strings collide")
	}
}

func TestKeyEncoding(t *testing.T) {
	priv, pub := mustKey(t)
	p, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivateKeyPEM(p)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := PublicKey(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatal("public key differs after PEM round trip")
	}
	sealed, _ := Seal(pub, []byte("v"), nil)
	if _, err := Open(back, sealed, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyPEM([]byte("junk")); err == nil {
		t.Fatal("parsed junk")
	}
}

func TestCheckPublicKey(t *testing.T) {
	_, pub := mustKey(t)
	if err := CheckPublicKey(pub); err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKey(pub[:31]); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := Seal(make([]byte, 31), []byte("v"), nil); err == nil {
		t.Fatal("sealed to short key")
	}
}
