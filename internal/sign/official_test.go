// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func TestRequireOwnTrust(t *testing.T) {
	own := signtest.NewTrust(t)
	official := signtest.NewTrust(t)
	officialKeys, err := sign.ParseReleaseKeys(official.ReleaseKeys())
	if err != nil {
		t.Fatal(err)
	}
	sign.SetOfficialKeys(t, sign.OfficialKeyEntry(officialKeys[0]))

	signtest.SetTrust(t, "", "")
	if err := sign.RequireOwnTrust(); !errors.Is(err, sign.ErrNoReleaseKeys) {
		t.Fatalf("no trust: %v", err)
	}
	signtest.SetTrust(t, own.ReleaseKeys(), "")
	if err := sign.RequireOwnTrust(); !errors.Is(err, sign.ErrNoCodeSigningRoots) {
		t.Fatalf("no roots: %v", err)
	}
	signtest.SetTrust(t, own.ReleaseKeys(), own.CodeSigningRoots())
	if err := sign.RequireOwnTrust(); err != nil {
		t.Fatalf("own trust: %v", err)
	}
	signtest.SetTrust(t, own.ReleaseKeys()+","+official.ReleaseKeys(), own.CodeSigningRoots())
	if err := sign.RequireOwnTrust(); !errors.Is(err, sign.ErrOfficialTrust) {
		t.Fatalf("official key trusted: %v", err)
	}
}

func TestOfficialKeysFormat(t *testing.T) {
	for i, s := range sign.OfficialKeys() {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("official key %d %q: %v", i, s, err)
		}
		k, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("official key %d %q: want base64 of an SPKI DER: %v", i, s, err)
		}
		ek, ok := k.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("official key %d %q: not an Ed25519 key", i, s)
		}
		if !sign.IsOfficialKey(ek) {
			t.Fatalf("official key %d %q: not matched by IsOfficialKey", i, s)
		}
	}
}
