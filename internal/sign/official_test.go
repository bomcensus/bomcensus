// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign_test

import (
	"errors"
	"testing"

	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

func TestRequireOwnTrust(t *testing.T) {
	own := signtest.NewTrust(t)
	official := signtest.NewTrust(t)
	sign.SetOfficialKeys(t, official.ReleaseKeys())

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
