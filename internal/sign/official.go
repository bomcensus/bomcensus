// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
)

// officialReleaseKeys are the release manifest public keys of the official
// bomcensus releases, standard base64 of the raw Ed25519 keys as printed by
// `bomcensus-release manifest-pub` (the PEM body). scripts/release.sh
// refuses to build a release whose manifest key is not listed here
// (bomcensus-release check-official), so an official release cannot ship
// without its entry.
var officialReleaseKeys = []string{
	`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAkagRvQ6lrFEAS4XTgGSiJjIPaV5eOx2UhMGn1wVNMVA=
-----END PUBLIC KEY-----`,
}

// IsOfficialKey reports whether k is a manifest key of the official
// releases.
func IsOfficialKey(k ed25519.PublicKey) bool {
	return slices.Contains(officialReleaseKeys, base64.StdEncoding.EncodeToString(k))
}

// ErrOfficialTrust is returned by RequireOwnTrust for a build that trusts
// the official release keys.
var ErrOfficialTrust = errors.New("sign: the build trusts the official bomcensus release keys")

// RequireOwnTrust checks the compiled trust of a build that changes the
// agent or scanner (for example with its own channel): it must have release
// keys and code-signing roots of its own, and must not trust the official
// release keys. Such a build is not an official release; trusting those
// keys would let an official update replace it, and it cannot be signed
// with them.
func RequireOwnTrust() error {
	keys, err := ReleaseKeys()
	if err != nil {
		return fmt.Errorf("%w: build it with the trust of your own release keys (bomcensus-release keygen, print-ldflags)", err)
	}
	if _, err := CodeSigningRoots(); err != nil {
		return fmt.Errorf("%w: build it with the trust of your own release keys (bomcensus-release keygen, print-ldflags)", err)
	}
	for _, k := range keys {
		if IsOfficialKey(k) {
			return fmt.Errorf("%w: a build with its own channels must be signed with your own release keys", ErrOfficialTrust)
		}
	}
	return nil
}
