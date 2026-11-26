// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import "testing"

// SetOfficialKeys replaces the official release keys for a test.
func SetOfficialKeys(t testing.TB, keys ...string) {
	prev := officialReleaseKeys
	officialReleaseKeys = keys
	t.Cleanup(func() { officialReleaseKeys = prev })
}

// OfficialKeys returns the official release keys.
func OfficialKeys() []string { return officialReleaseKeys }
