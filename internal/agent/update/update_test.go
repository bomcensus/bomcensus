// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package update

import (
	"path/filepath"
	"testing"
)

func TestDeriveInstallDir(t *testing.T) {
	base := filepath.Join(string(filepath.Separator)+"opt", "bomcensus")
	current := filepath.Join(base, "current", "bomcensus-agent.exe")
	for _, c := range []struct {
		goos, exe, want string
	}{
		{"linux", filepath.Join(base, "versions", "1.2.3", "bomcensus-agent"), base},
		{"windows", filepath.Join(base, "versions", "1.2.3", "bomcensus-agent.exe"), base},
		{"windows", current, base},
		// Only Windows starts the agent through current without resolving it.
		{"linux", current, ""},
		{"linux", filepath.Join(base, "versions", "latest", "bomcensus-agent"), ""},
		{"linux", filepath.Join(base, "bin", "bomcensus-agent"), ""},
	} {
		got, ok := deriveInstallDir(c.goos, c.exe)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s %s: %q %v, want %q", c.goos, c.exe, got, ok, c.want)
		}
	}
}
