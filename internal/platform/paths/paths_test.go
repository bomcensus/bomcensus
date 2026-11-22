// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package paths

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	for name, p := range map[string]string{
		"install": InstallDir(), "agent": AgentStateDir(),
		"scanner": ScannerStateDir(), "spool": UpdateSpoolDir(),
	} {
		if !filepath.IsAbs(p) {
			t.Errorf("%s: %q is not absolute", name, p)
		}
	}
	if !strings.HasPrefix(AgentStateDir(), DataDir()) {
		t.Errorf("agent state %q not under %q", AgentStateDir(), DataDir())
	}
	if runtime.GOOS == "linux" {
		want := map[string]string{
			InstallDir():      "/opt/bomcensus",
			AgentStateDir():   "/var/lib/bomcensus/agent",
			ScannerStateDir(): "/var/lib/bomcensus/scanner",
			UpdateSpoolDir():  "/var/lib/bomcensus/update-spool",
		}
		for got, w := range want {
			if got != w {
				t.Errorf("got %q, want %q", got, w)
			}
		}
	}
	if runtime.GOOS == "windows" {
		if filepath.Base(InstallDir()) != "bomcensus" || !strings.HasSuffix(UpdateSpoolDir(), `bomcensus\update-spool`) {
			t.Errorf("unexpected windows defaults %q %q", InstallDir(), UpdateSpoolDir())
		}
	}
}
