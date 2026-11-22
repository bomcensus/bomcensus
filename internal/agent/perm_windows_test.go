// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"testing"

	"github.com/bomcensus/bomcensus/internal/platform/paths"
	"github.com/bomcensus/bomcensus/internal/platform/winacl"
)

func checkPrivateDir(t *testing.T, dir string) {
	t.Helper()
	sid, err := winacl.ServiceSID(paths.AgentService)
	if err != nil {
		t.Fatal(err)
	}
	if err := winacl.Check(dir, sid); err != nil {
		t.Fatal(err)
	}
}

func checkPrivateFile(t *testing.T, path string) {
	t.Helper()
	sid, err := winacl.ServiceSID(paths.AgentService)
	if err != nil {
		t.Fatal(err)
	}
	if err := winacl.CheckGrants(path, sid); err != nil {
		t.Fatal(err)
	}
}
