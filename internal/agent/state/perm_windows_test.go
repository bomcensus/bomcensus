// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"path/filepath"
	"testing"

	"github.com/bomcensus/bomcensus/internal/platform/winacl"
)

func checkPrivateDir(t *testing.T, dir string) {
	t.Helper()
	if err := winacl.Check(dir); err != nil {
		t.Fatal(err)
	}
}

func checkPrivateFile(t *testing.T, path string) {
	t.Helper()
	if err := winacl.CheckGrants(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAsGrantsService(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	d, err := OpenAs(dir, "bomcensus-test")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	sid, err := winacl.ServiceSID("bomcensus-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := winacl.Check(dir, sid); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile("x", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile("x", []byte("y"), 0o600); err != nil {
		t.Fatalf("replace: %v", err)
	}
}
