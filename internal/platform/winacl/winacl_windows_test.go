// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package winacl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := filepath.Join(dir, "before")
	if err := os.WriteFile(before, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(dir); err == nil {
		t.Log("temporary directory already restricted")
	}
	if err := ProtectDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := Check(dir); err != nil {
		t.Fatal(err)
	}
	after := filepath.Join(dir, "after")
	if err := os.WriteFile(after, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{before, after} {
		if err := CheckGrants(p); err != nil {
			t.Error(err)
		}
	}
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile(f); err != nil {
		t.Fatal(err)
	}
	if err := Check(f); err != nil {
		t.Fatal(err)
	}
}

func TestServiceSID(t *testing.T) {
	// sc showsid TrustedInstaller
	sid, err := ServiceSID("TrustedInstaller")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sid.String(), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
