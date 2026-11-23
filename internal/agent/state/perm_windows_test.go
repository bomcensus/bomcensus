// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

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

func TestLockedOpenKeepsACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := OpenAs(dir, "bomcensus-test"); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open: %v", err)
	}
	// The service SID was not added while the directory was locked.
	if err := winacl.Check(dir); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesForeignDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("open of a non-empty directory without a lock file succeeded")
	}
	if _, err := os.Lstat(filepath.Join(dir, lockName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lock file left behind: %v", err)
	}
	if err := winacl.Check(dir); err == nil {
		t.Fatal("ACL of the directory was replaced")
	}
}

func TestOpenKeepsProtectedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	// The installer makes Administrators the owner; an Open of a directory
	// that is already protected must keep it.
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		t.Skipf("cannot make Administrators the owner: %v", err)
	}
	d, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(admins) {
		t.Fatalf("owner %v, %v", owner, err)
	}
}

func TestOpenAcceptsCopyWithoutLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, enrollmentName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	checkPrivateDir(t, dir)
}
