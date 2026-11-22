// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build windows

package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestJunctionSwitch(t *testing.T) {
	install := t.TempDir()
	root, err := os.OpenRoot(install)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, v := range []string{"1.0.0", "1.1.0"} {
		dir := filepath.Join(install, versionsDir, v)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bomcensus-agent.exe"), []byte(v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := currentFromLink(root, install); err != nil || v != "" {
		t.Fatalf("no link: %q %v", v, err)
	}
	for _, v := range []string{"1.0.0", "1.1.0", "1.0.0"} {
		if err := replaceCurrentLink(root, install, v); err != nil {
			t.Fatalf("switch to %s: %v", v, err)
		}
		got, err := currentFromLink(root, install)
		if err != nil || got != v {
			t.Fatalf("current %q %v, want %s", got, err, v)
		}
		b, err := os.ReadFile(filepath.Join(install, currentName, "bomcensus-agent.exe"))
		if err != nil || string(b) != v {
			t.Fatalf("through the junction: %q %v", b, err)
		}
	}
	names, err := readDirNames(root, ".")
	if err != nil || len(names) != 2 {
		t.Fatalf("leftovers in the install directory: %v %v", names, err)
	}
}

func TestJunctionRefusesDirectory(t *testing.T) {
	install := t.TempDir()
	root, err := os.OpenRoot(install)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.MkdirAll(filepath.Join(install, currentName, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceCurrentLink(root, install, "1.0.0"); err == nil {
		t.Fatal("a non-empty directory was turned into a junction")
	}
	if _, err := currentFromLink(root, install); err == nil {
		t.Fatal("a plain directory was read as a link")
	}
}

func TestLockFileEx(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx := context.Background()
	f, err := lockFile(ctx, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(ctx, root, 0); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	f.Close()
	g, err := lockFile(ctx, root, 0)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	g.Close()
}
