// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package updater

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const openNonblock = syscall.O_NONBLOCK

// mkdirMode creates a directory with exactly the given mode.
func mkdirMode(root *os.Root, name string, mode os.FileMode) error {
	if err := root.Mkdir(name, mode); err != nil {
		return err
	}
	d, err := root.Open(name)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Chmod(mode)
}

func syncDir(root *os.Root, name string) error {
	d, err := root.Open(name)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", name, err)
	}
	return nil
}

// tryLock takes a non-blocking exclusive flock. It reports false when
// another process holds it.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return false, err
}

// readCurrentLink returns the target of the current link as stored.
func readCurrentLink(root *os.Root, _ string) (string, error) {
	return root.Readlink(currentName)
}

// replaceCurrentLink points the current link at versions/<v> by renaming a
// new symlink over the old one, so a reader always sees one complete target.
func replaceCurrentLink(root *os.Root, _ string, v string) error {
	tmp := ".current.tmp-" + randSuffix()
	if err := root.Symlink(versionsDir+"/"+v, tmp); err != nil {
		return fmt.Errorf("updater: create link: %w", err)
	}
	if err := root.Rename(tmp, currentName); err != nil {
		root.Remove(tmp)
		return fmt.Errorf("updater: switch %s: %w", currentName, err)
	}
	return nil
}

// renameRetry renames a file or directory (see the Windows version).
func renameRetry(root *os.Root, oldname, newname string) error {
	return root.Rename(oldname, newname)
}
