// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// securePrivateDir sets mode 0700 on dir unless it has it already.
func securePrivateDir(dir string, fi os.FileInfo, _ string) error {
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("state: chmod %s: %w", dir, err)
		}
	}
	return nil
}

// lockFile takes a non-blocking exclusive flock on f.
func lockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrLocked
		}
		return fmt.Errorf("state: lock: %w", err)
	}
	return nil
}

func replaceFile(from, to string) error { return os.Rename(from, to) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("state: sync directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("state: sync directory: %w", err)
	}
	return nil
}
