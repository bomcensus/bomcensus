// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package updater

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// errNotRegular means a name does not refer to a regular file.
var errNotRegular = errors.New("not a regular file")

// openRegular opens name for reading only if it is a regular file and not a
// symlink. The O_NONBLOCK flag keeps a FIFO swapped in after the Lstat from
// blocking the open; the SameFile check rejects any swap.
func openRegular(root *os.Root, name string) (*os.File, error) {
	li, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		f.Close()
		return nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	return f, nil
}

// writeFileSync creates name exclusively with the given mode (not subject to
// the umask), writes data and syncs it.
func writeFileSync(root *os.Root, name string, data []byte, mode os.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

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

func randSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// lockFile takes an exclusive flock on <install>/updater.lock, retrying until
// wait has passed.
func lockFile(ctx context.Context, root *os.Root, wait time.Duration) (*os.File, error) {
	f, err := root.OpenFile(lockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", lockName, err)
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, ErrLocked
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
