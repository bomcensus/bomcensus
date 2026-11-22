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
	"time"
)

// errNotRegular means a name does not refer to a regular file.
var errNotRegular = errors.New("not a regular file")

// openRegular opens name for reading only if it is a regular file and not a
// symlink. The O_NONBLOCK flag (openNonblock, Unix only) keeps a FIFO swapped
// in after the Lstat from blocking the open; the SameFile check rejects any
// swap.
func openRegular(root *os.Root, name string) (*os.File, error) {
	li, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|openNonblock, 0)
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

func randSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// lockFile takes an exclusive lock on <install>/updater.lock (flock on Unix,
// LockFileEx on Windows), retrying until wait has passed.
func lockFile(ctx context.Context, root *os.Root, wait time.Duration) (*os.File, error) {
	f, err := root.OpenFile(lockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		locked, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", lockName, err)
		}
		if locked {
			return f, nil
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
