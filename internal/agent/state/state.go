// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package state keeps the persistent state of an agent or scanner in one
// directory: enrollment parameters, identity key and certificate, trust
// bundle, message counter, last server configuration, section digests,
// probe cache and the report spool.
//
// Every file is written atomically (temporary file, fsync, rename, fsync of
// the directory). The directory is created with mode 0700 and locked with
// flock so that two processes never share a counter. On Windows the
// directory gets a protected DACL instead of the mode (see
// internal/platform/winacl), the lock is LockFileEx and the rename is a
// write-through MoveFileEx.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bomcensus/bomcensus/internal/platform/paths"
)

// DefaultDir is the state directory of the host agent.
var DefaultDir = paths.AgentStateDir()

// File names inside the state directory.
const (
	lockName       = "lock"
	enrollmentName = "enrollment.json"
	identityName   = "identity.pem"
	nextKeyName    = "identity-next.pem"
	bundleName     = "trust-bundle.pem"
	extraRootsName = "tls-roots.pem"
	counterName    = "counter"
	configName     = "server-config.json"
	sectionsName   = "sections.json"
	cacheName      = "probe-cache.json"
	revokedName    = "revoked.json"
	spoolName      = "spool"
)

// ErrLocked is returned by Open when another process holds the directory.
var ErrLocked = errors.New("state: directory is in use by another process")

// Dir is an open state directory.
type Dir struct {
	path string
	lock *os.File
}

// Open creates path if needed (mode 0700), takes an exclusive lock on it and
// then tightens its mode. The lock is released by Close or when the process
// exits or executes another program. On Windows a directory that needs a new
// DACL is refused unless it was just created, is empty or already has the
// lock file of an earlier Open.
func Open(path string) (*Dir, error) { return OpenAs(path, "") }

// OpenAs is Open for the state directory of a Windows service: on Windows
// the DACL also grants the service's virtual account (NT SERVICE\<service>),
// so that an administrator may run a command such as enroll on the
// directory the service uses. On other systems service is ignored.
func OpenAs(path, service string) (*Dir, error) {
	if path == "" {
		return nil, errors.New("state: directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	_, err = os.Lstat(abs)
	created := errors.Is(err, fs.ErrNotExist)
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("state: create %s: %w", abs, err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("state: %s is not a directory", abs)
	}
	lockPath := filepath.Join(abs, lockName)
	_, err = os.Lstat(lockPath)
	hadLock := err == nil
	// A directory is known to be a state directory when it was just
	// created, was opened before (it has the lock file) or is empty.
	known := created || hadLock
	if !known {
		if known, err = isEmptyDir(abs); err != nil {
			return nil, fmt.Errorf("state: %w", err)
		}
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: open lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	// Permissions change only under the lock, so that a process that fails
	// with ErrLocked leaves the directory of the running one alone.
	if err := securePrivateDir(abs, fi, service, known); err != nil {
		f.Close()
		if !hadLock {
			os.Remove(lockPath)
		}
		return nil, err
	}
	return &Dir{path: abs, lock: f}, nil
}

func isEmptyDir(dir string) (bool, error) {
	d, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer d.Close()
	_, err = d.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}

// Path returns the absolute directory path.
func (d *Dir) Path() string { return d.path }

// Close releases the lock.
func (d *Dir) Close() error {
	if d.lock == nil {
		return nil
	}
	err := d.lock.Close()
	d.lock = nil
	return err
}

// ReadFile reads a file of the directory. A missing file yields an error
// matching fs.ErrNotExist.
func (d *Dir) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.path, name))
}

// WriteFile replaces a file of the directory atomically.
func (d *Dir) WriteFile(name string, data []byte, perm os.FileMode) error {
	return WriteFileAtomic(filepath.Join(d.path, name), data, perm)
}

// Remove deletes a file of the directory; a missing file is not an error.
func (d *Dir) Remove(name string) error {
	err := os.Remove(filepath.Join(d.path, name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: remove %s: %w", name, err)
	}
	return syncDir(d.path)
}

// readJSON decodes a file into v. It reports false when the file is absent.
func (d *Dir) readJSON(name string, v any) (bool, error) {
	b, err := d.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("state: read %s: %w", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("state: decode %s: %w", name, err)
	}
	return true, nil
}

func (d *Dir) writeJSON(name string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("state: encode %s: %w", name, err)
	}
	return d.WriteFile(name, append(b, '\n'), perm)
}

// WriteFileAtomic writes data to a temporary file next to path, syncs it,
// renames it over path and syncs the directory. perm is applied exactly.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp := filepath.Join(dir, "."+base+".tmp-"+randSuffix())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("state: write %s: %w", base, err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("state: write %s: %w", base, err)
	}
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("state: chmod %s: %w", base, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("state: sync %s: %w", base, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("state: close %s: %w", base, err)
	}
	if err := replaceFile(tmp, path); err != nil {
		return fmt.Errorf("state: rename %s: %w", base, err)
	}
	ok = true
	return syncDir(dir)
}

func randSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
