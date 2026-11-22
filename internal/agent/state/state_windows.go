// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/bomcensus/bomcensus/internal/platform/winacl"
)

// securePrivateDir gives dir a protected DACL with full control for
// LocalSystem, Administrators, the account of the process and the virtual
// account of service, inherited by every file in it. It is applied on every
// Open, because the mode check of other systems has no cheap equivalent.
func securePrivateDir(dir string, _ os.FileInfo, service string) error {
	var extra []*windows.SID
	if service != "" {
		sid, err := winacl.ServiceSID(service)
		if err != nil {
			return fmt.Errorf("state: service %s: %w", service, err)
		}
		extra = append(extra, sid)
	}
	if err := winacl.ProtectDir(dir, extra...); err != nil {
		return fmt.Errorf("state: restrict %s: %w", dir, err)
	}
	return nil
}

// lockFile takes a non-blocking exclusive LockFileEx lock on the first byte
// of f. Closing f releases it.
func lockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return ErrLocked
		}
		return fmt.Errorf("state: lock: %w", err)
	}
	return nil
}

// replaceFile renames from over to and returns once the change is on disk.
func replaceFile(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

// syncDir does nothing: a directory cannot be flushed on Windows, and
// replaceFile already waits for the rename to reach the disk.
func syncDir(string) error { return nil }
