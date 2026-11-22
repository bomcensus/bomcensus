// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build windows

package updater

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// Windows has no FIFOs that could block an open.
const openNonblock = 0

// mkdirMode creates a directory. Mode bits have no meaning on Windows: the
// directory inherits the ACL of the install directory.
func mkdirMode(root *os.Root, name string, _ os.FileMode) error {
	return root.Mkdir(name, 0o755)
}

// syncDir does nothing on Windows. NTFS journals directory changes, and
// FlushFileBuffers on a directory needs a handle opened for writing.
func syncDir(*os.Root, string) error { return nil }

// tryLock takes a non-blocking exclusive LockFileEx lock on the first byte.
// The lock is released when the file is closed.
func tryLock(f *os.File) (bool, error) {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}

// readCurrentLink returns the target of the current junction.
func readCurrentLink(_ *os.Root, installAbs string) (string, error) {
	p := filepath.Join(installAbs, currentName)
	h, err := openReparse(p, 0)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, maxReparseData)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: err}
	}
	t, err := decodeReparse(buf[:n])
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: err}
	}
	return t, nil
}

// replaceCurrentLink points the current junction at versions\<v>. An
// existing junction is retargeted in place, which replaces the target in a
// single operation: a reader resolves either the old or the new version,
// never a missing link. Without a junction a new one is created under a
// temporary name and renamed into place.
func replaceCurrentLink(root *os.Root, installAbs, v string) error {
	target := filepath.Join(installAbs, versionsDir, v)
	data, err := encodeMountPoint(target)
	if err != nil {
		return fmt.Errorf("updater: %w", err)
	}
	cur := filepath.Join(installAbs, currentName)
	err = setReparse(cur, data)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_REPARSE_TAG_MISMATCH):
		// A symbolic link made by hand: replace it with a junction.
		if err := root.Remove(currentName); err != nil {
			return fmt.Errorf("updater: switch %s: %w", currentName, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("updater: switch %s: %w", currentName, err)
	}
	tmp := ".current.tmp-" + randSuffix()
	if err := root.Mkdir(tmp, 0o755); err != nil {
		return fmt.Errorf("updater: create link: %w", err)
	}
	if err := setReparse(filepath.Join(installAbs, tmp), data); err != nil {
		root.Remove(tmp)
		return fmt.Errorf("updater: create link: %w", err)
	}
	if err := root.Rename(tmp, currentName); err != nil {
		root.Remove(tmp)
		return fmt.Errorf("updater: switch %s: %w", currentName, err)
	}
	return nil
}

// setReparse sets the reparse data of an existing directory. A directory
// that is not a reparse point must be empty; one that is a junction gets its
// target replaced.
func setReparse(path string, data []byte) error {
	h, err := openReparse(path, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a directory", path)
	}
	var n uint32
	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &n, nil)
}

// openReparse opens path itself, not the target of a reparse point.
func openReparse(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

// renameDir renames a directory, retrying for a short time while another
// process (typically a virus scanner looking at the new executables) has a
// file in it open, which makes Windows refuse the rename.
func renameRetry(root *os.Root, oldname, newname string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := root.Rename(oldname, newname)
		if err == nil || !(errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)) ||
			time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
