// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/bomcensus/bomcensus/internal/detectors"
)

var errDeniedSideFile = errors.New("side file not allowed")

// openSideConstrained opens a side file for a detector that is not built in
// (SECURITY.md, detector tables). The path must not be denied
// (detectors.DeniedPath), and it is opened one component at a time from the
// inspected root without following any symbolic link, so that the file
// opened is the file at that path and nothing it points to. The opened file
// must be a regular file.
func (c *collector) openSideConstrained(logical string) (*os.File, error) {
	if !strings.HasPrefix(logical, "/") || detectors.DeniedPath(logical) {
		return nil, errDeniedSideFile
	}
	parts := strings.Split(strings.TrimPrefix(logical, "/"), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, errDeniedSideFile
		}
	}
	dir, err := syscall.Open(c.env.Path("/"), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, p := range parts[:len(parts)-1] {
		next, err := syscall.Openat(dir, p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(dir)
		if err != nil {
			return nil, err
		}
		dir = next
	}
	fd, err := syscall.Openat(dir, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	syscall.Close(dir)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), logical)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, os.ErrInvalid
	}
	return f, nil
}
