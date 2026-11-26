// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux && !amd64 && !arm64

package sandbox

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Supported reports whether filters can be built for this architecture.
const Supported = false

var errUnsupported = errors.New("seccomp filters are not built for this architecture")

// CommandFilter fails: version commands are not run on this architecture.
func CommandFilter(int) ([]unix.SockFilter, error) { return nil, errUnsupported }

// Install fails on this architecture.
func Install([]unix.SockFilter, bool) error { return errUnsupported }
