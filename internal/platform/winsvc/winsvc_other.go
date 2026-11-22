// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package winsvc

import (
	"context"
	"io"
)

// IsService reports whether the process was started by the Windows service
// control manager. It is always false here.
func IsService() bool { return false }

// Run is not supported on this system.
func Run(string, func(context.Context) error, func(context.Context) error) error {
	return ErrUnsupported
}

// EventLog is not supported on this system.
func EventLog(string) (io.WriteCloser, error) { return nil, ErrUnsupported }
