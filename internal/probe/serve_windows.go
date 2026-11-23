// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

// Host root mode and the socket listener serve the Kubernetes node agent,
// which runs on Linux nodes only.

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"time"
)

var errLinuxOnly = errors.New("only available on Linux")

// ServeOptions configures Serve.
type ServeOptions struct {
	Socket         string
	SocketMode     fs.FileMode
	AllowUIDs      []int
	MaxConnections int
	MaxRuntime     time.Duration
	Exe            string
	Args           []string
	Env            []string
	Stderr         io.Writer
	Sandbox        bool
	Log            *slog.Logger
	Ready          func()
}

// Serve defaults.
const (
	DefaultServeConnections = 4
	DefaultServeRuntime     = 20 * time.Minute
)

// Serve is not available on Windows.
func Serve(context.Context, ServeOptions) error { return errLinuxOnly }

// EnterHostRoot is not available on Windows.
func EnterHostRoot(string) error { return errLinuxOnly }

// VerifyHostRootSandbox is not available on Windows.
func VerifyHostRootSandbox(*SandboxResult) error { return errLinuxOnly }
