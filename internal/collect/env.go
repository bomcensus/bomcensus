// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package collect holds what the collectors share: the environment they read
// from and the file hash cache. The collectors themselves live in the
// subpackages and only read; they never write to the file system or use the
// network.
package collect

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Env describes where a collector reads from and what it may do.
type Env struct {
	// Root is the file system root to inspect. "/" for the host; a container
	// is read through /proc/<pid>/root.
	Root string
	// Proc is the proc mount, normally "/proc". Tests point it at fixtures.
	Proc string
	// Policy bounds the work (version command execution, excluded paths).
	Policy report.Policy
	// Cache avoids re-hashing unchanged files. Never nil when built by NewEnv.
	Cache *HashCache
	// Privileged is true when the probe can read other users' processes.
	Privileged bool
	Log        *slog.Logger
}

// NewEnv returns an environment for the host with the default policy.
func NewEnv() *Env {
	return &Env{
		Root:   "/",
		Proc:   "/proc",
		Policy: report.DefaultPolicy(),
		Cache:  NewHashCache(),
		Log:    slog.New(slog.DiscardHandler),
	}
}

// WithRoot returns a copy of e that inspects another root, sharing the cache.
func (e *Env) WithRoot(root string) *Env {
	c := *e
	c.Root = root
	return &c
}

// Path maps an absolute path inside the inspected file system to the path to
// open. Collectors report the logical path and open the mapped one.
func (e *Env) Path(logical string) string {
	if e.Root == "" || e.Root == "/" {
		return logical
	}
	return filepath.Join(e.Root, logical)
}

// Logical is the inverse of Path.
func (e *Env) Logical(real string) string {
	if e.Root == "" || e.Root == "/" {
		return real
	}
	rel := strings.TrimPrefix(real, strings.TrimSuffix(e.Root, "/"))
	if rel == "" {
		return "/"
	}
	return rel
}

// Open opens a logical path for reading.
func (e *Env) Open(logical string) (*os.File, error) {
	return os.Open(e.Path(logical))
}
