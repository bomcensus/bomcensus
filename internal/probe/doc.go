// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package probe assembles one collection report from the collectors and
// restricts the probe process before it reads anything (see sandbox.go).
//
// Run collects the requested sections in the order host, packages,
// processes, artifacts, containers. Artifacts depend on the package owner
// index and on the running executables, so those are collected whenever
// artifacts are requested, even if their own sections are not emitted. The
// content of running containers is read through /proc/<pid>/root, once per
// image digest.
//
// On Windows nothing is collected yet: Run reports the host section and
// marks every other requested section as not collected (probe_windows.go).
// The sandbox of sandbox.go is Linux only.
package probe
