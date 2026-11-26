// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package sandbox

import "golang.org/x/sys/unix"

const (
	// AuditArch is the architecture value of native system calls.
	AuditArch = unix.AUDIT_ARCH_AARCH64
	checkX32  = false
)

// archProbeRules is empty: arm64 has only the *at variants of path calls.
func archProbeRules(uint32) []Rule { return nil }

// archCommandRules is empty: arm64 creates processes only through clone.
func archCommandRules(uint32) []Rule { return nil }
