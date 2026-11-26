// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package sandbox

import "golang.org/x/sys/unix"

const (
	// AuditArch is the architecture value of native system calls.
	AuditArch = unix.AUDIT_ARCH_X86_64
	// checkX32 kills x32 system calls, which share the architecture value
	// and would get around the numbers below.
	checkX32 = true
)

// archProbeRules covers the legacy path calls that amd64 still has besides
// the *at variants, and port I/O.
func archProbeRules(eacces uint32) []Rule {
	rules := []Rule{{Nr: unix.SYS_OPEN, Ret: eacces, Conds: []Cond{{Arg: 1, Op: AnyBits, K: openWriteFlags}}}}
	rules = append(rules, Deny(eacces,
		unix.SYS_CREAT, unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_UNLINK, unix.SYS_RENAME,
		unix.SYS_LINK, unix.SYS_SYMLINK, unix.SYS_MKNOD, unix.SYS_CHMOD, unix.SYS_CHOWN,
		unix.SYS_LCHOWN, unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT,
	)...)
	return append(rules, Deny(Errno(unix.EPERM), unix.SYS_IOPL, unix.SYS_IOPERM)...)
}

// archCommandRules denies the process creation calls besides clone, and
// two legacy calls with a history of kernel bugs.
func archCommandRules(eperm uint32) []Rule {
	return Deny(eperm, unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_MODIFY_LDT, unix.SYS_USELIB)
}
