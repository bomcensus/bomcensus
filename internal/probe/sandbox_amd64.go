// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	// checkX32 kills x32 system calls, which share the architecture value
	// and would get around the numbers below.
	checkX32 = true
)

// archRules covers the legacy path calls that amd64 still has besides the
// *at variants, and port I/O.
func archRules(eacces uint32) []rule {
	rules := []rule{{nr: unix.SYS_OPEN, ret: eacces, arg: 1, mask: openWriteFlags}}
	rules = append(rules, deny(eacces,
		unix.SYS_CREAT, unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_UNLINK, unix.SYS_RENAME,
		unix.SYS_LINK, unix.SYS_SYMLINK, unix.SYS_MKNOD, unix.SYS_CHMOD, unix.SYS_CHOWN,
		unix.SYS_LCHOWN, unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT,
	)...)
	return append(rules, deny(errnoRet(unix.EPERM), unix.SYS_IOPL, unix.SYS_IOPERM)...)
}
