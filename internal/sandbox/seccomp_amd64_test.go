// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package sandbox

import "golang.org/x/sys/unix"

func archCommandCases() []filterCase {
	return []filterCase{
		{"fork", unix.SYS_FORK, nil, eperm},
		{"vfork", unix.SYS_VFORK, nil, eperm},
		{"modify_ldt", unix.SYS_MODIFY_LDT, nil, eperm},
		{"open write", unix.SYS_OPEN, []uint64{0, unix.O_WRONLY}, eacces},
		{"open read", unix.SYS_OPEN, []uint64{0, unix.O_RDONLY}, RetAllow},
	}
}
