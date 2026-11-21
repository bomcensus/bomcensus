// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// landlockABI returns the Landlock ABI version of the kernel, 0 when
// Landlock is not available.
func landlockABI() int {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 || int(v) < 0 {
		return 0
	}
	return int(v)
}

// landlockStep records why Landlock is not applied (see sandbox.go).
func landlockStep() SandboxStep {
	detail := "not available in the kernel"
	if abi := landlockABI(); abi > 0 {
		detail = fmt.Sprintf("ABI %d available", abi)
	}
	return SandboxStep{Name: "landlock", Status: StepSkipped,
		Detail: detail + "; not used: a Landlock domain cannot read /proc/<pid> of processes outside it, seccomp restricts writes instead"}
}
