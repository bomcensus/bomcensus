// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"fmt"

	"github.com/bomcensus/bomcensus/internal/sandbox"
)

// landlockABI returns the Landlock ABI version of the kernel, 0 when
// Landlock is not available.
func landlockABI() int { return sandbox.LandlockABI() }

// landlockStep records why Landlock is not applied to the probe (see
// sandbox.go). Version commands are put into a Landlock domain by the exec
// helper.
func landlockStep() SandboxStep {
	detail := "not available in the kernel"
	if abi := landlockABI(); abi > 0 {
		detail = fmt.Sprintf("ABI %d available", abi)
	}
	return SandboxStep{Name: "landlock", Status: StepSkipped,
		Detail: detail + "; not used: a Landlock domain cannot read /proc/<pid> of processes outside it, seccomp restricts writes instead"}
}
