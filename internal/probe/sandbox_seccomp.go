// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux && (amd64 || arm64)

package probe

// The rules of the probe's filter are in internal/sandbox (rules.go), shared
// with the exec helper of version commands, which installs them again with
// its own additions.

import (
	"fmt"

	"github.com/bomcensus/bomcensus/internal/sandbox"
)

func applySeccomp() SandboxStep { return applySeccompRules(sandbox.ProbeRules()) }

func applySeccompRules(rules []sandbox.Rule) SandboxStep {
	step := SandboxStep{Name: "seccomp"}
	prog, err := sandbox.Build(rules)
	if err != nil {
		step.Status = StepFailed
		step.Detail = err.Error()
		return step
	}
	if err := sandbox.Install(prog, true); err != nil {
		step.Status = StepFailed
		step.Detail = err.Error()
		return step
	}
	step.Status = StepApplied
	step.Detail = fmt.Sprintf("%d system calls restricted (%d instructions), all threads", len(rules), len(prog))
	return step
}
