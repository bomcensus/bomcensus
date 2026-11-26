// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

// The self-restriction of sandbox.go (privilege drop, no_new_privs,
// seccomp) and the memory re-execution of reexec.go have no Windows
// counterpart yet. The functions below keep the command's interface and
// report plainly that nothing was restricted. Version commands have their
// own sandbox (internal/sandbox), which CheckSandbox checks.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/bomcensus/bomcensus/internal/sandbox"
)

// Step outcomes.
const (
	StepApplied = "applied"
	StepPartial = "partial"
	StepSkipped = "skipped"
	StepKept    = "kept"
	StepFailed  = "failed"
)

// SandboxStep is the outcome of one restriction.
type SandboxStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SandboxResult summarizes what took effect.
type SandboxResult struct {
	Steps []SandboxStep `json:"steps"`
	// User is the account the process runs as (DOMAIN\name).
	User     string `json:"user"`
	Elevated bool   `json:"elevated"`
}

// SandboxCheck is the result of trying one operation after the sandbox was
// applied.
type SandboxCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

const noSandbox = "no process sandbox on Windows; the probe keeps every privilege of the account that started it"

// String renders the result for humans.
func (r *SandboxResult) String() string {
	var b strings.Builder
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "%-14s %-8s %s\n", s.Name, s.Status, s.Detail)
	}
	fmt.Fprintf(&b, "user=%s elevated=%v\n", r.User, r.Elevated)
	return b.String()
}

// ApplySandbox restricts nothing on Windows and says so.
func ApplySandbox(log *slog.Logger) *SandboxResult {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	res := &SandboxResult{Steps: []SandboxStep{{Name: "sandbox", Status: StepSkipped, Detail: noSandbox}}}
	log.Log(context.Background(), slog.LevelWarn, "sandbox", "step", "sandbox", "status", StepSkipped, "detail", noSandbox)
	tok := windows.GetCurrentProcessToken()
	res.Elevated = tok.IsElevated()
	if u, err := tok.GetTokenUser(); err == nil {
		if acct, dom, _, err := u.User.Sid.LookupAccount(""); err == nil {
			res.User = dom + `\` + acct
		} else {
			res.User = u.User.Sid.String()
		}
	}
	return res
}

// CheckSandbox reports that the restrictions the Linux probe applies to
// itself are absent, and runs the own binary as a version command, which
// tries from inside what the command sandbox must deny
// (sandbox.CheckCommand).
func CheckSandbox(...string) []SandboxCheck {
	return append([]SandboxCheck{{Name: "sandbox", OK: false, Detail: "not available on Windows"}}, checkCommands()...)
}

func checkCommands() []SandboxCheck {
	const name = "version command"
	exe, err := os.Executable()
	if err != nil {
		return []SandboxCheck{{Name: name, Detail: err.Error()}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	checks, err := sandbox.CheckCommand(ctx, exe, 512, sandbox.CheckTargets{MemoryMB: 1024})
	if err != nil {
		return []SandboxCheck{{Name: name, Detail: err.Error() + " (the probe's directory must grant ALL APPLICATION PACKAGES " +
			"read and execute, as Program Files does)"}}
	}
	out := []SandboxCheck{{Name: name, OK: true, Detail: "ran"}}
	for _, c := range checks {
		out = append(out, SandboxCheck{Name: "command: " + c.Name, OK: c.OK, Detail: c.Detail})
	}
	return out
}

// EnsureExecutableAfterDrop does nothing on Windows: the probe does not
// change its account.
func EnsureExecutableAfterDrop(*slog.Logger) {}
