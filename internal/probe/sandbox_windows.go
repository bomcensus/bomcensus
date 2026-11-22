// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

// The self-restriction of sandbox.go (privilege drop, no_new_privs,
// seccomp) and the memory re-execution of reexec.go have no Windows
// counterpart yet. The functions below keep the command's interface and
// report plainly that nothing was restricted.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows"
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

// CheckSandbox reports the one fact there is to check: the restrictions
// the Linux probe applies are absent.
func CheckSandbox(...string) []SandboxCheck {
	return []SandboxCheck{{Name: "sandbox", OK: false, Detail: "not available on Windows"}}
}

// EnsureExecutableAfterDrop does nothing on Windows: the probe does not
// change its account.
func EnsureExecutableAfterDrop(*slog.Logger) {}
