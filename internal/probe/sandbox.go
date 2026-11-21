// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

// Self-restriction (SECURITY.md 6.2).
//
// The probe parses untrusted files while it can read everything. Before it
// reads anything it restricts itself, in this order, each step best effort:
//
//  1. privileges: started as root with CAP_DAC_READ_SEARCH and
//     CAP_SYS_PTRACE available, it keeps only those two (effective and
//     permitted; the bounding set is reduced to them) and switches to
//     uid/gid 65534 without supplementary groups. Root without them (a
//     container with the default capability set) stays uid 0 with its
//     capabilities unchanged, see keepRoot. Started as another user, it
//     keeps what it was given.
//  2. no_new_privs on every thread.
//  3. seccomp: a deny list returning an errno (see sandbox_seccomp.go). It
//     also denies every way of writing to, creating, removing or renaming a
//     path, and creating network sockets.
//
// Landlock is not used. A Landlock domain applies Landlock's ptrace
// restriction: a process inside a domain may not access processes outside
// it, which includes /proc/<pid>/{exe,maps,fd,root}. Every other process
// on the host is outside the probe's domain, so process and container
// collection would see nothing. The seccomp filter covers the file system
// and network restrictions instead, also on kernels without Landlock.
//
// The filter and no_new_privs are inherited by every child, including the
// version commands started through the exec helper.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Step outcomes.
const (
	StepApplied = "applied"
	StepPartial = "partial"
	StepSkipped = "skipped"
	// StepKept means the step deliberately left the state as it was.
	StepKept   = "kept"
	StepFailed = "failed"
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
	UID   int           `json:"uid"`
	GID   int           `json:"gid"`
	// Groups are the supplementary groups after the restriction.
	Groups []int `json:"groups"`
	// Capabilities are the effective capabilities after the restriction.
	Capabilities []string `json:"capabilities"`
	// Bounding is the capability bounding set after the restriction.
	Bounding []string `json:"bounding"`
	// Ambient is the ambient capability set after the restriction.
	Ambient     []string `json:"ambient"`
	NoNewPrivs  bool     `json:"no_new_privs"`
	LandlockABI int      `json:"landlock_abi"`
	// Seccomp is the seccomp mode of the process (2 = filter).
	Seccomp int `json:"seccomp"`
}

// String renders the result for humans.
func (r *SandboxResult) String() string {
	var b strings.Builder
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "%-14s %-8s %s\n", s.Name, s.Status, s.Detail)
	}
	fmt.Fprintf(&b, "uid=%d gid=%d groups=%v\n", r.UID, r.GID, r.Groups)
	fmt.Fprintf(&b, "effective capabilities: %s\n", listOrNone(r.Capabilities))
	fmt.Fprintf(&b, "bounding set:           %s\n", listOrNone(r.Bounding))
	fmt.Fprintf(&b, "ambient set:            %s\n", listOrNone(r.Ambient))
	fmt.Fprintf(&b, "no_new_privs=%v landlock_abi=%d seccomp_mode=%d\n", r.NoNewPrivs, r.LandlockABI, r.Seccomp)
	return b.String()
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ",")
}

// ApplySandbox restricts the calling process for the rest of its life. It
// never fails as a whole; every step is logged and reported.
func ApplySandbox(log *slog.Logger) *SandboxResult {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	res := &SandboxResult{}
	add := func(s SandboxStep) {
		res.Steps = append(res.Steps, s)
		lvl := slog.LevelInfo
		if s.Status == StepFailed || s.Status == StepPartial {
			lvl = slog.LevelWarn
		}
		log.Log(context.Background(), lvl, "sandbox", "step", s.Name, "status", s.Status, "detail", s.Detail)
	}
	add(restrictPrivileges())
	add(setNoNewPrivs())
	add(landlockStep())
	add(applySeccomp())
	res.observe()
	return res
}

// observe fills the state after the restrictions from the kernel's view.
func (r *SandboxResult) observe() {
	r.UID, r.GID = os.Geteuid(), os.Getegid()
	r.Groups, _ = os.Getgroups()
	if r.Groups == nil {
		r.Groups = []int{}
	}
	if caps, err := currentCaps(); err == nil {
		r.Capabilities = caps.effective.names()
		r.Bounding = caps.bounding.names()
		r.Ambient = caps.ambient.names()
	}
	if b, err := os.ReadFile("/proc/thread-self/status"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "NoNewPrivs":
				r.NoNewPrivs = v == "1"
			case "Seccomp":
				fmt.Sscan(v, &r.Seccomp)
			}
		}
	}
	r.LandlockABI = landlockABI()
}
