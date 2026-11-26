// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

// Package sandboxtest holds what the tests expect in each privilege
// scenario that scripts/sandbox-matrix.sh runs them in. It is imported by
// tests only.
//
// Environment:
//
//	BOMCENSUS_SANDBOX_SCENARIO   name of the scenario (see scenarios)
//	BOMCENSUS_TEST_LANDLOCK_ABI  Landlock ABI the kernel offers, as seen
//	                             outside any container; the tests fail when
//	                             the ABI they see differs
package sandboxtest

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	"github.com/bomcensus/bomcensus/internal/sandbox"
)

// Environment variables set by scripts/sandbox-matrix.sh.
const (
	EnvScenario    = "BOMCENSUS_SANDBOX_SCENARIO"
	EnvLandlockABI = "BOMCENSUS_TEST_LANDLOCK_ABI"
)

// Privilege classes: what the probe starts with.
const (
	// RootKeep is root with CAP_SETUID and CAP_SETGID but without
	// CAP_DAC_READ_SEARCH or CAP_SYS_PTRACE (Docker's default set): the
	// probe stays root, version commands run as 65534.
	RootKeep = "root-keep"
	// RootDrop is root with both read capabilities: the probe switches to
	// 65534 and keeps only them; version commands run as 65534.
	RootDrop = "root-drop"
	// RootNoCaps is root without capabilities: version commands are not
	// run and static extraction is used.
	RootNoCaps = "root-nocaps"
	// User is a non-root user without capabilities: version commands run
	// as that user.
	User = "user"
	// UserCaps is a non-root user with CAP_DAC_READ_SEARCH and
	// CAP_SYS_PTRACE as ambient capabilities, as the systemd unit starts
	// the probe: they are kept, version commands run as that user without
	// capabilities.
	UserCaps = "user-caps"
)

// Scenario is one row of the matrix.
type Scenario struct {
	Name      string
	Privilege string
	// NetNS is true when version commands must get a new network
	// namespace (root with CAP_SYS_ADMIN, and clone permitted).
	NetNS bool
}

var scenarios = []Scenario{
	{"root-default", RootKeep, false},
	{"root-drop", RootDrop, false},
	{"root-nocaps", RootNoCaps, false},
	{"user", User, false},
	{"root-sysadmin", RootKeep, true},
	{"host-root", RootDrop, true},
	{"host-unit", UserCaps, false},
	{"host-nocaps", RootNoCaps, false},
	{"host-user", User, false},
}

// Current returns the scenario named by BOMCENSUS_SANDBOX_SCENARIO, and
// false when the variable is not set (a plain go test run). An unknown
// name fails the test.
func Current(t testing.TB) (Scenario, bool) {
	t.Helper()
	name := os.Getenv(EnvScenario)
	if name == "" {
		return Scenario{}, false
	}
	for _, s := range scenarios {
		if s.Name == name {
			return s, true
		}
	}
	t.Fatalf("%s=%q: unknown scenario", EnvScenario, name)
	return Scenario{}, false
}

// CommandsRun reports whether version commands are executed.
func (s Scenario) CommandsRun() bool { return s.Privilege != RootNoCaps }

// Root reports whether the scenario starts as root.
func (s Scenario) Root() bool {
	return s.Privilege == RootKeep || s.Privilege == RootDrop || s.Privilege == RootNoCaps
}

// CommandUID is the uid version commands run as, given the uid of the
// process that starts them when it is not root.
func (s Scenario) CommandUID() int {
	if s.Root() {
		return 65534
	}
	return os.Getuid()
}

// LandlockABI returns the ABI the kernel offers to this process, and fails
// the test when BOMCENSUS_TEST_LANDLOCK_ABI is set to another value: a
// container runtime or a seccomp profile that hides Landlock must not let
// the tests pass with the Landlock checks relaxed.
func LandlockABI(t testing.TB) int {
	t.Helper()
	abi := sandbox.LandlockABI()
	want := os.Getenv(EnvLandlockABI)
	if want == "" {
		t.Logf("Landlock ABI %d", abi)
		return abi
	}
	n, err := strconv.Atoi(want)
	if err != nil {
		t.Fatalf("%s=%q: %v", EnvLandlockABI, want, err)
	}
	if abi != n {
		t.Errorf("Landlock ABI %d here, %d expected (%s)", abi, n, EnvLandlockABI)
	} else {
		t.Logf("Landlock ABI %d (expected)", abi)
	}
	return abi
}

// HideGoBuildInfo returns a copy of the Go executable data whose build
// information cannot be found. The artifact collector never runs version
// commands of Go binaries (their build information identifies them), so a
// Go program that stands in for other software in the tests needs this.
// The program itself still runs.
func HideGoBuildInfo(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\xff Go buildinf:"), []byte("\xff no buildinf:"))
}
