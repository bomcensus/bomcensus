// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/sandbox/sandboxtest"
)

// sandboxLogMarker is logged by a sandboxed collect run.
const sandboxLogMarker = "step=seccomp status=applied"

type selfTestResult struct {
	Steps []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"steps"`
	UID          int      `json:"uid"`
	Capabilities []string `json:"capabilities"`
	Seccomp      int      `json:"seccomp"`
	NoNewPrivs   bool     `json:"no_new_privs"`
	LandlockABI  int      `json:"landlock_abi"`
	Checks       []struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	} `json:"checks"`
}

func TestSelfTest(t *testing.T) {
	sc, inMatrix := sandboxtest.Current(t)
	out, stderr, code := runProbe(t, "", "self-test", "--json")
	var res selfTestResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("exit %d: %v\n%s\n%s", code, err, out, stderr)
	}
	if !res.NoNewPrivs {
		t.Error("no_new_privs not set")
	}
	if res.Seccomp != 2 {
		if inMatrix {
			t.Fatalf("seccomp filter not installed\n%s", out)
		}
		t.Skip("seccomp filters not available")
	}
	commands, failed, tolerated := 0, 0, 0
	for _, c := range res.Checks {
		if strings.HasPrefix(c.Name, "command: ") {
			commands++
		}
		switch {
		case c.OK:
		case !inMatrix && res.LandlockABI == 0 && c.Name == "command: read another process's environment":
			// Without Landlock only the kernel's ptrace access rules
			// protect a dumpable process of the same user.
			t.Logf("check %s: %s", c.Name, c.Detail)
			failed++
			tolerated++
		default:
			t.Errorf("check %s: %s", c.Name, c.Detail)
			failed++
		}
	}
	// A failed check fails the command.
	if (failed > 0) != (code == 1) || (failed == 0 && code != 0) {
		t.Errorf("exit %d with %d failed checks\n%s", code, failed, stderr)
	}
	if !inMatrix {
		if commands == 0 {
			t.Error("version command sandbox not checked")
		}
		return
	}

	if abi := sandboxtest.LandlockABI(t); res.LandlockABI != abi {
		t.Errorf("self-test reports Landlock ABI %d, %d available", res.LandlockABI, abi)
	}
	var priv string
	for _, s := range res.Steps {
		if s.Name == "privileges" {
			priv = s.Status
		}
	}
	readCaps := []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE"}
	switch sc.Privilege {
	case sandboxtest.RootKeep, sandboxtest.RootNoCaps:
		if priv != "kept" || res.UID != 0 {
			t.Errorf("privileges %s, uid %d; want kept, uid 0", priv, res.UID)
		}
	case sandboxtest.RootDrop:
		if priv != "applied" || res.UID != 65534 || !slices.Equal(res.Capabilities, readCaps) {
			t.Errorf("privileges %s, uid %d, capabilities %v; want applied, 65534, %v", priv, res.UID, res.Capabilities, readCaps)
		}
	case sandboxtest.User, sandboxtest.UserCaps:
		if priv != "skipped" || res.UID != os.Geteuid() {
			t.Errorf("privileges %s, uid %d; want skipped, uid %d", priv, res.UID, os.Geteuid())
		}
		if sc.Privilege == sandboxtest.UserCaps && !slices.Equal(res.Capabilities, readCaps) {
			t.Errorf("capabilities %v, want %v", res.Capabilities, readCaps)
		}
	}
	detail := func(name string) string {
		for _, c := range res.Checks {
			if c.Name == name {
				return c.Detail
			}
		}
		t.Errorf("no check %q", name)
		return ""
	}
	if !sc.CommandsRun() {
		if d := detail("version command"); !strings.HasPrefix(d, "not run") || commands != 0 {
			t.Errorf("version command: %q, %d checks from inside", d, commands)
		}
		return
	}
	if d := detail("version command"); !strings.HasPrefix(d, "ran") {
		t.Errorf("version command: %q", d)
	}
	uid := strconv.Itoa(sc.CommandUID())
	if d := detail("command: not root"); d != "uid "+strings.Repeat(uid+"/", 3)+uid {
		t.Errorf("command: not root: %q, want uid %s", d, uid)
	}
	if commands < 20 {
		t.Errorf("only %d checks from inside the version command", commands)
	}
}
