// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// sandboxLogMarker is logged by a sandboxed collect run.
const sandboxLogMarker = "step=seccomp status=applied"

func TestSelfTest(t *testing.T) {
	out, stderr, code := runProbe(t, "", "self-test", "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	var res struct {
		Seccomp     int  `json:"seccomp"`
		NoNewPrivs  bool `json:"no_new_privs"`
		LandlockABI int  `json:"landlock_abi"`
		Checks      []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !res.NoNewPrivs {
		t.Error("no_new_privs not set")
	}
	if res.Seccomp != 2 {
		t.Skip("seccomp filters not available")
	}
	commands := 0
	for _, c := range res.Checks {
		if strings.HasPrefix(c.Name, "command: ") {
			commands++
		}
		switch {
		case c.OK:
		case res.LandlockABI == 0 && c.Name == "command: read another process's environment":
			// Without Landlock only the kernel's ptrace access rules
			// protect a dumpable process of the same user.
			t.Logf("check %s: %s", c.Name, c.Detail)
		default:
			t.Errorf("check %s: %s", c.Name, c.Detail)
		}
	}
	if commands == 0 {
		t.Error("version command sandbox not checked")
	}
}
