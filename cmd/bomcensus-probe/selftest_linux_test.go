// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"encoding/json"
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
		Seccomp    int  `json:"seccomp"`
		NoNewPrivs bool `json:"no_new_privs"`
		Checks     []struct {
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
	for _, c := range res.Checks {
		if !c.OK {
			t.Errorf("check %s: %s", c.Name, c.Detail)
		}
	}
}
