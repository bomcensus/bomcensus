// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"encoding/json"
	"testing"
)

// sandboxLogMarker is logged by a collect run without --no-sandbox: there
// is no sandbox on Windows and the probe says so.
const sandboxLogMarker = "step=sandbox status=skipped"

func TestSelfTest(t *testing.T) {
	// The one check, the missing sandbox, fails.
	out, stderr, code := runProbe(t, "", "self-test", "--json")
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	var res struct {
		Steps []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"steps"`
		User   string `json:"user"`
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(res.Steps) != 1 || res.Steps[0].Status != "skipped" || res.User == "" {
		t.Errorf("self-test = %s", out)
	}
	if len(res.Checks) != 1 || res.Checks[0].OK {
		t.Errorf("checks = %+v", res.Checks)
	}
}
