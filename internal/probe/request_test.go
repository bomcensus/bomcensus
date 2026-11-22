// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestDecodeRequest(t *testing.T) {
	def := report.DefaultPolicy()
	for _, in := range []string{"", "  \n", "{}"} {
		req, err := DecodeRequest(strings.NewReader(in))
		if err != nil || len(req.Sections) != 0 || req.Policy.ExecVersion != def.ExecVersion ||
			req.Policy.CollectCmdline != def.CollectCmdline || req.Policy.ScanContainers != def.ScanContainers {
			t.Errorf("%q: %+v, %v", in, req, err)
		}
	}
	req, err := DecodeRequest(strings.NewReader(`{"sections":["host"],"policy":{"exec_version":false,"max_runtime_seconds":5}}`))
	if err != nil || !req.Policy.CollectCmdline || req.Policy.ExecVersion || req.Policy.MaxRuntimeSeconds != 5 || req.Sections[0] != "host" {
		t.Errorf("partial policy: %+v, %v", req, err)
	}
	for _, bad := range []string{"{", `{"sections":"host"}`, `{} {}`} {
		if _, err := DecodeRequest(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	big := bytes.Repeat([]byte(" "), MaxRequestSize+1)
	if _, err := DecodeRequest(bytes.NewReader(big)); err == nil {
		t.Error("oversized request accepted")
	}
}

func TestWantedSections(t *testing.T) {
	if _, err := Run(context.Background(), report.Request{Sections: []string{"nope"}}, Options{}); err == nil {
		t.Error("request without a known section accepted")
	}
}
