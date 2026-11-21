// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package artifact

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect"
)

// TestCollectSystem runs a full collection of the real root when
// BOMCENSUS_TEST_SYSTEM is set, and logs the software found. It is meant to
// be run inside a container image while writing detectors.
func TestCollectSystem(t *testing.T) {
	if os.Getenv("BOMCENSUS_TEST_SYSTEM") == "" {
		t.Skip("BOMCENSUS_TEST_SYSTEM is not set")
	}
	env := collect.NewEnv()
	sec := Collect(context.Background(), env, Inputs{})
	t.Logf("coverage %s %q, %d artifacts, %d ms", sec.Coverage, sec.Reason, len(sec.Artifacts), sec.DurationMs)
	for _, a := range sec.Artifacts {
		if a.Kind == "go_module" {
			continue
		}
		a.Nested = a.Nested[:min(len(a.Nested), 2)]
		b, _ := json.Marshal(a)
		t.Logf("%s", b)
	}
}
