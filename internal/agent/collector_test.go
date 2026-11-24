// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
)

// TestSetConfigWalkPaths checks that a change of the walk paths schedules
// the artifacts section right away, and that other changes do not.
func TestSetConfigWalkPaths(t *testing.T) {
	c := &collector{next: map[string]time.Time{}, manual: map[string]bool{}, wake: make(chan struct{}, 1)}
	cfg := func(paths ...string) agentapi.AgentConfig {
		var cfg agentapi.AgentConfig
		if paths != nil {
			cfg.Policy.WalkPaths = &paths
		}
		return cfg
	}
	ctx := context.Background()
	steps := []struct {
		cfg  agentapi.AgentConfig
		want bool
	}{
		{cfg("/opt"), false}, // the first configuration is the one in use
		{cfg("/opt"), false},
		{cfg("/opt", "/srv"), true},
		{cfg("/srv", "/opt"), false},
		{cfg(), true},
		{cfg(), false},
	}
	for i, s := range steps {
		c.manual = map[string]bool{}
		c.setConfig(ctx, s.cfg)
		if got := c.manual[report.SectionArtifacts]; got != s.want {
			t.Errorf("step %d: artifacts scheduled = %v, want %v", i, got, s.want)
		}
	}
}
