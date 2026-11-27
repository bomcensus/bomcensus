// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
)

func detectorBlob(t *testing.T, extraID string) (*dto.DetectorTable, []byte, string) {
	t.Helper()
	tb := detectors.Builtin()
	tb.Detectors = append(tb.Detectors, report.DetectorSpec{ID: extraID, Name: extraID, Names: []string{extraID},
		Static: []report.DetectorStatic{{Rules: []report.DetectorRule{{Pattern: extraID + ` (\d+\.\d+)`}}}}})
	raw, err := detectors.Encode(tb)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := detectors.Digest(tb)
	return &dto.DetectorTable{Digest: d, Table: raw}, raw, d
}

func probeRequests(t *testing.T, h *harness) []string {
	t.Helper()
	b, err := os.ReadFile(h.reqFile)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// TestDetectorTableSync: the agent fetches the table when the digest of the
// configuration changes, keeps it, passes it to its probe (an older probe,
// the fake one, ignores it), refuses a table that does not match and drops
// the table when the server has none.
func TestDetectorTableSync(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	r := h.start(nil)
	h.wait("first poll", func() bool { return len(h.srv.Polls()) >= 1 })
	if p := lastPoll(h); p.DetectorsDigest == nil || *p.DetectorsDigest != "" {
		t.Fatalf("first poll digest %v", p.DetectorsDigest)
	}

	blob, raw, d1 := detectorBlob(t, "acme")
	h.srv.SetDetectors(blob)
	h.srv.SetConfig(func(c *dto.AgentConfig) { c.DetectorsDigest = &d1 })
	h.wait("table 1", func() bool { p := lastPoll(h); return p.DetectorsDigest != nil && *p.DetectorsDigest == d1 })
	h.wait("artifacts collected with the table", func() bool {
		for _, l := range probeRequests(t, h) {
			if strings.Contains(l, `"detectors":{"schema_version":1`) && strings.Contains(l, `"id":"acme"`) &&
				strings.Contains(l, `"artifacts"`) {
				return true
			}
		}
		return false
	})
	n := len(h.srv.Polls())
	h.wait("more polls", func() bool { return len(h.srv.Polls()) >= n+3 })
	if s := h.srv.DetectorSends(); s != 1 {
		t.Fatalf("table sent %d times", s)
	}
	stored, err := os.ReadFile(filepath.Join(h.stateDir, "detectors.json"))
	if err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("stored table: %v", err)
	}

	// A table that does not match its digest is refused once and not
	// asked for again; the probe gets no table.
	bad, _, d2 := detectorBlob(t, "other")
	bad.Table = append(bytes.Clone(bad.Table[:len(bad.Table)-1]), ' ', '\n')
	h.srv.SetDetectors(bad)
	h.srv.SetConfig(func(c *dto.AgentConfig) { c.DetectorsDigest = &d2 })
	h.wait("refused table remembered", func() bool { p := lastPoll(h); return p.DetectorsDigest != nil && *p.DetectorsDigest == d2 })
	n = len(h.srv.Polls())
	h.wait("more polls", func() bool { return len(h.srv.Polls()) >= n+3 })
	if s := h.srv.DetectorSends(); s != 2 {
		t.Fatalf("table sent %d times", s)
	}
	// The directive is acknowledged once queued; the run follows.
	runs := len(probeRequests(t, h))
	h.srv.Queue(map[string]any{"type": "collect", "id": "c1", "sections": []string{"artifacts"}})
	h.wait("collect acknowledged", func() bool { return h.srv.Acked("c1") })
	h.wait("collect run", func() bool { return len(probeRequests(t, h)) > runs })
	reqs := probeRequests(t, h)
	if last := reqs[len(reqs)-1]; strings.Contains(last, `"detectors"`) {
		t.Fatalf("refused table passed to the probe: %s", last)
	}

	// Back to table 1, then a restart: the stored table is used without
	// being sent again.
	h.srv.SetDetectors(blob)
	h.srv.SetConfig(func(c *dto.AgentConfig) { c.DetectorsDigest = &d1 })
	h.wait("table 1 again", func() bool { p := lastPoll(h); return p.DetectorsDigest != nil && *p.DetectorsDigest == d1 })
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	sends := h.srv.DetectorSends()
	n = len(h.srv.Polls())
	h.start(nil)
	h.wait("polls after restart", func() bool { return len(h.srv.Polls()) >= n+2 })
	if p := h.srv.Polls()[n]; p.DetectorsDigest == nil || *p.DetectorsDigest != d1 || h.srv.DetectorSends() != sends {
		t.Fatalf("after restart: digest %v, sends %d", p.DetectorsDigest, h.srv.DetectorSends()-sends)
	}

	// A server without detector tables: the table is dropped.
	h.srv.SetConfig(func(c *dto.AgentConfig) { c.DetectorsDigest = nil })
	h.wait("table dropped", func() bool { p := lastPoll(h); return p.DetectorsDigest != nil && *p.DetectorsDigest == "" })
	if _, err := os.Stat(filepath.Join(h.stateDir, "detectors.json")); !os.IsNotExist(err) {
		t.Fatalf("stored table left: %v", err)
	}
}

// TestSetConfigDetectors: another detector table collects artifacts and
// containers right away.
func TestSetConfigDetectors(t *testing.T) {
	c := &collector{next: map[string]time.Time{}, manual: map[string]bool{}, wake: make(chan struct{}, 1)}
	digest := func(s string) dto.AgentConfig {
		var cfg dto.AgentConfig
		if s != "" {
			cfg.DetectorsDigest = &s
		}
		return cfg
	}
	for i, s := range []struct {
		cfg  dto.AgentConfig
		want bool
	}{
		{digest(""), false}, {digest("a"), true}, {digest("a"), false}, {digest("b"), true}, {digest(""), true},
	} {
		c.manual = map[string]bool{}
		c.setConfig(context.Background(), s.cfg)
		if c.manual[report.SectionArtifacts] != s.want || c.manual[report.SectionContainers] != s.want {
			t.Errorf("step %d: scheduled %v", i, c.manual)
		}
	}
}
