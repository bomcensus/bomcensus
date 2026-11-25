// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
)

// fakeIntegrityProbe answers integrity chunks: it walks numbered packages,
// stepsPerChunk at a time.
type fakeIntegrityProbe struct {
	mu            sync.Mutex
	packages      int
	stepsPerChunk int
	busy          bool
	requests      []report.Request
	block         chan struct{}
}

func (p *fakeIntegrityProbe) Collect(ctx context.Context, req *report.Request) (*report.Report, error) {
	p.mu.Lock()
	p.requests = append(p.requests, *req)
	block, busy := p.block, p.busy
	p.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	q := req.Integrity
	sec := &report.IntegritySection{PassID: q.PassID, Cursor: q.Cursor, UTCOffsetSeconds: 9 * 3600, Cache: []byte(`"c"`)}
	if busy {
		sec.Coverage = report.CoverageNone
		return &report.Report{SchemaVersion: 1, Integrity: sec}, nil
	}
	n := 0
	if q.Cursor != "" {
		n = int(q.Cursor[0] - '0')
	}
	n += p.stepsPerChunk
	if n >= p.packages {
		sec.PassDone, sec.Cursor = true, ""
	} else {
		sec.Cursor = string(rune('0' + n))
	}
	sec.Coverage = report.CoverageFull
	return &report.Report{SchemaVersion: 1, Integrity: sec}, nil
}

type integrityHarness struct {
	g       *integrityRunner
	probe   *fakeIntegrityProbe
	now     time.Time
	uploads [][]byte
}

func newIntegrityHarness(t *testing.T, probe *fakeIntegrityProbe) *integrityHarness {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &integrityHarness{probe: probe, now: time.Date(2026, 11, 25, 3, 0, 0, 0, time.UTC)}
	h.g = &integrityRunner{
		st: st, probe: probe, log: slog.New(slog.DiscardHandler), now: func() time.Time { return h.now },
		agentID: "agent-1", state: &state.Integrity{}, wake: make(chan struct{}, 1),
		policy: report.DefaultPolicy,
		submit: func(_ context.Context, b []byte, _ core.ReportMeta) error {
			h.uploads = append(h.uploads, bytes.Clone(b))
			return nil
		},
	}
	off := 0
	h.g.state.UTCOffset = &off
	return h
}

func integrityConfig(enabled bool) agentapi.AgentConfig {
	return agentapi.AgentConfig{Integrity: &agentapi.IntegrityConfig{
		Enabled: enabled, WindowStart: "02:00", WindowEnd: "05:00", IntervalDays: 1, MaxReadMbps: 20, FullRehashDays: 7,
	}}
}

func TestIntegrityDecide(t *testing.T) {
	if !integritySupported {
		t.Skip("integrity passes run on Linux only")
	}
	h := newIntegrityHarness(t, &fakeIntegrityProbe{packages: 3, stepsPerChunk: 1})
	g := h.g
	if p := g.decide(h.now); p.run || p.wait != 0 {
		t.Errorf("without config: %+v", p)
	}
	g.setConfig(context.Background(), integrityConfig(true))
	// The jittered start lies in the first half of 02:00..05:00.
	h.now = time.Date(2026, 11, 25, 4, 0, 0, 0, time.UTC)
	p := g.decide(h.now)
	if !p.run || !p.deadline.Equal(time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC)) {
		t.Fatalf("in the window: %+v", p)
	}
	h.now = time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC)
	if p := g.decide(h.now); p.run || p.wait <= 0 {
		t.Errorf("after the window: %+v", p)
	}
	// A pass started this night is not repeated the same night.
	g.state.LastStart = time.Date(2026, 11, 25, 2, 30, 0, 0, time.UTC)
	h.now = time.Date(2026, 11, 25, 4, 50, 0, 0, time.UTC)
	if p := g.decide(h.now); p.run {
		t.Errorf("second pass in one night: %+v", p)
	}
	// The next night it runs.
	h.now = time.Date(2026, 11, 26, 4, 0, 0, 0, time.UTC)
	if p := g.decide(h.now); !p.run {
		t.Errorf("next night: %+v", p)
	}
	// Too little time left.
	h.now = time.Date(2026, 11, 26, 4, 59, 0, 0, time.UTC)
	if p := g.decide(h.now); p.run {
		t.Errorf("a minute before the end: %+v", p)
	}
}

func TestIntegrityChunks(t *testing.T) {
	if !integritySupported {
		t.Skip("integrity passes run on Linux only")
	}
	h := newIntegrityHarness(t, &fakeIntegrityProbe{packages: 3, stepsPerChunk: 2})
	g := h.g
	g.setConfig(context.Background(), integrityConfig(true))
	deadline := time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC)
	if !g.chunk(context.Background(), deadline) {
		t.Fatal("first chunk made no progress")
	}
	first := h.probe.requests[0]
	if first.Integrity.Cursor != "" || !first.Integrity.FullRehash || first.Policy.MaxRuntimeSeconds != 2*3600 {
		t.Errorf("first request %+v policy %+v", first.Integrity, first.Policy)
	}
	if g.state.PassID == "" || g.state.Cursor != "2" {
		t.Fatalf("after one chunk: %+v", g.state)
	}
	pass := g.state.PassID
	if !g.chunk(context.Background(), deadline) {
		t.Fatal("second chunk made no progress")
	}
	second := h.probe.requests[1]
	if second.Integrity.PassID != pass || second.Integrity.Cursor != "2" || string(second.Integrity.Cache) != `"c"` {
		t.Errorf("second request %+v", second.Integrity)
	}
	if g.state.PassID != "" || g.state.LastDone.IsZero() || g.state.LastFull.IsZero() {
		t.Errorf("pass not finished: %+v", g.state)
	}
	if len(h.uploads) != 2 {
		t.Fatalf("%d uploads, want 2", len(h.uploads))
	}
	rep, err := report.Decode(bytes.NewReader(h.uploads[1]))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Integrity == nil || !rep.Integrity.PassDone || rep.Integrity.Cache != nil || rep.Subject == nil {
		t.Errorf("uploaded %+v", rep.Integrity)
	}
	// State survives a restart.
	s, err := g.st.LoadIntegrity()
	if err != nil || s.LastDone.IsZero() || s.UTCOffset == nil || *s.UTCOffset != 9*3600 {
		t.Errorf("stored state %+v, %v", s, err)
	}
	if c, _ := g.st.LoadIntegrityCache(); string(c) != `"c"` {
		t.Errorf("stored cache %s", c)
	}
	// The next pass within full_rehash_days trusts the cache.
	h.now = h.now.Add(24 * time.Hour)
	g.chunk(context.Background(), deadline.Add(24*time.Hour))
	if h.probe.requests[2].Integrity.FullRehash {
		t.Error("full rehash a day after the last one")
	}
}

func TestIntegrityBusyIsRetried(t *testing.T) {
	if !integritySupported {
		t.Skip("integrity passes run on Linux only")
	}
	h := newIntegrityHarness(t, &fakeIntegrityProbe{packages: 3, stepsPerChunk: 1, busy: true})
	h.g.setConfig(context.Background(), integrityConfig(true))
	if h.g.chunk(context.Background(), h.now.Add(time.Hour)) {
		t.Error("busy chunk counted as progress")
	}
	if len(h.uploads) != 0 {
		t.Error("busy chunk uploaded")
	}
	if h.g.state.PassID == "" || h.g.state.Cursor != "" {
		t.Errorf("state %+v", h.g.state)
	}
}

func TestIntegrityDisableCancels(t *testing.T) {
	if !integritySupported {
		t.Skip("integrity passes run on Linux only")
	}
	probe := &fakeIntegrityProbe{packages: 3, stepsPerChunk: 1, block: make(chan struct{})}
	h := newIntegrityHarness(t, probe)
	h.g.setConfig(context.Background(), integrityConfig(true))
	done := make(chan bool)
	go func() { done <- h.g.chunk(context.Background(), h.now.Add(time.Hour)) }()
	for {
		probe.mu.Lock()
		n := len(probe.requests)
		probe.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	h.g.setConfig(context.Background(), integrityConfig(false))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("chunk not cancelled")
	}
	if h.g.state.PassID != "" || len(h.uploads) != 0 {
		t.Errorf("after disable: %+v, %d uploads", h.g.state, len(h.uploads))
	}
	if p := h.g.decide(h.now); p.run {
		t.Error("runs while disabled")
	}
}
