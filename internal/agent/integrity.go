// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/nightwindow"
	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	// integrityRetry is the wait after a chunk that failed or found a
	// package manager at work, while the window lasts.
	integrityRetry = 10 * time.Minute
	// integrityIdleCheck bounds a wait between decisions, so that a clock
	// or zone change is noticed.
	integrityIdleCheck = 30 * time.Minute
	// integrityMinChunk is the least time left in a window for a chunk to
	// start.
	integrityMinChunk = 2 * time.Minute
	// integrityIntervalSlack lets a pass start earlier in the window than
	// the previous one did: the start is jittered every night.
	integrityIntervalSlack = 12 * time.Hour
)

// integritySupported is false where the probe cannot check package files.
var integritySupported = runtime.GOOS == "linux"

// integrityRunner runs the integrity passes of the agent's own host in the
// configured window, apart from the collection loop: a chunk can run for
// hours, and processes are still collected meanwhile.
type integrityRunner struct {
	st      *state.Dir
	probe   Prober
	log     *slog.Logger
	now     func() time.Time
	agentID string
	// policy returns the collection policy in use; submit uploads a report.
	policy func() report.Policy
	submit func(ctx context.Context, encoded []byte, meta core.ReportMeta) error

	mu     sync.Mutex
	cfg    *agentapi.IntegrityConfig
	state  *state.Integrity
	cache  []byte
	cancel context.CancelFunc
	wake   chan struct{}
}

func newIntegrityRunner(rt *core.Runtime, probe Prober, log *slog.Logger) (*integrityRunner, error) {
	st := rt.State()
	s, err := st.LoadIntegrity()
	if err != nil {
		return nil, err
	}
	cache, err := st.LoadIntegrityCache()
	if err != nil {
		return nil, err
	}
	g := &integrityRunner{
		st: st, probe: probe, log: log, now: time.Now, agentID: rt.AgentID(),
		state: s, cache: cache, wake: make(chan struct{}, 1),
		policy: func() report.Policy {
			if c, ok := rt.Config(); ok {
				return core.PolicyFromConfig(c.Policy)
			}
			return report.DefaultPolicy()
		},
		submit: rt.SubmitReport,
	}
	rt.OnConfig(g.setConfig)
	rt.AddTask(core.Task{
		Name:      "integrity",
		Interval:  func() time.Duration { return time.Minute },
		Immediate: true,
		Run:       g.loop,
	})
	return g, nil
}

func (g *integrityRunner) signal() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

func (g *integrityRunner) setConfig(_ context.Context, cfg agentapi.AgentConfig) {
	g.mu.Lock()
	g.cfg = cfg.Integrity
	if !g.enabledLocked() && g.state.PassID != "" {
		// Switched off: stop the chunk and forget the pass. A later pass
		// starts from the beginning.
		if g.cancel != nil {
			g.cancel()
		}
		g.state.PassID, g.state.Cursor, g.state.FullRehash = "", "", false
		s := *g.state
		g.mu.Unlock()
		if err := g.st.SaveIntegrity(&s); err != nil {
			g.log.Warn("store integrity state", "error", err)
		}
		g.signal()
		return
	}
	g.mu.Unlock()
	g.signal()
}

func (g *integrityRunner) enabledLocked() bool {
	return integritySupported && g.cfg != nil && g.cfg.Enabled
}

// plan is what the loop does next.
type plan struct {
	run      bool
	deadline time.Time     // when run: end of the window
	wait     time.Duration // when not run; 0 waits for a wake-up
}

// decide picks the next step at now. The caller holds mu.
func (g *integrityRunner) decide(now time.Time) plan {
	if !g.enabledLocked() {
		return plan{}
	}
	w, err := nightwindow.Parse(g.cfg.WindowStart, g.cfg.WindowEnd)
	if err != nil {
		g.log.Warn("integrity window ignored", "error", err)
		return plan{}
	}
	from, to := w.Around(now, nightwindow.Location(g.state.UTCOffset, time.Local))
	start := from.Add(nightwindow.Jitter(g.agentID, from, to.Sub(from)))
	interval := time.Duration(max(g.cfg.IntervalDays, 1)) * 24 * time.Hour
	if g.state.PassID == "" {
		if earliest := g.state.LastStart.Add(interval - integrityIntervalSlack); !g.state.LastStart.IsZero() && now.Before(earliest) {
			return plan{wait: min(earliest.Sub(now), integrityIdleCheck)}
		}
	}
	if now.Before(start) {
		return plan{wait: min(start.Sub(now), integrityIdleCheck)}
	}
	if to.Sub(now) < integrityMinChunk {
		return plan{wait: min(to.Sub(now)+time.Minute, integrityIdleCheck)}
	}
	return plan{run: true, deadline: to}
}

func (g *integrityRunner) loop(ctx context.Context) error {
	for ctx.Err() == nil {
		g.mu.Lock()
		p := g.decide(g.now())
		g.mu.Unlock()
		if p.run {
			if !g.chunk(ctx, p.deadline) {
				p = plan{wait: integrityRetry}
			} else {
				continue
			}
		}
		var timer <-chan time.Time
		var t *time.Timer
		if p.wait > 0 {
			t = time.NewTimer(p.wait)
			timer = t.C
		} else {
			t = time.NewTimer(integrityIdleCheck)
			timer = t.C
		}
		select {
		case <-ctx.Done():
		case <-g.wake:
		case <-timer:
		}
		t.Stop()
	}
	return nil
}

// chunk runs one probe chunk until deadline and submits its result. It
// returns false when the chunk made no progress (probe failure, package
// manager running) and should be retried later.
func (g *integrityRunner) chunk(ctx context.Context, deadline time.Time) bool {
	now := g.now()
	g.mu.Lock()
	cfg := *g.cfg
	if g.state.PassID == "" {
		full := cfg.FullRehashDays <= 0 || g.state.LastFull.IsZero() ||
			now.Sub(g.state.LastFull) >= time.Duration(cfg.FullRehashDays)*24*time.Hour
		g.state.PassID = newPassID()
		g.state.Cursor = ""
		g.state.FullRehash = full
		g.state.StartedAt = now
		g.state.LastStart = now
	}
	q := report.IntegrityQuery{
		PassID: g.state.PassID, Cursor: g.state.Cursor, FullRehash: g.state.FullRehash,
		MaxReadMBps: cfg.MaxReadMbps, Cache: g.cache,
	}
	if cfg.ExcludePaths != nil {
		q.ExcludePaths = slices.Clone(*cfg.ExcludePaths)
	}
	cctx, cancel := context.WithCancel(ctx)
	g.cancel = cancel
	s := *g.state
	g.mu.Unlock()
	defer cancel()
	if err := g.st.SaveIntegrity(&s); err != nil {
		g.log.Warn("store integrity state", "error", err)
	}

	limit := min(deadline.Sub(now), report.MaxIntegrityRuntimeSeconds*time.Second)
	policy := g.policy()
	policy.MaxRuntimeSeconds = int(limit / time.Second)
	req := &report.Request{Sections: []string{report.SectionIntegrity}, Policy: policy, Integrity: &q}
	g.log.Info("integrity chunk", "pass", q.PassID, "cursor", q.Cursor, "full_rehash", q.FullRehash, "limit", limit.Round(time.Second).String())
	rep, err := g.probe.Collect(cctx, req)
	if err != nil || rep.Integrity == nil {
		if cctx.Err() == nil {
			g.log.Error("integrity chunk failed", "error", err)
		}
		return false
	}
	sec := rep.Integrity
	progress := sec.PassDone || sec.Cursor != q.Cursor

	g.mu.Lock()
	if g.state.PassID != q.PassID {
		// Switched off meanwhile; the result belongs to a dropped pass.
		g.mu.Unlock()
		return true
	}
	if len(sec.Cache) > 0 {
		g.cache = sec.Cache
	}
	off := sec.UTCOffsetSeconds
	g.state.UTCOffset = &off
	if sec.PassDone {
		g.state.LastDone = g.now()
		if g.state.FullRehash {
			g.state.LastFull = g.state.LastDone
		}
		g.state.PassID, g.state.Cursor, g.state.FullRehash = "", "", false
	} else {
		g.state.Cursor = sec.Cursor
	}
	s = *g.state
	cache := g.cache
	g.mu.Unlock()
	if err := g.st.SaveIntegrityCache(cache); err != nil {
		g.log.Warn("store integrity cache", "error", err)
	}
	if err := g.st.SaveIntegrity(&s); err != nil {
		g.log.Warn("store integrity state", "error", err)
	}
	g.log.Info("integrity chunk finished", "pass", q.PassID, "done", sec.PassDone, "packages", sec.Packages,
		"checked", sec.Checked, "findings", len(sec.Findings), "coverage", sec.Coverage)

	if progress {
		sec.Cache = nil
		rep.Cache = nil
		rep.Subject = &report.Subject{Kind: report.SubjectSelf}
		var buf bytes.Buffer
		if err := report.Encode(&buf, rep); err != nil {
			g.log.Error("encode report", "error", err)
		} else if err := g.submit(ctx, buf.Bytes(), core.ReportMeta{}); err != nil && ctx.Err() == nil {
			g.log.Warn("report upload failed, kept in the spool", "error", err)
		}
	}
	return progress
}

func newPassID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("p%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
