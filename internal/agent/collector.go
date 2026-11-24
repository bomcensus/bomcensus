// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/report/reportapi"
)

// Prober produces a report for a request (probeexec.Invoker).
type Prober interface {
	Collect(ctx context.Context, req *report.Request) (*report.Report, error)
}

// failureRetry is the wait before sections are retried after a failed run.
const failureRetry = 5 * time.Minute

// collector schedules sections, runs the probe one run at a time and
// submits the reports.
type collector struct {
	rt    *core.Runtime
	st    *state.Dir
	probe Prober
	log   *slog.Logger
	now   func() time.Time

	mu        sync.Mutex
	sections  *state.Sections
	cache     json.RawMessage
	privilege *report.Privilege
	cfg       *agentapi.AgentConfig
	next      map[string]time.Time
	manual    map[string]bool
	manualAll bool
	full      bool
	// symbols is the Go symbol query waiting to be answered, the latest
	// one received.
	symbols *report.GoSymbolQuery
	wake    chan struct{}
}

func newCollector(rt *core.Runtime, probe Prober, log *slog.Logger) (*collector, error) {
	st := rt.State()
	secs, err := st.LoadSections()
	if err != nil {
		return nil, err
	}
	cache, err := st.LoadProbeCache()
	if err != nil {
		return nil, err
	}
	c := &collector{
		rt: rt, st: st, probe: probe, log: log, now: time.Now,
		sections: secs, cache: cache,
		next:   map[string]time.Time{},
		manual: map[string]bool{},
		wake:   make(chan struct{}, 1),
	}
	rt.OnConfig(c.setConfig)
	rt.OnStatus(c.status)
	rt.OnUploaded(c.uploaded)
	rt.Handle("collect", c.handleCollect)
	rt.Handle("go_symbols", c.handleGoSymbols)
	rt.AddTask(core.Task{
		Name:      "collection",
		Interval:  func() time.Duration { return time.Hour },
		Immediate: true,
		Run:       c.loop,
	})
	return c, nil
}

func (c *collector) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *collector) setConfig(_ context.Context, cfg agentapi.AgentConfig) {
	c.mu.Lock()
	if c.cfg != nil && !sameWalkPaths(c.cfg.Policy.WalkPaths, cfg.Policy.WalkPaths) {
		// Other directories are to be walked: collect the artifacts now
		// rather than at their next scheduled run.
		c.manual[report.SectionArtifacts] = true
	}
	c.cfg = &cfg
	// Recompute the schedule from the last run times.
	c.next = map[string]time.Time{}
	c.mu.Unlock()
	c.signal()
}

// sameWalkPaths compares two walk path lists, in any order.
func sameWalkPaths(a, b *[]string) bool {
	var x, y []string
	if a != nil {
		x = slices.Sorted(slices.Values(*a))
	}
	if b != nil {
		y = slices.Sorted(slices.Values(*b))
	}
	return slices.Equal(x, y)
}

func (c *collector) handleCollect(_ context.Context, d agentapi.Directive) error {
	cd, err := d.AsCollectDirective()
	if err != nil {
		return err
	}
	c.mu.Lock()
	if len(cd.Sections) == 0 {
		c.manualAll = true
	}
	for _, s := range cd.Sections {
		c.manual[string(s)] = true
	}
	if cd.Full != nil && *cd.Full {
		c.full = true
	}
	c.mu.Unlock()
	c.signal()
	return nil
}

func (c *collector) handleGoSymbols(_ context.Context, d agentapi.Directive) error {
	gd, err := d.AsGoSymbolsDirective()
	if err != nil {
		return err
	}
	q := reportapi.GoSymbolQuery(gd.Query)
	c.mu.Lock()
	c.symbols = &q
	c.mu.Unlock()
	c.signal()
	return nil
}

func interval(cfg *agentapi.AgentConfig, section string) time.Duration {
	if cfg == nil {
		return 0
	}
	si := cfg.SectionIntervals
	var s int
	switch section {
	case report.SectionHost:
		s = si.Host
	case report.SectionPackages:
		s = si.Packages
	case report.SectionArtifacts:
		s = si.Artifacts
	case report.SectionProcesses:
		s = si.Processes
	case report.SectionContainers:
		s = si.Containers
	}
	return time.Duration(s) * time.Second
}

// due returns the sections to collect now, whether the run ignores known
// digests, and how long to wait otherwise (0: until woken).
func (c *collector) due(now time.Time) ([]string, bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := map[string]bool{}
	if c.manualAll {
		for _, s := range report.AllSections {
			set[s] = true
		}
	}
	maps.Copy(set, c.manual)
	full := c.full
	var wait time.Duration
	for _, s := range report.AllSections {
		iv := interval(c.cfg, s)
		if iv <= 0 {
			continue
		}
		n, ok := c.next[s]
		if !ok {
			n = now
			if last, ok := c.sections.LastRun[s]; ok {
				n = last.Add(iv)
			}
			c.next[s] = n
		}
		// Sections that become due soon join this run.
		window := min(30*time.Second, iv/4)
		if !n.After(now.Add(window)) {
			set[s] = true
			continue
		}
		if d := n.Sub(now); wait == 0 || d < wait {
			wait = d
		}
	}
	var out []string
	for _, s := range report.AllSections {
		if set[s] {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		c.manual = map[string]bool{}
		c.manualAll, c.full = false, false
	}
	return out, full, wait
}

func (c *collector) loop(ctx context.Context) error {
	for ctx.Err() == nil {
		c.mu.Lock()
		q := c.symbols
		c.symbols = nil
		c.mu.Unlock()
		if q != nil {
			c.answerSymbols(ctx, q)
			continue
		}
		sections, full, wait := c.due(c.now())
		if len(sections) > 0 {
			c.collect(ctx, sections, full)
			continue
		}
		var timer <-chan time.Time
		var t *time.Timer
		if wait > 0 {
			t = time.NewTimer(wait)
			timer = t.C
		}
		select {
		case <-ctx.Done():
		case <-c.wake:
		case <-timer:
		}
		if t != nil {
			t.Stop()
		}
	}
	return nil
}

func (c *collector) reschedule(sections []string, at func(iv time.Duration) time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range sections {
		if iv := interval(c.cfg, s); iv > 0 {
			c.next[s] = at(iv)
		}
	}
}

func (c *collector) collect(ctx context.Context, sections []string, full bool) {
	now := c.now()
	c.mu.Lock()
	policy := report.DefaultPolicy()
	if c.cfg != nil {
		policy = core.PolicyFromConfig(c.cfg.Policy)
	}
	req := &report.Request{Sections: sections, Policy: policy, Cache: c.cache}
	if !full {
		req.KnownDigests = map[string]string{}
		for _, s := range sections {
			if d, ok := c.sections.Digests[s]; ok {
				req.KnownDigests[s] = d
			}
		}
	}
	c.mu.Unlock()

	c.log.Info("collecting", "sections", sections, "full", full)
	rep, err := c.probe.Collect(ctx, req)
	if err != nil {
		if ctx.Err() == nil {
			c.log.Error("probe run failed", "error", err)
			c.reschedule(sections, func(iv time.Duration) time.Time { return now.Add(min(iv, failureRetry)) })
		}
		return
	}
	c.reschedule(sections, func(iv time.Duration) time.Time { return now.Add(core.Jitter(iv, 0.1)) })

	c.mu.Lock()
	if len(rep.Cache) > 0 {
		c.cache = rep.Cache
	}
	priv := rep.Privilege
	c.privilege = &priv
	for _, s := range sections {
		c.sections.LastRun[s] = now
	}
	secs := c.snapshot()
	cache := c.cache
	c.mu.Unlock()
	if err := c.st.SaveProbeCache(cache); err != nil {
		c.log.Warn("store probe cache", "error", err)
	}
	if err := c.st.SaveSections(secs); err != nil {
		c.log.Warn("store section state", "error", err)
	}

	prepare(rep)
	var buf bytes.Buffer
	if err := report.Encode(&buf, rep); err != nil {
		c.log.Error("encode report", "error", err)
		return
	}
	meta := core.ReportMeta{Digests: digestsOf(rep)}
	if err := c.rt.SubmitReport(ctx, buf.Bytes(), meta); err != nil && ctx.Err() == nil {
		c.log.Warn("report upload failed, kept in the spool", "error", err)
	}
}

// answerSymbols runs the probe for a Go symbol query alone and submits
// the report, which carries only the go_symbols section.
func (c *collector) answerSymbols(ctx context.Context, q *report.GoSymbolQuery) {
	c.mu.Lock()
	policy := report.DefaultPolicy()
	if c.cfg != nil {
		policy = core.PolicyFromConfig(c.cfg.Policy)
	}
	c.mu.Unlock()
	req := &report.Request{Sections: []string{report.SectionGoSymbols}, Policy: policy, GoSymbols: q}
	c.log.Info("answering go symbol query", "files", len(q.Files))
	rep, err := c.probe.Collect(ctx, req)
	if err != nil {
		if ctx.Err() == nil {
			c.log.Error("go symbol query failed", "error", err)
		}
		return
	}
	prepare(rep)
	var buf bytes.Buffer
	if err := report.Encode(&buf, rep); err != nil {
		c.log.Error("encode report", "error", err)
		return
	}
	if err := c.rt.SubmitReport(ctx, buf.Bytes(), core.ReportMeta{}); err != nil && ctx.Err() == nil {
		c.log.Warn("report upload failed, kept in the spool", "error", err)
	}
}

// snapshot copies the section state; the caller holds mu.
func (c *collector) snapshot() *state.Sections {
	return &state.Sections{Digests: maps.Clone(c.sections.Digests), LastRun: maps.Clone(c.sections.LastRun)}
}

// prepare makes a probe report uploadable: subject self, no cache, no
// probe-internal container hints.
func prepare(rep *report.Report) {
	rep.Subject = &report.Subject{Kind: report.SubjectSelf}
	rep.Cache = nil
	if rep.Containers != nil {
		for i := range rep.Containers.Containers {
			rep.Containers.Containers[i].InitPID = 0
			rep.Containers.Containers[i].UpperDir = ""
		}
	}
}

func digestsOf(rep *report.Report) map[string]string {
	out := map[string]string{}
	add := func(name string, m *report.SectionMeta) {
		if m != nil && m.Digest != "" {
			out[name] = m.Digest
		}
	}
	if rep.Host != nil {
		add(report.SectionHost, &rep.Host.SectionMeta)
	}
	if rep.Packages != nil {
		add(report.SectionPackages, &rep.Packages.SectionMeta)
	}
	if rep.Artifacts != nil {
		add(report.SectionArtifacts, &rep.Artifacts.SectionMeta)
	}
	if rep.Processes != nil {
		add(report.SectionProcesses, &rep.Processes.SectionMeta)
	}
	if rep.Containers != nil {
		add(report.SectionContainers, &rep.Containers.SectionMeta)
	}
	return out
}

// uploaded records the digests of a report the server accepted.
func (c *collector) uploaded(_ context.Context, meta core.ReportMeta) {
	if len(meta.Digests) == 0 {
		return
	}
	c.mu.Lock()
	maps.Copy(c.sections.Digests, meta.Digests)
	secs := c.snapshot()
	c.mu.Unlock()
	if err := c.st.SaveSections(secs); err != nil {
		c.log.Warn("store section digests", "error", err)
	}
}

func (c *collector) status(_ context.Context, req *agentapi.PollRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req.SectionDigests = maps.Clone(c.sections.Digests)
	features := []string{report.FeatureGoSymbols}
	req.Features = &features
	if c.privilege != nil {
		p := agentapi.Privilege{Level: agentapi.PrivilegeLevel(c.privilege.Level), Uid: c.privilege.UID}
		if len(c.privilege.Capabilities) > 0 {
			caps := slices.Clone(c.privilege.Capabilities)
			p.Capabilities = &caps
		}
		if c.privilege.ExecHelper {
			t := true
			p.ExecHelper = &t
		}
		if p.Level.Valid() {
			req.Privilege = p
		}
	}
}
