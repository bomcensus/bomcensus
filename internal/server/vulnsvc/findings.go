// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/normalize"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Defaults of the findings refresh.
const (
	DefaultRefreshInterval = 2 * time.Minute
	refreshBatch           = 200
	// maxFindingProcesses bounds the processes kept on a finding.
	maxFindingProcesses = 5
)

// FindingsStore is what the refresher reads and writes.
type FindingsStore interface {
	DirtyFindingAssets(ctx context.Context, limit int) ([]string, error)
	FindingInputs(ctx context.Context, assetID string) (store.FindingInputs, error)
	ApplyFindings(ctx context.Context, assetID string, rows []store.FindingRow, stamp store.FindingStamp) (store.FindingsChange, error)
}

// Refresher keeps the findings of assets up to date.
type Refresher struct {
	st     FindingsStore
	queue  job.Queue
	log    *slog.Logger
	runFor time.Duration
	now    func() time.Time
}

// NewRefresher returns a Refresher; queue may be nil for tests that call
// Run.
func NewRefresher(st FindingsStore, queue job.Queue, log *slog.Logger) (*Refresher, error) {
	if st == nil {
		return nil, errors.New("vulnsvc: store is required")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Refresher{st: st, queue: queue, log: log, runFor: DefaultRunFor, now: time.Now}, nil
}

// Register registers the refresh job and its periodic run with q.
func (r *Refresher) Register(q job.Queue, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	if err := q.Register(job.KindFindingsRefresh, func(ctx context.Context, _ job.Job) error { return r.Run(ctx) }); err != nil {
		return err
	}
	return q.Periodic(job.KindFindingsRefresh, interval, nil, job.UniqueKey(job.KindFindingsRefresh))
}

// Trigger queues a refresh after delay unless one is queued already.
func (r *Refresher) Trigger(ctx context.Context, delay time.Duration) error {
	if r.queue == nil {
		return errors.New("vulnsvc: no queue")
	}
	opts := []job.Option{job.UniqueKey(job.KindFindingsRefresh)}
	if delay > 0 {
		opts = append(opts, job.ScheduledAt(r.now().Add(delay)))
	}
	_, err := r.queue.Enqueue(ctx, job.KindFindingsRefresh, nil, opts...)
	return err
}

// Run computes the findings of out-of-date assets until none is left or
// RunFor has passed (it then returns job.Snooze to continue).
func (r *Refresher) Run(ctx context.Context) error {
	deadline := r.now().Add(r.runFor)
	var total store.FindingsChange
	assets := 0
	defer func() {
		if assets > 0 {
			r.log.Info("findings refreshed", "assets", assets, "opened", total.Opened, "resolved", total.Resolved)
		}
	}()
	for {
		ids, err := r.st.DirtyFindingAssets(ctx, refreshBatch)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		for _, id := range ids {
			in, err := r.st.FindingInputs(ctx, id)
			if errors.Is(err, store.ErrNotFound) {
				continue // deleted meanwhile
			}
			if err != nil {
				return err
			}
			ch, err := r.st.ApplyFindings(ctx, id, Compute(in), in.Stamp)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			assets++
			total.Opened += ch.Opened
			total.Resolved += ch.Resolved
			if !r.now().Before(deadline) {
				return job.Snooze(time.Second)
			}
		}
	}
}

// exposureRank orders exposures, most exposed first.
var exposureRank = map[string]int{
	store.ExposureListening: 0, store.ExposureRunning: 1, store.ExposureUnknown: 2, store.ExposureInstalled: 3,
}

// Compute returns the findings of an asset: one per container, component
// and vulnerability, with the exposure of the component and, for Go
// components, whether the vulnerable functions are linked (gosymbols.go).
func Compute(in store.FindingInputs) []store.FindingRow {
	if in.Gone {
		return nil
	}
	type key struct{ container, comp, vuln string }
	best := map[key]int{}
	var out []store.FindingRow
	for _, s := range in.Sources {
		exposure, procs := exposureOf(in, s)
		for _, v := range s.VulnIDs {
			row := store.FindingRow{Container: s.Container, Layer: s.Layer, ImageDigest: s.ImageDigest,
				ComponentID: s.Component.ID, VulnID: v, Exposure: exposure, Processes: procs}
			// A vulnerable function linked into none of the executables
			// lowers the exposure to that of an installed component.
			row.Reachability = reachabilityOf(in, s, v)
			if row.Reachability == store.ReachSymbolAbsent &&
				(row.Exposure == store.ExposureListening || row.Exposure == store.ExposureRunning) {
				row.Exposure = store.ExposureInstalled
			}
			k := key{s.Container, s.Component.ID, v}
			// The same component in two layers of a container is one
			// finding: the more exposed, then the runtime layer.
			if i, ok := best[k]; ok {
				if exposureRank[row.Exposure] < exposureRank[out[i].Exposure] ||
					(row.Exposure == out[i].Exposure && row.Layer == store.FindingLayerRuntime) {
					out[i] = row
				}
				continue
			}
			best[k] = len(out)
			out = append(out, row)
		}
	}
	slices.SortFunc(out, func(a, b store.FindingRow) int {
		for _, c := range [...]int{cmpStr(a.Container, b.Container), cmpStr(a.ComponentID, b.ComponentID), cmpStr(a.VulnID, b.VulnID)} {
			if c != 0 {
				return c
			}
		}
		return 0
	})
	return out
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// exposureOf tells how exposed a source component is, from the processes
// of its container that load it.
//
//   - listening: a loading process listens on a non-loopback address
//   - running: a process loads it, or the component is flagged in use
//   - installed: the container's processes were fully collected, with the
//     packages they load where the component is an OS package, and none
//     loads it
//   - unknown: otherwise
func exposureOf(in store.FindingInputs, s store.FindingSource) (string, []store.FindingProcessRef) {
	osPackage := osPackageTypes[s.Component.Type]
	keys := normalize.OwnerKeys(s.Component)
	locs := map[string]bool{}
	for _, l := range s.Locations {
		locs[l] = true
	}
	hashed := func(h string) bool { return h != "" && slices.Contains(in.HashComponents[h], s.Component.ID) }
	loads := func(p store.FindingProcess) bool {
		if p.ComponentID == s.Component.ID || locs[p.Exe] || hashed(p.SHA256) {
			return true
		}
		for _, l := range p.Libs {
			if locs[l.Path] || hashed(l.SHA256) {
				return true
			}
		}
		if osPackage {
			for _, k := range keys {
				if slices.Contains(p.Packages, k) {
					return true
				}
			}
		}
		return false
	}

	var refs []store.FindingProcessRef
	listening := false
	complete := true
	for _, p := range in.Processes {
		if p.Container != s.Container {
			continue
		}
		if osPackage && p.Packages == nil {
			complete = false
		}
		if !loads(p) {
			continue
		}
		if len(p.Ports) > 0 {
			listening = true
		}
		refs = append(refs, store.FindingProcessRef{PID: p.PID, Exe: p.Exe, Pod: p.Pod, Ports: p.Ports})
	}
	// Listening processes first, then by pid.
	slices.SortStableFunc(refs, func(a, b store.FindingProcessRef) int {
		if (len(a.Ports) > 0) != (len(b.Ports) > 0) {
			if len(a.Ports) > 0 {
				return -1
			}
			return 1
		}
		return a.PID - b.PID
	})
	if len(refs) > maxFindingProcesses {
		refs = refs[:maxFindingProcesses]
	}

	switch {
	case listening:
		return store.ExposureListening, refs
	case len(refs) > 0 || s.InUse:
		return store.ExposureRunning, refs
	case complete && processCoverage(in, s.Container) == store.CoverageFull:
		return store.ExposureInstalled, nil
	}
	return store.ExposureUnknown, nil
}

// processCoverage is the coverage of the processes of a container: its own
// section for a workload container, the host's for the host and its
// containers.
func processCoverage(in store.FindingInputs, container string) store.Coverage {
	if c, ok := in.ProcessCoverage[container]; ok {
		return c
	}
	if in.Kind == store.AssetHost {
		return in.ProcessCoverage[""]
	}
	return ""
}
