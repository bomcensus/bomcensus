// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/report/reportapi"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Defaults of the Go symbol check.
const (
	DefaultSymbolCheckInterval = 15 * time.Minute
	// SymbolQueryTTL is how long a query waits: an agent's directive
	// expires after it and the asset is not asked again before.
	SymbolQueryTTL = time.Hour
	// SymbolRetryAfter is how long an answer of not checked stands before
	// the name is asked again.
	SymbolRetryAfter = 24 * time.Hour
	symbolCheckBatch = 100
)

// SymbolStore is what the Go symbol check reads and writes.
type SymbolStore interface {
	GoSymbolAssets(ctx context.Context, since time.Time, limit int) ([]string, error)
	FindingInputs(ctx context.Context, assetID string) (store.FindingInputs, error)
	GetAsset(ctx context.Context, id string) (store.AssetDetail, error)
	GetAgent(ctx context.Context, id string) (store.Agent, error)
	PutGoSymbolQuery(ctx context.Context, q store.GoSymbolQuery) error
}

// Enqueuer delivers a directive to an agent.
type Enqueuer interface {
	Enqueue(ctx context.Context, agentID string, d dispatch.Directive) (string, error)
}

// SymbolChecker asks the collectors of assets whether the vulnerable
// functions of their Go findings are linked into the executables. Agents
// get a directive at once; for SSH scans and Kubernetes exec the query
// waits for the next collection, which carries it when the scanner
// supports it.
type SymbolChecker struct {
	st       SymbolStore
	dispatch Enqueuer
	log      *slog.Logger
	now      func() time.Time
}

// NewSymbolChecker returns a SymbolChecker.
func NewSymbolChecker(st SymbolStore, d Enqueuer, log *slog.Logger) *SymbolChecker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &SymbolChecker{st: st, dispatch: d, log: log, now: time.Now}
}

// Register registers the check job and its periodic run with q.
func (c *SymbolChecker) Register(q job.Queue, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultSymbolCheckInterval
	}
	if err := q.Register(job.KindGoSymbolCheck, func(ctx context.Context, _ job.Job) error { return c.Run(ctx) }); err != nil {
		return err
	}
	return q.Periodic(job.KindGoSymbolCheck, interval, nil, job.UniqueKey(job.KindGoSymbolCheck))
}

// Run creates the queries of the assets that need one.
func (c *SymbolChecker) Run(ctx context.Context) error {
	now := c.now().UTC()
	ids, err := c.st.GoSymbolAssets(ctx, now.Add(-SymbolQueryTTL), symbolCheckBatch)
	if err != nil {
		return fmt.Errorf("vulnsvc: go symbol assets: %w", err)
	}
	asked := 0
	for _, id := range ids {
		n, err := c.check(ctx, id, now)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		asked += n
	}
	if asked > 0 {
		c.log.Info("go symbol queries created", "queries", asked)
	}
	return nil
}

// check creates the queries of one asset and returns how many.
func (c *SymbolChecker) check(ctx context.Context, assetID string, now time.Time) (int, error) {
	in, err := c.st.FindingInputs(ctx, assetID)
	if err != nil {
		return 0, err
	}
	needs := SymbolNeeds(in, now.Add(-SymbolRetryAfter))
	if len(needs) == 0 {
		return 0, nil
	}
	asset, err := c.st.GetAsset(ctx, assetID)
	if err != nil {
		return 0, err
	}
	runtimeID := map[string]string{}
	for _, ct := range asset.Containers {
		if ct.GoneAt == nil && ct.Instances > 0 && ct.RuntimeID != "" {
			runtimeID[ct.Name] = ct.RuntimeID
		}
	}

	switch {
	case asset.Kind == store.AssetWorkload:
		// Kubernetes exec runs the probe inside each container.
		byContainer := map[string][]SymbolNeed{}
		for _, n := range needs {
			byContainer[n.Container] = append(byContainer[n.Container], n)
		}
		count := 0
		for name, ns := range byContainer {
			if name == "" {
				continue
			}
			if err := c.put(ctx, assetID, name, buildQuery(ns, func(string) (string, bool) { return "", true }), now); err != nil {
				return count, err
			}
			count++
		}
		return count, nil
	case asset.AgentID != "":
		agent, err := c.st.GetAgent(ctx, asset.AgentID)
		if err != nil {
			return 0, err
		}
		if agent.State == store.AgentRevoked || !agent.HasFeature(store.FeatureGoSymbols) {
			return 0, nil
		}
		q := buildQuery(needs, containerRuntime(runtimeID))
		if len(q.Files) == 0 {
			return 0, nil
		}
		if err := c.put(ctx, assetID, "", q, now); err != nil {
			return 0, err
		}
		if err := c.deliver(ctx, agent.ID, q); err != nil {
			return 0, err
		}
		return 1, nil
	case asset.ScanTargetID != "":
		q := buildQuery(needs, containerRuntime(runtimeID))
		if len(q.Files) == 0 {
			return 0, nil
		}
		return 1, c.put(ctx, assetID, "", q, now)
	}
	return 0, nil
}

func containerRuntime(ids map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == "" {
			return "", true
		}
		id, ok := ids[name]
		return id, ok
	}
}

func (c *SymbolChecker) put(ctx context.Context, assetID, container string, q report.GoSymbolQuery, now time.Time) error {
	if len(q.Files) == 0 {
		return nil
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return fmt.Errorf("vulnsvc: encode go symbol query: %w", err)
	}
	if err := c.st.PutGoSymbolQuery(ctx, store.GoSymbolQuery{AssetID: assetID, Container: container, Query: raw, CreatedAt: now}); err != nil {
		return fmt.Errorf("vulnsvc: put go symbol query: %w", err)
	}
	return nil
}

func (c *SymbolChecker) deliver(ctx context.Context, agentID string, q report.GoSymbolQuery) error {
	if c.dispatch == nil {
		return nil
	}
	var body agentapi.Directive
	if err := body.FromGoSymbolsDirective(agentapi.GoSymbolsDirective{Type: agentapi.GoSymbols, Query: reportapi.APIGoSymbolQuery(q)}); err != nil {
		return fmt.Errorf("vulnsvc: build go symbols directive: %w", err)
	}
	if _, err := c.dispatch.Enqueue(ctx, agentID, dispatch.Directive{Body: body, DedupeKey: "go_symbols", TTL: SymbolQueryTTL}); err != nil {
		return fmt.Errorf("vulnsvc: enqueue go symbols directive: %w", err)
	}
	return nil
}

// SymbolNeed is an executable and the names to ask about it.
type SymbolNeed struct {
	// Container is the container name of the asset, "" for the asset
	// itself.
	Container string
	Path      string
	SHA256    string
	Names     []string
}

// SymbolNeeds returns what is not known yet about the asset's Go
// executables: names of vulnerable functions without an answer, or with
// an answer of not checked from before retryBefore. Executables whose
// reachability is already decided are left out.
func SymbolNeeds(in store.FindingInputs, retryBefore time.Time) []SymbolNeed {
	type binKey struct{ container, path, sha string }
	names := map[binKey]map[string]bool{}
	var order []binKey
	for _, s := range in.Sources {
		for _, v := range s.VulnIDs {
			imps := in.Symbols[store.SymbolKey(s.Component.ID, v)]
			if len(imps) == 0 {
				continue
			}
			for _, b := range sourceBinaries(in, s) {
				if binaryReach(in, b, imps) != "" {
					continue
				}
				answers := in.SymbolResults[b.SHA256]
				k := binKey{b.Container, b.Path, b.SHA256}
				for _, imp := range imps {
					if !imp.Applies(b.GOOS, b.GOARCH) {
						continue
					}
					for _, n := range imp.Names() {
						a, ok := answers[n]
						if ok && (a.Result != store.GoSymbolNotChecked || a.CheckedAt.After(retryBefore)) {
							continue
						}
						if names[k] == nil {
							names[k] = map[string]bool{}
							order = append(order, k)
						}
						names[k][n] = true
					}
				}
			}
		}
	}
	out := make([]SymbolNeed, 0, len(order))
	for _, k := range order {
		ns := make([]string, 0, len(names[k]))
		for n := range names[k] {
			ns = append(ns, n)
		}
		slices.Sort(ns)
		out = append(out, SymbolNeed{Container: k.container, Path: k.path, SHA256: k.sha, Names: ns})
	}
	return out
}

// buildQuery turns needs into a query within the probe's limits. runtime
// maps a container name to the runtime id the probe knows it by; needs of
// containers without one are left out. What does not fit is asked later.
func buildQuery(needs []SymbolNeed, runtime func(string) (string, bool)) report.GoSymbolQuery {
	var q report.GoSymbolQuery
	total := 0
	for _, n := range needs {
		if len(q.Files) == report.MaxGoSymbolFiles || total == report.MaxGoSymbolNames {
			break
		}
		id, ok := runtime(n.Container)
		if !ok {
			continue
		}
		names := n.Names
		if len(names) > report.MaxGoSymbolNamesPerFile {
			names = names[:report.MaxGoSymbolNamesPerFile]
		}
		if total+len(names) > report.MaxGoSymbolNames {
			names = names[:report.MaxGoSymbolNames-total]
		}
		total += len(names)
		q.Files = append(q.Files, report.GoSymbolFile{Container: id, Path: n.Path, SHA256: n.SHA256, Names: names})
	}
	return q
}
