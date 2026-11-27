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

	"github.com/bomcensus/bomcensus/agentproto/dto"
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
	GoSymbolQueryFor(ctx context.Context, assetID, container string) (store.GoSymbolQuery, error)
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
		// A node agent that runs a pod of the workload is asked too: it
		// sees the runtime layer and the processes of the pod.
		n, err := c.askNodes(ctx, in.NodeContainers, needs, now)
		return count + n, err
	case asset.AgentID != "":
		return c.askAgent(ctx, asset, needs, nil, runtimeID, now)
	case asset.ScanTargetID != "":
		q := buildQuery(needs, containerRuntime(runtimeID))
		if len(q.Files) == 0 {
			return 0, nil
		}
		return 1, c.put(ctx, assetID, "", q, now)
	}
	return 0, nil
}

// askAgent sends the agent of a host the query for needs and for extra,
// the needs of workloads in the host's pod containers. runtimeID maps the
// host's container names to runtime ids.
func (c *SymbolChecker) askAgent(ctx context.Context, asset store.AssetDetail, needs, extra []SymbolNeed, runtimeID map[string]string, now time.Time) (int, error) {
	if asset.AgentID == "" {
		return 0, nil
	}
	agent, err := c.st.GetAgent(ctx, asset.AgentID)
	if err != nil {
		return 0, err
	}
	if agent.State == store.AgentRevoked || !agent.HasFeature(store.FeatureGoSymbols) {
		return 0, nil
	}
	q := buildQuery(append(slices.Clone(needs), extra...), containerRuntime(runtimeID))
	if len(q.Files) == 0 {
		return 0, nil
	}
	if len(extra) > 0 {
		// Workloads of several pods on the host ask through it in turn;
		// a waiting query keeps what it asks.
		old, err := c.st.GoSymbolQueryFor(ctx, asset.ID, "")
		switch {
		case err == nil && old.CreatedAt.After(now.Add(-SymbolQueryTTL)):
			var oq report.GoSymbolQuery
			if json.Unmarshal(old.Query, &oq) == nil {
				q = mergeQuery(oq, q)
			}
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return 0, err
		}
	}
	if err := c.put(ctx, asset.ID, "", q, now); err != nil {
		return 0, err
	}
	if err := c.deliver(ctx, agent.ID, q); err != nil {
		return 0, err
	}
	return 1, nil
}

// askNodes asks the agents of the hosts that recently saw a workload's pod
// containers about the needs of those containers, together with the
// hosts' own needs: a host keeps one query at a time. One host is asked
// per workload container.
func (c *SymbolChecker) askNodes(ctx context.Context, nodes []store.FindingNodeContainer, needs []SymbolNeed, now time.Time) (int, error) {
	pick := map[string]store.FindingNodeContainer{}
	for _, n := range nodes {
		if _, ok := pick[n.Container]; !ok && n.Fresh && n.RuntimeID != "" {
			pick[n.Container] = n
		}
	}
	extra := map[string][]SymbolNeed{}
	runtimes := map[string]map[string]string{}
	var hosts []string
	for _, need := range needs {
		n, ok := pick[need.Container]
		if !ok {
			continue
		}
		if runtimes[n.HostID] == nil {
			runtimes[n.HostID] = map[string]string{}
			hosts = append(hosts, n.HostID)
		}
		runtimes[n.HostID][n.HostContainer] = n.RuntimeID
		need.Container = n.HostContainer
		extra[n.HostID] = append(extra[n.HostID], need)
	}
	count := 0
	for _, id := range hosts {
		hin, err := c.st.FindingInputs(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return count, err
		}
		host, err := c.st.GetAsset(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return count, err
		}
		rt := runtimes[id]
		for _, ct := range host.Containers {
			if ct.GoneAt == nil && ct.Instances > 0 && ct.RuntimeID != "" {
				rt[ct.Name] = ct.RuntimeID
			}
		}
		n, err := c.askAgent(ctx, host, SymbolNeeds(hin, now.Add(-SymbolRetryAfter)), extra[id], rt, now)
		if err != nil {
			return count, err
		}
		count += n
	}
	return count, nil
}

// mergeQuery adds the files and names of add to q within the probe's
// limits.
func mergeQuery(q, add report.GoSymbolQuery) report.GoSymbolQuery {
	type fileKey struct{ container, path, sha string }
	index := map[fileKey]int{}
	total := 0
	for i, f := range q.Files {
		index[fileKey{f.Container, f.Path, f.SHA256}] = i
		total += len(f.Names)
	}
	for _, f := range add.Files {
		k := fileKey{f.Container, f.Path, f.SHA256}
		i, ok := index[k]
		if !ok {
			if len(q.Files) == report.MaxGoSymbolFiles {
				continue
			}
			i = len(q.Files)
			index[k] = i
			q.Files = append(q.Files, report.GoSymbolFile{Container: f.Container, Path: f.Path, SHA256: f.SHA256})
		}
		for _, n := range f.Names {
			if total == report.MaxGoSymbolNames || len(q.Files[i].Names) == report.MaxGoSymbolNamesPerFile {
				break
			}
			if !slices.Contains(q.Files[i].Names, n) {
				q.Files[i].Names = append(q.Files[i].Names, n)
				total++
			}
		}
	}
	// A file kept without names would be rejected.
	q.Files = slices.DeleteFunc(q.Files, func(f report.GoSymbolFile) bool { return len(f.Names) == 0 })
	return q
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
	var body dto.Directive
	if err := body.FromGoSymbolsDirective(dto.GoSymbolsDirective{Type: dto.GoSymbols, Query: reportapi.APIGoSymbolQuery(q)}); err != nil {
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
