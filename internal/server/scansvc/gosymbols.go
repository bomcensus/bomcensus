// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/kube"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// goSymbols returns the Go symbol query waiting for an asset's container
// scope, or nil. A query that cannot be read is left out: the scan runs
// without it.
func (s *Service) goSymbols(ctx context.Context, assetID, container string) *report.GoSymbolQuery {
	if assetID == "" {
		return nil
	}
	w, err := s.st.GoSymbolQueryFor(ctx, assetID, container)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("go symbol query not attached", "asset", assetID, "error", err)
		}
		return nil
	}
	var q report.GoSymbolQuery
	if err := json.Unmarshal(w.Query, &q); err != nil || q.Validate() != nil {
		s.log.Warn("go symbol query not attached", "asset", assetID, "error", err)
		return nil
	}
	return &q
}

// withGoSymbols returns targets with the waiting queries of their workload
// containers. One replica per workload container carries a query: the
// answers are kept for the workload by executable hash.
func (s *Service) withGoSymbols(ctx context.Context, clusterID string, targets []kube.ExecTarget) []kube.ExecTarget {
	waiting, err := s.st.ClusterGoSymbolQueries(ctx, clusterID)
	if err != nil {
		s.log.Warn("go symbol queries not attached", "cluster", clusterID, "error", err)
		return targets
	}
	if len(waiting) == 0 {
		return targets
	}
	type key struct{ ns, kind, name, container string }
	byKey := map[key]store.WorkloadGoSymbolQuery{}
	for _, w := range waiting {
		byKey[key{w.Namespace, w.WorkloadKind, w.WorkloadName, w.Container}] = w
	}
	out := make([]kube.ExecTarget, len(targets))
	copy(out, targets)
	for i := range out {
		t := &out[i]
		k := key{t.Namespace, t.WorkloadKind, t.WorkloadName, t.Container}
		w, ok := byKey[k]
		if !ok {
			continue
		}
		delete(byKey, k)
		var q report.GoSymbolQuery
		if err := json.Unmarshal(w.Query, &q); err != nil || q.Validate() != nil {
			continue
		}
		t.GoSymbols = &q
	}
	return out
}
