// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// applyGoSymbols stores the answers of a report to the query waiting for
// the asset's container scope ("" for the whole asset). Only answers to
// that query are kept: a collector cannot add results for files or names
// it was not asked about. Answered, the query is removed.
func (s *Service) applyGoSymbols(ctx context.Context, tx store.Store, assetID, container string, r *report.Report) error {
	sec := r.GoSymbols
	if sec == nil || assetID == "" {
		return nil
	}
	waiting, err := tx.GoSymbolQueryFor(ctx, assetID, container)
	if errors.Is(err, store.ErrNotFound) {
		s.log.Info("go symbol answers without a query", "asset", assetID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("ingest: go symbol query: %w", err)
	}
	var q report.GoSymbolQuery
	if err := json.Unmarshal(waiting.Query, &q); err != nil {
		return fmt.Errorf("ingest: go symbol query: %w", err)
	}
	type fileKey struct{ container, path, sha256 string }
	asked := map[fileKey]map[string]bool{}
	for _, f := range q.Files {
		k := fileKey{f.Container, f.Path, strings.ToLower(f.SHA256)}
		if asked[k] == nil {
			asked[k] = map[string]bool{}
		}
		for _, n := range f.Names {
			asked[k][n] = true
		}
	}
	at := s.reportTime(r, &sec.SectionMeta)
	var results []store.GoSymbolResult
	for _, ans := range sec.Files {
		names := asked[fileKey{ans.Container, ans.Path, strings.ToLower(ans.SHA256)}]
		for name, res := range ans.Results {
			if !names[name] {
				continue
			}
			switch res {
			case report.GoSymbolPresent, report.GoSymbolAbsent, report.GoSymbolNotChecked:
			default:
				continue
			}
			reason := ans.Reason
			if len(reason) > 500 {
				reason = reason[:500]
			}
			results = append(results, store.GoSymbolResult{SHA256: strings.ToLower(ans.SHA256), Name: name,
				Result: res, Reason: reason, CheckedAt: at})
		}
	}
	if err := tx.SaveGoSymbolResults(ctx, assetID, results); err != nil {
		return fmt.Errorf("ingest: save go symbol results: %w", err)
	}
	if err := tx.DeleteGoSymbolQuery(ctx, assetID, container); err != nil {
		return fmt.Errorf("ingest: delete go symbol query: %w", err)
	}
	return nil
}
