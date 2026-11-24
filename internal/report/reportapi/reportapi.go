// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package reportapi converts between report types and their agent API
// forms.
package reportapi

import (
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report"
)

// GoSymbolQuery converts a query from its agent API form.
func GoSymbolQuery(q agentapi.GoSymbolQuery) report.GoSymbolQuery {
	out := report.GoSymbolQuery{Files: make([]report.GoSymbolFile, 0, len(q.Files))}
	for _, f := range q.Files {
		rf := report.GoSymbolFile{Path: f.Path, SHA256: f.Sha256, Names: f.Names}
		if f.Container != nil {
			rf.Container = *f.Container
		}
		out.Files = append(out.Files, rf)
	}
	return out
}

// GoSymbolQueryPtr converts an optional query; nil stays nil.
func GoSymbolQueryPtr(q *agentapi.GoSymbolQuery) *report.GoSymbolQuery {
	if q == nil {
		return nil
	}
	out := GoSymbolQuery(*q)
	return &out
}

// APIGoSymbolQuery converts a query to its agent API form.
func APIGoSymbolQuery(q report.GoSymbolQuery) agentapi.GoSymbolQuery {
	out := agentapi.GoSymbolQuery{Files: make([]agentapi.GoSymbolFile, 0, len(q.Files))}
	for _, f := range q.Files {
		wf := agentapi.GoSymbolFile{Path: f.Path, Sha256: f.SHA256, Names: f.Names}
		if f.Container != "" {
			ct := f.Container
			wf.Container = &ct
		}
		out.Files = append(out.Files, wf)
	}
	return out
}

// APIGoSymbolQueryPtr converts an optional query; nil stays nil.
func APIGoSymbolQueryPtr(q *report.GoSymbolQuery) *agentapi.GoSymbolQuery {
	if q == nil {
		return nil
	}
	out := APIGoSymbolQuery(*q)
	return &out
}
