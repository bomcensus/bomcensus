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

// IntegrityQuery converts the API form of an integrity chunk.
func IntegrityQuery(q agentapi.IntegrityQuery) report.IntegrityQuery {
	out := report.IntegrityQuery{PassID: q.PassId}
	if q.Cursor != nil {
		out.Cursor = *q.Cursor
	}
	if q.FullRehash != nil {
		out.FullRehash = *q.FullRehash
	}
	if q.MaxReadMbps != nil {
		out.MaxReadMBps = *q.MaxReadMbps
	}
	if q.ExcludePaths != nil {
		out.ExcludePaths = append([]string(nil), *q.ExcludePaths...)
	}
	return out
}

// IntegrityQueryPtr is IntegrityQuery for an optional query.
func IntegrityQueryPtr(q *agentapi.IntegrityQuery) *report.IntegrityQuery {
	if q == nil {
		return nil
	}
	out := IntegrityQuery(*q)
	return &out
}

// APIIntegrityQuery converts an integrity chunk to its API form; the cache
// is not part of it.
func APIIntegrityQuery(q report.IntegrityQuery) agentapi.IntegrityQuery {
	out := agentapi.IntegrityQuery{PassId: q.PassID}
	if q.Cursor != "" {
		c := q.Cursor
		out.Cursor = &c
	}
	if q.FullRehash {
		t := true
		out.FullRehash = &t
	}
	if q.MaxReadMBps > 0 {
		r := q.MaxReadMBps
		out.MaxReadMbps = &r
	}
	if len(q.ExcludePaths) > 0 {
		e := append([]string(nil), q.ExcludePaths...)
		out.ExcludePaths = &e
	}
	return out
}
