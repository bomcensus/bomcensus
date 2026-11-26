// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"errors"

	"github.com/bomcensus/bomcensus/internal/detectors"
	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/detectorsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// maxDetectorRevisions bounds the revisions listed.
const maxDetectorRevisions = 200

func (h *Handlers) detectorService() (*detectorsvc.Service, error) {
	if h.detectors == nil {
		return nil, apierr.Unavailable("detector tables are not available")
	}
	return h.detectors, nil
}

func problemsDTO(probs []detectors.Problem, warningsOnly bool) []gen.DetectorTableProblem {
	out := []gen.DetectorTableProblem{}
	for _, p := range probs {
		if warningsOnly && !p.Warning {
			continue
		}
		sev := gen.DetectorTableProblemSeverityError
		if p.Warning {
			sev = gen.DetectorTableProblemSeverityWarning
		}
		out = append(out, gen.DetectorTableProblem{Index: p.Index, Id: optString(p.ID), Severity: sev, Message: p.Message})
	}
	return out
}

func (h *Handlers) detectorStateDTO(svc *detectorsvc.Service, e detectorsvc.Effective) gen.DetectorTableState {
	def, _ := svc.Default()
	_, probs := detectorsvc.Parse([]byte(e.YAML))
	out := gen.DetectorTableState{
		Custom:        e.Custom,
		Yaml:          e.YAML,
		Digest:        e.Digest,
		Detectors:     len(e.Table.Table.Detectors),
		DefaultDigest: def.Digest,
		BuiltinDigest: detectors.BuiltinDigest(),
		Warnings:      problemsDTO(probs, true),
	}
	if e.Revision > 0 {
		r, at := e.Revision, e.UpdatedAt
		out.Revision, out.UpdatedAt, out.UpdatedBy = &r, &at, optString(e.UpdatedBy)
	}
	return out
}

// GetDetectorTable implements getDetectorTable.
func (h *Handlers) GetDetectorTable(ctx context.Context, _ gen.GetDetectorTableRequestObject) (gen.GetDetectorTableResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	e, err := svc.Effective(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetDetectorTable200JSONResponse(h.detectorStateDTO(svc, e)), nil
}

// SaveDetectorTable implements saveDetectorTable.
func (h *Handlers) SaveDetectorTable(ctx context.Context, req gen.SaveDetectorTableRequestObject) (gen.SaveDetectorTableResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.Invalid("request body is required")
	}
	e, probs, err := svc.Save(ctx, []byte(req.Body.Yaml), h.who(ctx))
	if errors.Is(err, detectorsvc.ErrInvalid) {
		return gen.SaveDetectorTable422JSONResponse(checkDTO(nil, probs)), nil
	}
	if err != nil {
		return nil, err
	}
	h.log.Info("detector table saved", "revision", e.Revision, "digest", e.Digest, "detectors", len(e.Table.Table.Detectors),
		"by", h.who(ctx))
	return gen.SaveDetectorTable200JSONResponse(h.detectorStateDTO(svc, e)), nil
}

// ResetDetectorTable implements resetDetectorTable.
func (h *Handlers) ResetDetectorTable(ctx context.Context, _ gen.ResetDetectorTableRequestObject) (gen.ResetDetectorTableResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	e, err := svc.Reset(ctx, h.who(ctx))
	if err != nil {
		return nil, err
	}
	h.log.Info("detector table reset to the default", "revision", e.Revision, "digest", e.Digest, "by", h.who(ctx))
	return gen.ResetDetectorTable200JSONResponse(h.detectorStateDTO(svc, e)), nil
}

func checkDTO(t *detectorsvc.Table, probs []detectors.Problem) gen.DetectorTableCheck {
	out := gen.DetectorTableCheck{Valid: t != nil, Problems: problemsDTO(probs, false)}
	if t != nil {
		n := len(t.Table.Detectors)
		out.Digest, out.Detectors = optString(t.Digest), &n
	}
	return out
}

// CheckDetectorTable implements checkDetectorTable.
func (h *Handlers) CheckDetectorTable(_ context.Context, req gen.CheckDetectorTableRequestObject) (gen.CheckDetectorTableResponseObject, error) {
	if _, err := h.detectorService(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.Invalid("request body is required")
	}
	t, probs := detectorsvc.Parse([]byte(req.Body.Yaml))
	if t.Table == nil {
		return gen.CheckDetectorTable200JSONResponse(checkDTO(nil, probs)), nil
	}
	return gen.CheckDetectorTable200JSONResponse(checkDTO(&t, probs)), nil
}

// GetDefaultDetectorTable implements getDefaultDetectorTable.
func (h *Handlers) GetDefaultDetectorTable(context.Context, gen.GetDefaultDetectorTableRequestObject) (gen.GetDefaultDetectorTableResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	def, source := svc.Default()
	return gen.GetDefaultDetectorTable200JSONResponse{Yaml: def.YAML, Digest: def.Digest, Source: source,
		Detectors: len(def.Table.Detectors)}, nil
}

func revisionDTO(r store.DetectorTableRevision) gen.DetectorTableRevision {
	return gen.DetectorTableRevision{Revision: r.ID, Reset: r.Reset, Digest: optString(r.Digest), Yaml: optString(r.YAML),
		CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy}
}

// ListDetectorTableRevisions implements listDetectorTableRevisions.
func (h *Handlers) ListDetectorTableRevisions(ctx context.Context, _ gen.ListDetectorTableRevisionsRequestObject) (gen.ListDetectorTableRevisionsResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	revs, err := svc.History(ctx, maxDetectorRevisions)
	if err != nil {
		return nil, err
	}
	out := gen.ListDetectorTableRevisions200JSONResponse{Items: make([]gen.DetectorTableRevision, 0, len(revs))}
	for _, r := range revs {
		out.Items = append(out.Items, revisionDTO(r))
	}
	return out, nil
}

// GetDetectorTableRevision implements getDetectorTableRevision.
func (h *Handlers) GetDetectorTableRevision(ctx context.Context, req gen.GetDetectorTableRevisionRequestObject) (gen.GetDetectorTableRevisionResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	r, err := svc.Revision(ctx, req.Revision)
	if err != nil {
		return nil, err
	}
	return gen.GetDetectorTableRevision200JSONResponse(revisionDTO(r)), nil
}

// GetDetectorTableUsage implements getDetectorTableUsage.
func (h *Handlers) GetDetectorTableUsage(ctx context.Context, _ gen.GetDetectorTableUsageRequestObject) (gen.GetDetectorTableUsageResponseObject, error) {
	svc, err := h.detectorService()
	if err != nil {
		return nil, err
	}
	e, err := svc.Effective(ctx)
	if err != nil {
		return nil, err
	}
	usage, err := svc.Usage(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.GetDetectorTableUsage200JSONResponse{Items: make([]gen.DetectorTableUsage, 0, len(usage))}
	for _, u := range usage {
		out.Items = append(out.Items, gen.DetectorTableUsage{Kind: gen.AgentKind(u.Kind), Reported: u.Reported,
			Digest: optString(u.Digest), Count: u.Count, Current: u.Reported && u.Digest == e.Digest})
	}
	return out, nil
}
