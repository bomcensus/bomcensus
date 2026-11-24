// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"errors"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// ListComponentVulnerabilities implements gen.StrictServerInterface.
func (h *Handlers) ListComponentVulnerabilities(ctx context.Context, req gen.ListComponentVulnerabilitiesRequestObject) (gen.ListComponentVulnerabilitiesResponseObject, error) {
	if _, err := h.cfg.Store.GetComponent(ctx, req.Id); errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("component")
	} else if err != nil {
		return nil, err
	}
	out := gen.ListComponentVulnerabilities200JSONResponse{Items: []gen.ComponentVulnerability{}}
	m, e, at, err := h.cfg.Store.GetComponentMatch(ctx, req.Id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return out, nil
	case err != nil:
		return nil, err
	}
	out.Match = &gen.ComponentMatchState{Status: gen.ComponentMatchStateStatus(m.Status), Revision: e.Revision, MatchedAt: at,
		Reason: optStr(m.Reason), OsKey: optStr(m.OSKey)}
	rows, err := h.cfg.Store.ListComponentVulns(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out.Items = append(out.Items, componentVulnDTO(r))
	}
	return out, nil
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func componentVulnDTO(r store.ComponentVulnRow) gen.ComponentVulnerability {
	v := gen.ComponentVulnerability{
		VulnId: r.VulnID, Aliases: r.Meta.Aliases, Summary: optStr(r.Meta.Summary), Score: r.Meta.MaxScore,
		Kev: r.Meta.KEV != nil, Epss: r.Meta.EPSS, EpssPercentile: r.Meta.EPSSPercentile, Published: r.Meta.Published,
		Method: gen.ComponentVulnerabilityMethod(r.Method), Ecosystem: optStr(r.Ecosystem), FixState: gen.FixState(r.FixState),
		FixedVersion: optStr(r.FixedVersion), Platforms: r.Platforms, Advisories: make([]gen.VulnAdvisory, 0, len(r.Advisories)),
	}
	if v.Aliases == nil {
		v.Aliases = []string{}
	}
	if v.Platforms == nil {
		v.Platforms = []string{}
	}
	if r.Meta.Severity != "" {
		s := gen.Severity(r.Meta.Severity)
		v.Severity = &s
	}
	if r.Meta.KEV != nil {
		if t, err := time.Parse(time.DateOnly, r.Meta.KEV.DateAdded); err == nil {
			v.KevAdded = &openapi_types.Date{Time: t}
		}
	}
	if r.CPEMatch != "" {
		c := gen.ComponentVulnerabilityCpeMatch(r.CPEMatch)
		v.CpeMatch = &c
	}
	if r.RangeSource != "" {
		s := gen.ComponentVulnerabilityRangeSource(r.RangeSource)
		v.RangeSource = &s
	}
	for _, a := range r.Advisories {
		v.Advisories = append(v.Advisories, gen.VulnAdvisory{Source: a.Source, Id: a.ID, Severity: optStr(a.Severity)})
	}
	return v
}
