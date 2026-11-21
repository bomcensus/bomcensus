// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net/http"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/updatesvc"
)

func releaseDTO(r updatesvc.Release) gen.Release {
	platforms := make([]string, 0, len(r.Platforms))
	for _, p := range r.Platforms {
		platforms = append(platforms, p.String())
	}
	return gen.Release{
		Version:     r.Version,
		PublishedAt: r.PublishedAt,
		ImportedAt:  r.CreatedAt,
		Source:      gen.ReleaseSource(r.Source),
		Verified:    r.Verified,
		Notes:       r.Notes,
		Platforms:   platforms,
	}
}

// ListReleases implements listReleases.
func (h *Handlers) ListReleases(ctx context.Context, req gen.ListReleasesRequestObject) (gen.ListReleasesResponseObject, error) {
	p := req.Params
	all, err := h.updates.List(ctx)
	if err != nil {
		return nil, err
	}
	kept := all[:0]
	for _, r := range all {
		if (p.Source == nil || string(r.Source) == string(*p.Source)) &&
			(p.Verified == nil || r.Verified == *p.Verified) &&
			matches(p.Q, r.Version, r.Notes) {
			kept = append(kept, r)
		}
	}
	field, desc := parseSort(p.Sort, "-version")
	sortBy(kept, desc, func(x, y updatesvc.Release) int {
		var c int
		switch field {
		case "publishedAt":
			c = x.PublishedAt.Compare(y.PublishedAt)
		case "importedAt":
			c = x.CreatedAt.Compare(y.CreatedAt)
		}
		return cmp.Or(c, updatesvc.CompareVersions(x.Version, y.Version))
	})
	out := gen.ListReleases200JSONResponse{Items: []gen.Release{}, Total: len(kept)}
	for _, r := range paginate(kept, pageOf(p.Limit, p.Offset)) {
		out.Items = append(out.Items, releaseDTO(r))
	}
	return out, nil
}

// UploadRelease implements uploadRelease. The bundle part is streamed into
// release verification; nothing else of the body is kept.
func (h *Handlers) UploadRelease(ctx context.Context, req gen.UploadReleaseRequestObject) (gen.UploadReleaseResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.Invalid("multipart body is required")
	}
	for {
		part, err := req.Body.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, apierr.Invalid("the bundle part is missing")
		}
		if err != nil {
			return nil, apierrInvalidOr(err, "malformed multipart body")
		}
		if part.FormName() != "bundle" {
			part.Close()
			continue
		}
		r, err := h.updates.Import(ctx, part, store.ReleaseUpload)
		part.Close()
		if err != nil {
			if isConflict(err) {
				return nil, apierr.Conflict("this version is stored with a different manifest").Wrap(err)
			}
			return nil, mapErr(err)
		}
		h.log.Info("release uploaded", "version", r.Version, "by", h.who(ctx))
		return gen.UploadRelease201JSONResponse(releaseDTO(r)), nil
	}
}

// apierrInvalidOr keeps a body-size error as it is (413) and turns other
// read errors into 400.
func apierrInvalidOr(err error, msg string) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return err
	}
	return apierr.Invalid("%s", msg).Wrap(err)
}

func updateSettingsDTO(s store.UpdateSettings) gen.UpdateSettings {
	return gen.UpdateSettings{TargetVersion: optString(s.TargetVersion), CheckIntervalMinutes: s.CheckIntervalMinutes}
}

// GetUpdateSettings implements getUpdateSettings.
func (h *Handlers) GetUpdateSettings(ctx context.Context, _ gen.GetUpdateSettingsRequestObject) (gen.GetUpdateSettingsResponseObject, error) {
	s, err := h.updates.Settings(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetUpdateSettings200JSONResponse(updateSettingsDTO(s)), nil
}

// SetUpdateSettings implements setUpdateSettings.
func (h *Handlers) SetUpdateSettings(ctx context.Context, req gen.SetUpdateSettingsRequestObject) (gen.SetUpdateSettingsResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.Invalid("request body is required")
	}
	s := store.UpdateSettings{TargetVersion: deref(req.Body.TargetVersion), CheckIntervalMinutes: req.Body.CheckIntervalMinutes}
	if err := h.updates.SetSettings(ctx, s); err != nil {
		return nil, mapErr(err)
	}
	h.log.Info("update settings changed", "target_version", s.TargetVersion, "check_interval_minutes", s.CheckIntervalMinutes, "by", h.who(ctx))
	s, err := h.updates.Settings(ctx)
	if err != nil {
		return nil, err
	}
	return gen.SetUpdateSettings200JSONResponse(updateSettingsDTO(s)), nil
}
