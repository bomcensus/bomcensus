// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

const (
	maxDetectDirPath        = 1024
	maxDetectDirDescription = 200
)

func detectDirDTO(d store.DetectDir) gen.DetectDir {
	return gen.DetectDir{
		Id:          d.ID,
		Path:        d.Path,
		Description: optString(d.Description),
		Agents:      d.Agents,
		ScanTargets: d.ScanTargets,
		CreatedAt:   d.CreatedAt,
	}
}

// cleanDetectPath validates an absolute directory and returns it cleaned.
// Glob characters are refused: the path is walked as it is.
func cleanDetectPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	switch {
	case !strings.HasPrefix(p, "/"):
		return "", apierr.Invalid("path must be absolute")
	case strings.ContainsAny(p, "*?["):
		return "", apierr.Invalid("path must not contain glob characters")
	case strings.ContainsFunc(p, unicode.IsControl):
		return "", apierr.Invalid("path must not contain control characters")
	}
	p = path.Clean(p)
	if len(p) > maxDetectDirPath {
		return "", apierr.Invalid("path must be at most %d bytes", maxDetectDirPath)
	}
	return p, nil
}

func cleanDetectDescription(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case utf8.RuneCountInString(s) > maxDetectDirDescription:
		return "", apierr.Invalid("description must be at most %d characters", maxDetectDirDescription)
	case strings.ContainsFunc(s, unicode.IsControl):
		return "", apierr.Invalid("description must not contain control characters")
	}
	return s, nil
}

// ListDetectDirs implements listDetectDirs.
func (h *Handlers) ListDetectDirs(ctx context.Context, _ gen.ListDetectDirsRequestObject) (gen.ListDetectDirsResponseObject, error) {
	dirs, err := h.st.ListDetectDirs(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListDetectDirs200JSONResponse{Items: make([]gen.DetectDir, 0, len(dirs)), Total: len(dirs)}
	for _, d := range dirs {
		out.Items = append(out.Items, detectDirDTO(d))
	}
	return out, nil
}

// CreateDetectDir implements createDetectDir.
func (h *Handlers) CreateDetectDir(ctx context.Context, req gen.CreateDetectDirRequestObject) (gen.CreateDetectDirResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	p, err := cleanDetectPath(b.Path)
	if err != nil {
		return nil, err
	}
	desc, err := cleanDetectDescription(deref(b.Description))
	if err != nil {
		return nil, err
	}
	d, err := h.st.CreateDetectDir(ctx, store.DetectDir{Path: p, Description: desc})
	if err != nil {
		return nil, err
	}
	h.log.Info("detect directory added", "detect_dir_id", d.ID, "path", d.Path, "by", h.who(ctx))
	return gen.CreateDetectDir201JSONResponse(detectDirDTO(d)), nil
}

// UpdateDetectDir implements updateDetectDir.
func (h *Handlers) UpdateDetectDir(ctx context.Context, req gen.UpdateDetectDirRequestObject) (gen.UpdateDetectDirResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	d, err := h.st.GetDetectDir(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if b.Path != nil {
		if d.Path, err = cleanDetectPath(*b.Path); err != nil {
			return nil, err
		}
	}
	if b.Description != nil {
		if d.Description, err = cleanDetectDescription(*b.Description); err != nil {
			return nil, err
		}
	}
	if d, err = h.st.UpdateDetectDir(ctx, d); err != nil {
		return nil, err
	}
	h.log.Info("detect directory updated", "detect_dir_id", d.ID, "path", d.Path, "by", h.who(ctx))
	return gen.UpdateDetectDir200JSONResponse(detectDirDTO(d)), nil
}

// DeleteDetectDir implements deleteDetectDir.
func (h *Handlers) DeleteDetectDir(ctx context.Context, req gen.DeleteDetectDirRequestObject) (gen.DeleteDetectDirResponseObject, error) {
	if err := h.st.DeleteDetectDir(ctx, req.Id); err != nil {
		return nil, err
	}
	h.log.Info("detect directory deleted", "detect_dir_id", req.Id, "by", h.who(ctx))
	return gen.DeleteDetectDir204Response{}, nil
}

// checkDetectDirs checks that every id names a stored detect directory, so
// that an unknown one is a 400 and not a 404 of the agent or target.
func (h *Handlers) checkDetectDirs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	dirs, err := h.st.ListDetectDirs(ctx)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		known[d.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return apierr.Invalid("detect directory %s does not exist", id)
		}
	}
	return nil
}

// orEmpty keeps JSON arrays from rendering as null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
