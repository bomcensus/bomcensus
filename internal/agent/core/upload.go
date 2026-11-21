// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
)

// ReportMeta is stored with a spooled report and passed to OnUploaded
// functions once the server accepted it.
type ReportMeta struct {
	// JobID is sent as the job_id query parameter (scanner).
	JobID string `json:"job_id,omitempty"`
	// Digests are the section digests of the report.
	Digests map[string]string `json:"digests,omitempty"`
	// ReportID is set by the server on acceptance; it is not stored.
	ReportID string `json:"-"`
}

// SubmitReport queues an encoded report and uploads the queue in order.
// The report is written to the spool first, so it survives a failed
// upload, a shutdown during the upload and a restart. It returns the
// upload error; the report then stays queued.
func (r *Runtime) SubmitReport(ctx context.Context, encoded []byte, meta ReportMeta) error {
	mb, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	r.uploadMu.Lock()
	dropped, err := r.spool.Put(encoded, mb)
	r.uploadMu.Unlock()
	for _, name := range dropped {
		r.log.Warn("report spool full, dropped the oldest report", "entry", name)
	}
	if errors.Is(err, state.ErrTooLarge) {
		r.log.Warn("report is larger than the spool, sending it without spooling", "size", len(encoded))
		if err := r.FlushSpool(ctx); err != nil {
			return err
		}
		id, err := r.upload(ctx, encoded, meta.JobID)
		if err != nil {
			return err
		}
		meta.ReportID = id
		r.uploaded(ctx, meta)
		return nil
	}
	if err != nil {
		return err
	}
	return r.FlushSpool(ctx)
}

// FlushSpool uploads spooled reports, oldest first, and stops at the first
// failure that may be temporary. Reports the server refuses as malformed
// or too large are dropped.
func (r *Runtime) FlushSpool(ctx context.Context) error {
	r.uploadMu.Lock()
	defer r.uploadMu.Unlock()
	entries, err := r.spool.List()
	if err != nil {
		return err
	}
	for _, e := range entries {
		data, err := r.spool.Read(e.Name)
		if err != nil {
			r.log.Warn("dropping unreadable spooled report", "entry", e.Name, "error", err)
			_ = r.spool.Remove(e.Name)
			continue
		}
		var meta ReportMeta
		_ = json.Unmarshal(e.Meta, &meta)
		id, err := r.upload(ctx, data, meta.JobID)
		if err != nil {
			if IsStatus(err, http.StatusBadRequest) || IsStatus(err, http.StatusRequestEntityTooLarge) {
				r.log.Error("server refused a report, dropping it", "entry", e.Name, "error", err)
				_ = r.spool.Remove(e.Name)
				continue
			}
			return err
		}
		if err := r.spool.Remove(e.Name); err != nil {
			return err
		}
		meta.ReportID = id
		r.log.Info("report uploaded", "report_id", id, "size", len(data))
		r.uploaded(ctx, meta)
	}
	return nil
}

// SpoolLen returns the number of queued reports.
func (r *Runtime) SpoolLen() int {
	entries, err := r.spool.List()
	if err != nil {
		return 0
	}
	return len(entries)
}

func (r *Runtime) uploaded(ctx context.Context, meta ReportMeta) {
	for _, f := range r.uploadFuncs {
		f(ctx, meta)
	}
}

func (r *Runtime) upload(ctx context.Context, data []byte, jobID string) (string, error) {
	var params agentapi.UploadReportParams
	if jobID != "" {
		params.JobId = &jobID
	}
	resp, err := r.client.UploadReportWithBodyWithResponse(ctx, &params, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	var acc agentapi.ReportAccepted
	if err := DecodeResponse(resp.HTTPResponse, resp.Body, http.StatusAccepted, &acc); err != nil {
		return "", err
	}
	return acc.ReportId, nil
}
