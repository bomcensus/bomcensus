// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	agentgen "github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/server/agentapi"
	"github.com/bomcensus/bomcensus/internal/server/auth"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/updatesvc"
)

// updates is agentapi.Updates over the update service.
type updates struct {
	svc *updatesvc.Service
}

var _ agentapi.Updates = updates{}

// CheckUpdate implements agentapi.Updates. The deployed version is passed
// on even when it is not newer than the caller's: agents decide themselves
// and never downgrade.
func (u updates) CheckUpdate(ctx context.Context, currentVersion, os, arch string) (agentgen.UpdateCheck, error) {
	c, err := u.svc.Check(ctx, currentVersion, os, arch)
	if err != nil {
		return agentgen.UpdateCheck{}, err
	}
	out := agentgen.UpdateCheck{CheckIntervalMinutes: c.CheckIntervalMinutes}
	if c.TargetVersion == "" {
		return out, nil
	}
	v := c.TargetVersion
	out.TargetVersion = &v
	if c.Manifest == nil {
		// The deployed release has no files for this platform.
		return out, nil
	}
	manifest, sig, size := c.Manifest, c.Signature, c.BundleSize
	files := make([]agentgen.ReleaseFile, 0, len(c.Files))
	for _, f := range c.Files {
		files = append(files, agentgen.ReleaseFile{Name: f.Name, Sha256: hex.EncodeToString(f.SHA256), Size: f.Size})
	}
	out.Manifest, out.ManifestSignature, out.Files, out.BundleSize = &manifest, &sig, &files, &size
	return out, nil
}

// Bundle implements agentapi.Updates.
func (u updates) Bundle(ctx context.Context, version, os, arch string) (io.ReadCloser, int64, error) {
	return u.svc.Bundle(ctx, version, os, arch)
}

// Probe implements agentapi.Updates.
func (u updates) Probe(ctx context.Context, os, arch string) ([]byte, string, error) {
	return u.svc.Probe(ctx, os, arch)
}

// reportIngest is agentapi.Ingest: uploads are accepted synchronously, so
// that decoding and authorization errors reach the uploader, and applied by
// the ingest_report job.
type reportIngest struct {
	ing   *ingest.Service
	queue job.Queue
	// scans, when set, receives scan job results; see Scans.
	scans Scans
	log   *slog.Logger
}

var _ agentapi.Ingest = (*reportIngest)(nil)

func sender(a store.Agent) ingest.Sender {
	return ingest.Sender{AgentID: a.ID, Kind: a.Kind, RemoteAddr: a.Address}
}

// Submit implements agentapi.Ingest. The job id of a scanner upload is not
// needed here: the scan job result lists the reports of the job.
func (r *reportIngest) Submit(ctx context.Context, from store.Agent, jobID string, raw []byte) (string, error) {
	id, err := r.ing.Accept(ctx, sender(from), raw)
	if err != nil {
		return "", err
	}
	res, err := r.queue.Enqueue(ctx, job.KindIngestReport, job.IngestReportArgs{ReportID: id},
		job.UniqueKey(job.IngestReportKey(id)))
	if err != nil {
		return "", fmt.Errorf("queue report %s: %w", id, err)
	}
	r.log.DebugContext(ctx, "report accepted", "report", id, "agent_id", from.ID, "job_id", jobID, "duplicate", res.Duplicate)
	return id, nil
}

// IngestK8sInventory implements agentapi.Ingest.
// After the inventory is stored, a scan service that observes inventories
// plans the exec collection of the cluster.
func (r *reportIngest) IngestK8sInventory(ctx context.Context, from store.Agent, inv agentgen.K8sInventory) error {
	if err := r.ing.IngestK8sInventory(ctx, sender(from), inv.ClusterId, inv); err != nil {
		return err
	}
	if o, ok := r.scans.(InventoryObserver); ok {
		if err := o.InventoryIngested(ctx, inv.ClusterId, inv); err != nil {
			r.log.WarnContext(ctx, "exec collection not planned", "cluster", inv.ClusterId, "agent_id", from.ID, "error", err)
		}
	}
	return nil
}

// RecordScanResult implements agentapi.Ingest. Scan jobs belong to the scan
// service; without one no job exists.
func (r *reportIngest) RecordScanResult(ctx context.Context, from store.Agent, jobID string, res agentgen.ScanJobResult) error {
	if r.scans == nil {
		return fmt.Errorf("scan job %q: no scan service: %w", jobID, store.ErrNotFound)
	}
	return r.scans.RecordJobResult(ctx, from, jobID, res)
}

// collector is inventoryapi.Collector: agents through dispatch, everything
// else through the scan service.
type collector struct {
	dispatch *dispatch.Service
	scans    Scans
}

// RequestCollect implements inventoryapi.Collector.
func (c collector) RequestCollect(ctx context.Context, assetID string) error {
	err := c.dispatch.RequestCollect(ctx, assetID)
	if !errors.Is(err, dispatch.ErrNotAgentBacked) {
		return err
	}
	if c.scans != nil {
		return c.scans.RequestCollect(ctx, assetID)
	}
	return fmt.Errorf("%w: %w", store.ErrInvalidState, err)
}

// cleanupStore is job.CleanupStore. The three expiries that belong to a
// service go through that service; the rest are plain store deletions.
type cleanupStore struct {
	store.Store
	auth     *auth.Service
	enroll   *enrollsvc.Service
	dispatch *dispatch.Service
}

var _ job.CleanupStore = cleanupStore{}

func (c cleanupStore) DeleteExpiredSessions(ctx context.Context, _ time.Time) (int64, error) {
	return c.auth.PurgeExpired(ctx)
}

func (c cleanupStore) DeleteExpiredEnrollSessions(ctx context.Context, _ time.Time) (int64, error) {
	return c.enroll.Cleanup(ctx)
}

func (c cleanupStore) DeleteExpiredDirectives(ctx context.Context, now, ackedBefore time.Time) (int64, error) {
	keep := time.Duration(1<<63 - 1) // a zero ackedBefore keeps acknowledged directives
	if !ackedBefore.IsZero() {
		keep = now.Sub(ackedBefore)
	}
	return c.dispatch.Cleanup(ctx, keep)
}
