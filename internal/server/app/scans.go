// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package app

import (
	"context"
	"log/slog"

	agentgen "github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/inventoryapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/manageapi"
	"github.com/bomcensus/bomcensus/internal/server/detectorsvc"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/scansvc"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/updatesvc"
	"github.com/bomcensus/bomcensus/server/config"
)

// Scans is the seam for the scan service: SSH scan targets, Kubernetes
// clusters, scan jobs handed to scanners and the embedded scanner. Run works
// without one; the operations below then answer 503 (run, sync), 409
// (collecting an asset no agent collects) and 404 (scan job results).
type Scans interface {
	// RequestRun starts an on-demand scan of a scan target
	// (manageapi.ScanRunner).
	RequestRun(ctx context.Context, targetID string) error
	// RequestSync asks for an inventory sync of a Kubernetes cluster now
	// (inventoryapi.ClusterSyncer).
	RequestSync(ctx context.Context, clusterID string) error
	// RequestCollect collects an asset that no agent collects: the host of
	// a scan target or a Kubernetes workload. It is called for the assets
	// dispatch reports as dispatch.ErrNotAgentBacked, with the errors of
	// inventoryapi.Collector.
	RequestCollect(ctx context.Context, assetID string) error
	// RecordJobResult stores the outcome of a scan job reported by a
	// scanner (operation submitScanJobResult). An unknown job is
	// store.ErrNotFound; errors are classified as for agentapi.Ingest.
	RecordJobResult(ctx context.Context, sender store.Agent, jobID string, res agentgen.ScanJobResult) error
	// Run does the background work (the embedded scanner, dial-outs) until
	// ctx ends. It returns nil or ctx's error after a shutdown; any other
	// error stops the server.
	Run(ctx context.Context) error
}

var (
	_ manageapi.ScanRunner       = Scans(nil)
	_ inventoryapi.ClusterSyncer = Scans(nil)
)

// Services are the wired components a scan service builds on.
type Services struct {
	Config config.Config
	Store  store.Store
	// Queue is not started yet when NewScans runs: Register the scan job
	// kinds (job.KindScanSSHDue, job.KindK8sSyncDue) and their Periodic
	// schedules there.
	Queue    job.Queue
	Dispatch *dispatch.Service
	Ingest   *ingest.Service
	Updates  *updatesvc.Service
	PKI      *pkisvc.Service
	Secrets  *secret.Box
	// Detectors is the detector table service.
	Detectors *detectorsvc.Service
	Logger    *slog.Logger
}

// NewScans builds the scan service from the wired components. It is called
// once in Run, after the PKI is bootstrapped and before the queue starts and
// the listeners accept connections.
type NewScans func(ctx context.Context, s Services) (Scans, error)

// InventoryObserver is implemented by a Scans that wants to know when a
// remote scanner's Kubernetes inventory was stored, to plan the exec
// collection of the cluster. Its errors are logged; the upload succeeded.
type InventoryObserver interface {
	InventoryIngested(ctx context.Context, clusterID string, inv agentgen.K8sInventory) error
}

var (
	_ Scans             = (*scansvc.Service)(nil)
	_ InventoryObserver = (*scansvc.Service)(nil)
)

// ScanService is the NewScans of internal/server/scansvc. The embedded
// scanner follows Config.EmbeddedScanner; the scheduler jobs are
// registered on the queue.
func ScanService(_ context.Context, s Services) (Scans, error) {
	cfg := scansvc.Config{
		Store:           s.Store,
		Ingest:          s.Ingest,
		Secrets:         s.Secrets,
		Queue:           s.Queue,
		EmbeddedScanner: s.Config.EmbeddedScanner,
		Logger:          s.Logger,
	}
	if s.Dispatch != nil {
		cfg.Notify = s.Dispatch
	}
	if s.Updates != nil {
		cfg.Probe = s.Updates.Probe
	}
	if s.Detectors != nil {
		cfg.Detectors = s.Detectors.ForProbe
	}
	return scansvc.New(cfg)
}
