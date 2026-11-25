// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// embeddedSink applies the output of embedded jobs directly.
type embeddedSink struct{ s *Service }

func (e *embeddedSink) SubmitReport(ctx context.Context, enc []byte, _ string) error {
	return e.s.ing.IngestReport(ctx, ingest.EmbeddedScanner(), enc)
}

func (e *embeddedSink) SubmitInventory(ctx context.Context, inv agentapi.K8sInventory) error {
	return e.s.ing.IngestK8sInventory(ctx, ingest.EmbeddedScanner(), inv.ClusterId, inv)
}

func (e *embeddedSink) SubmitResult(ctx context.Context, jobID string, res runner.Result) error {
	return e.s.applyResult(ctx, ingest.EmbeddedScanner(), jobID, res.ScanJobResult)
}

// RecordJobResult stores the outcome of a job reported by a remote scanner
// (POST /agent/v1/scan-jobs/{id}/result). The host key of a scan_ssh
// result is pinned on the first successful scan. An unknown job id is
// store.ErrNotFound; a job of a subject not assigned to the sender is an
// error with Permanent() true.
func (s *Service) RecordJobResult(ctx context.Context, sender store.Agent, jobID string, res agentapi.ScanJobResult) error {
	if sender.Kind != store.AgentKindScanner || sender.ID == "" {
		return forbidden("only scanners report scan jobs")
	}
	return s.applyResult(ctx, ingest.Sender{AgentID: sender.ID, Kind: sender.Kind, RemoteAddr: sender.Address}, jobID, res)
}

func (s *Service) applyResult(ctx context.Context, sender ingest.Sender, jobID string, res agentapi.ScanJobResult) error {
	kind, subject, ok := parseJobID(jobID)
	if !ok {
		return fmt.Errorf("scansvc: scan job %q: %w", jobID, store.ErrNotFound)
	}
	switch res.Status {
	case agentapi.ScanJobStatusOk, agentapi.ScanJobStatusPartial, agentapi.ScanJobStatusFailed:
	default:
		return &permanentError{fmt.Errorf("scansvc: unknown job status %q: %w", res.Status, store.ErrInvalid)}
	}
	var err error
	switch kind {
	case kindSSH:
		err = s.applySSHResult(ctx, sender, subject, res)
	case kindSync:
		err = s.applySyncResult(ctx, sender, subject, res)
	case kindExec:
		err = s.applyExecResult(ctx, sender, subject, res)
	case kindIntegrity:
		err = s.applyIntegrityResult(ctx, sender, subject, res)
	}
	if err != nil {
		return err
	}
	if sender.AgentID != "" {
		// Embedded jobs release their lease when their goroutine ends.
		if rerr := s.leases.Release(ctx, leaseKey(kind, subject), jobID); rerr != nil {
			s.log.Warn("cannot release scan lease", "job_id", jobID, "error", rerr)
		}
	}
	s.log.Info("scan job finished", "job_id", jobID, "status", res.Status, "scanner", sender.AgentID)
	return nil
}

// cluster loads a cluster and checks that sender is its scanner.
func (s *Service) cluster(ctx context.Context, sender ingest.Sender, id string) (store.K8sCluster, error) {
	c, err := s.st.GetCluster(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return c, fmt.Errorf("scansvc: cluster %s: %w", id, store.ErrNotFound)
	}
	if err != nil {
		return c, fmt.Errorf("scansvc: cluster %s: %w", id, err)
	}
	if c.ScannerID != sender.AgentID {
		return c, forbidden("cluster %s is not assigned to scanner %q", c.ID, sender.AgentID)
	}
	return c, nil
}

func finishedAt(res agentapi.ScanJobResult, now time.Time) time.Time {
	if res.FinishedAt.IsZero() {
		return now
	}
	return res.FinishedAt.UTC()
}

// applySyncResult records the sync status. A successful sync already
// recorded ok when its inventory was stored; warnings are added here.
func (s *Service) applySyncResult(ctx context.Context, sender ingest.Sender, clusterID string, res agentapi.ScanJobResult) error {
	c, err := s.cluster(ctx, sender, clusterID)
	if err != nil {
		return err
	}
	msg := ""
	if res.Message != nil {
		msg = *res.Message
	}
	status := store.K8sSyncOK
	if res.Status == agentapi.ScanJobStatusFailed {
		status = store.K8sSyncFailed
	} else if msg == "" {
		return nil
	}
	if err := s.st.RecordClusterSync(ctx, c.ID, status, msg, finishedAt(res, s.now())); err != nil {
		return fmt.Errorf("scansvc: record sync of %s: %w", c.ID, err)
	}
	return nil
}

// applyExecResult records the coverage of containers that produced no
// report; those with a report got theirs from ingest.
func (s *Service) applyExecResult(ctx context.Context, sender ingest.Sender, clusterID string, res agentapi.ScanJobResult) error {
	c, err := s.cluster(ctx, sender, clusterID)
	if err != nil {
		return err
	}
	if res.Targets == nil {
		return nil
	}
	for _, t := range *res.Targets {
		if t.Status != agentapi.ScanJobStatusFailed {
			continue
		}
		reason := ""
		if t.Reason != nil {
			reason = *t.Reason
		}
		cov := store.Coverage(t.Coverage)
		if cov != store.CoverageUnsupported {
			cov = store.CoverageFailed
		}
		err := s.st.SetPodContainerCoverage(ctx, c.ID, t.Namespace, t.Pod, t.Container, cov, reason)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("scansvc: coverage of %s/%s/%s: %w", t.Namespace, t.Pod, t.Container, err)
		}
	}
	return nil
}
