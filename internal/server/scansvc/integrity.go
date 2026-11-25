// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report/reportapi"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

const (
	// IntegrityPerScanner bounds the integrity chunks one scanner (or the
	// embedded scanner) runs at once, so that collections keep workers.
	IntegrityPerScanner = 2
	// integrityBackoff is the wait after a chunk that left no result
	// (connection lost, package manager running).
	integrityBackoff = 10 * time.Minute
)

// ScheduleSSHIntegrity starts the due integrity chunks of scan targets:
// a target whose effective integrity mode is on, that was collected once
// (it has an asset), inside the window in the host's local time. It runs
// with the SSH scheduler.
func (s *Service) ScheduleSSHIntegrity(ctx context.Context) error {
	pol, err := integritysvc.Load(ctx, s.st)
	if err != nil {
		return fmt.Errorf("scansvc: %w", err)
	}
	now := s.now().UTC()
	var targets []store.ScanTarget
	for off := 0; ; {
		page, total, err := s.st.ListScanTargets(ctx, store.ScanTargetFilter{}, store.Page{Limit: 1000, Offset: off})
		if err != nil {
			return fmt.Errorf("scansvc: list scan targets: %w", err)
		}
		targets = append(targets, page...)
		off += len(page)
		if len(page) == 0 || off >= total {
			break
		}
	}
	type due struct {
		t     store.ScanTarget
		chunk integritysvc.Chunk
	}
	running := map[string]int{}
	var queue []due
	for _, t := range targets {
		if t.AssetID == "" || !integritysvc.Enabled(t.Integrity, pol.SSH) {
			continue
		}
		if l, err := s.leases.Get(ctx, leaseKey(kindIntegrity, t.ID)); err == nil && l.Active(now) {
			running[t.ScannerID]++
			continue
		} else if err != nil {
			return fmt.Errorf("scansvc: integrity lease of %s: %w", t.ID, err)
		}
		var last *store.IntegrityPass
		p, err := s.st.LastIntegrityPass(ctx, t.AssetID)
		switch {
		case err == nil:
			last = &p
		case !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("scansvc: integrity pass of %s: %w", t.ID, err)
		}
		if s.backingOff(t.ID, last, now) {
			continue
		}
		if c, ok := integritysvc.NextChunk(pol, t.ID, last, now); ok {
			queue = append(queue, due{t, c})
		}
	}
	var errs []error
	for _, d := range queue {
		if running[d.t.ScannerID] >= IntegrityPerScanner {
			continue
		}
		err := s.startIntegrity(ctx, d.t, d.chunk)
		if err == nil {
			running[d.t.ScannerID]++
			s.markTried(d.t.ID, now)
			continue
		}
		if !ignorable(err) && !errors.Is(err, ErrScannerUnavailable) && !errors.Is(err, ErrNoScanner) {
			errs = append(errs, err)
		}
		s.logStart("integrity", d.t.ID, err)
	}
	return errors.Join(errs...)
}

// backingOff reports whether the last chunk started for the target ended
// without a recorded result less than integrityBackoff ago.
func (s *Service) backingOff(targetID string, last *store.IntegrityPass, now time.Time) bool {
	s.integrityMu.Lock()
	defer s.integrityMu.Unlock()
	tried, ok := s.integrityTried[targetID]
	if !ok || now.Sub(tried) >= integrityBackoff {
		return false
	}
	return last == nil || last.LastChunkAt.Before(tried)
}

func (s *Service) markTried(targetID string, at time.Time) {
	s.integrityMu.Lock()
	defer s.integrityMu.Unlock()
	if s.integrityTried == nil {
		s.integrityTried = map[string]time.Time{}
	}
	s.integrityTried[targetID] = at
}

// startIntegrity runs a chunk on the embedded scanner or sends it to the
// target's scanner, when that scanner runs integrity chunks.
func (s *Service) startIntegrity(ctx context.Context, t store.ScanTarget, c integritysvc.Chunk) error {
	jobID := newJobID(kindIntegrity, t.ID)
	policy := s.sshPolicy(ctx, t)
	policy.MaxRuntimeSeconds = int(c.Limit / time.Second)
	if t.ScannerID == "" {
		return s.startEmbedded(ctx, leaseKey(kindIntegrity, t.ID), jobID, func(ctx context.Context) {
			sink := &embeddedSink{s: s}
			cred, secret, err := s.sshSecret(ctx, t)
			if err != nil {
				s.failJob(ctx, sink, jobID, runner.ReasonSecret, err)
				return
			}
			q := c.Query
			job := runner.SSHJob{
				JobID: jobID, TargetID: t.ID, Address: t.Address, Port: t.Port, User: cred.Username,
				Credential: secret, Sudo: t.Sudo, HostKey: t.HostKey, Policy: policy, Integrity: &q,
			}
			if _, err := s.run.RunSSH(ctx, job, s.deps(sink)); err != nil {
				s.log.Warn("result of an embedded integrity chunk was not stored", "job_id", jobID, "error", err)
			}
		})
	}
	sc, err := s.scanner(ctx, t.ScannerID)
	if err != nil {
		return err
	}
	if !sc.HasFeature(store.FeatureIntegrity) {
		return nil
	}
	cred, secret, err := s.sshSecret(ctx, t)
	if err != nil {
		return fmt.Errorf("scansvc: scan target %s: %w", t.ID, err)
	}
	sealed, err := sealSSHCredential(sc, jobID, cred, secret)
	if err != nil {
		return err
	}
	port := t.Port
	if port == 0 {
		port = 22
	}
	q := reportapi.APIIntegrityQuery(c.Query)
	d := agentapi.ScanSshDirective{
		Type: agentapi.ScanSsh, JobId: jobID, ScanTargetId: t.ID, Address: t.Address, Port: port,
		Username: cred.Username, Sudo: t.Sudo, Credential: sealed, Policy: runner.PolicyToAPI(policy),
		Integrity: &q,
	}
	if len(t.HostKey) > 0 {
		key, err := gossh.ParsePublicKey(t.HostKey)
		if err != nil {
			return fmt.Errorf("scansvc: scan target %s: stored host key: %w", t.ID, err)
		}
		fp := gossh.FingerprintSHA256(key)
		wire := key.Marshal()
		d.HostKeyFingerprint, d.HostKey = &fp, &wire
	}
	var body agentapi.Directive
	if err := body.FromScanSshDirective(d); err != nil {
		return err
	}
	return s.submitDirective(ctx, sc, leaseKey(kindIntegrity, t.ID), "scan_ssh_integrity:"+t.ID, jobID, body, sshTimeout())
}

// applyIntegrityResult checks the sender of a chunk's result. The chunk's
// report was ingested on its own; the result does not count as a scan of
// the target.
func (s *Service) applyIntegrityResult(ctx context.Context, sender ingest.Sender, targetID string, res agentapi.ScanJobResult) error {
	t, err := s.st.GetScanTarget(ctx, targetID)
	if err != nil {
		return fmt.Errorf("scansvc: scan target %s: %w", targetID, err)
	}
	if t.ScannerID != sender.AgentID {
		return forbidden("scan target %s is not assigned to scanner %q", t.ID, sender.AgentID)
	}
	if res.Status == agentapi.ScanJobStatusFailed {
		msg := ""
		if res.Message != nil {
			msg = *res.Message
		}
		s.log.Warn("integrity chunk failed", "scan_target", t.ID, "message", msg)
	}
	return nil
}
