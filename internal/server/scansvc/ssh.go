// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	gossh "golang.org/x/crypto/ssh"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/report/reportapi"
	"github.com/bomcensus/bomcensus/internal/scanner/runner"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// RequestRun starts an on-demand scan of a scan target: in this process
// when no scanner is assigned, otherwise as a directive to the scanner.
// It returns ErrInFlight when a scan of the target is already running,
// ErrNoScanner when the target has no scanner and the embedded scanner is
// off and ErrScannerUnavailable when the assigned scanner cannot take work.
func (s *Service) RequestRun(ctx context.Context, targetID string) error {
	t, err := s.st.GetScanTarget(ctx, targetID)
	if err != nil {
		return fmt.Errorf("scansvc: scan target %s: %w", targetID, err)
	}
	return s.startSSH(ctx, t)
}

func (s *Service) startSSH(ctx context.Context, t store.ScanTarget) error {
	jobID := newJobID(kindSSH, t.ID)
	if t.ScannerID == "" {
		return s.startEmbedded(ctx, leaseKey(kindSSH, t.ID), jobID, func(ctx context.Context) {
			s.runEmbeddedSSH(ctx, t, jobID)
		})
	}
	sc, err := s.scanner(ctx, t.ScannerID)
	if err != nil {
		return err
	}
	return s.dispatchSSH(ctx, sc, t, jobID)
}

// ScheduleSSH starts the scans that are due: the embedded scanner's in this
// process, the remote scanners' as directives. It is the handler of
// job.KindScanSSHDue.
func (s *Service) ScheduleSSH(ctx context.Context) error {
	now := s.now().UTC()
	var errs []error
	if s.embedded {
		due, err := s.st.ListDueScanTargets(ctx, "", now, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("scansvc: due scan targets: %w", err))
		}
		for _, t := range due {
			s.logStart("ssh", t.ID, s.startSSH(ctx, t))
		}
	}
	scanners, err := s.scanners(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, sc := range scanners {
		due, err := s.st.ListDueScanTargets(ctx, sc.ID, now, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("scansvc: due scan targets of %s: %w", sc.ID, err))
			continue
		}
		for _, t := range due {
			s.logStart("ssh", t.ID, s.startSSH(ctx, t))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) logStart(kind, subject string, err error) {
	switch {
	case err == nil:
	case ignorable(err):
		s.log.Debug("scheduled job not started", "kind", kind, "subject", subject, "reason", err)
	default:
		s.log.Warn("scheduled job not started", "kind", kind, "subject", subject, "error", err)
	}
}

// sshSecret opens the credential of a target.
func (s *Service) sshSecret(ctx context.Context, t store.ScanTarget) (store.Credential, runner.SSHCredential, error) {
	cred, err := s.st.GetCredentialWithSecret(ctx, t.CredentialID)
	if err != nil {
		return cred, runner.SSHCredential{}, fmt.Errorf("credential %s: %w", t.CredentialID, err)
	}
	if cred.Kind != store.CredentialSSHKey && cred.Kind != store.CredentialSSHPassword {
		return cred, runner.SSHCredential{}, fmt.Errorf("credential %s is not an SSH credential", cred.ID)
	}
	sec, err := s.secrets.OpenCredential(cred.ID, cred.Secret)
	if err != nil {
		return cred, runner.SSHCredential{}, fmt.Errorf("credential %s: %w", cred.ID, err)
	}
	out := runner.SSHCredential{Password: sec.Password}
	if sec.PrivateKey != "" {
		out.PrivateKey = []byte(sec.PrivateKey)
	}
	if sec.Passphrase != "" {
		out.Passphrase = []byte(sec.Passphrase)
	}
	return cred, out, nil
}

func (s *Service) runEmbeddedSSH(ctx context.Context, t store.ScanTarget, jobID string) {
	sink := &embeddedSink{s: s}
	cred, secret, err := s.sshSecret(ctx, t)
	if err != nil {
		s.failJob(ctx, sink, jobID, runner.ReasonSecret, err)
		return
	}
	job := runner.SSHJob{
		JobID: jobID, TargetID: t.ID, Address: t.Address, Port: t.Port, User: cred.Username,
		Credential: secret, Sudo: t.Sudo, HostKey: t.HostKey, Policy: s.sshPolicy(ctx, t),
		GoSymbols: s.goSymbols(ctx, t.AssetID, ""),
	}
	if _, err := s.run.RunSSH(ctx, job, s.deps(sink)); err != nil {
		s.log.Warn("result of an embedded scan was not stored", "job_id", jobID, "error", err)
	}
}

// failJob records a job that could not be started.
func (s *Service) failJob(ctx context.Context, sink runner.Sink, jobID, reason string, cause error) {
	now := s.now().UTC()
	msg := runner.Message(reason, cause.Error())
	res := runner.Result{ScanJobResult: agentapi.ScanJobResult{Status: agentapi.ScanJobStatusFailed, Message: &msg,
		StartedAt: now, FinishedAt: now}}
	s.log.Warn("scan job failed before it started", "job_id", jobID, "reason", reason, "error", cause)
	if err := sink.SubmitResult(context.WithoutCancel(ctx), jobID, res); err != nil {
		s.log.Warn("cannot record the failed job", "job_id", jobID, "error", err)
	}
}

// dispatchSSH sends a scan_ssh directive with the credential sealed to the
// scanner. The pinned host key is sent as fingerprint and in full, so the
// scanner can enforce it before it sends credentials.
func (s *Service) dispatchSSH(ctx context.Context, sc store.Agent, t store.ScanTarget, jobID string) error {
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
	d := agentapi.ScanSshDirective{
		Type: agentapi.ScanSsh, JobId: jobID, ScanTargetId: t.ID, Address: t.Address, Port: port,
		Username: cred.Username, Sudo: t.Sudo, Credential: sealed, Policy: runner.PolicyToAPI(s.sshPolicy(ctx, t)),
	}
	if sc.HasFeature(store.FeatureGoSymbols) {
		d.GoSymbols = reportapi.APIGoSymbolQueryPtr(s.goSymbols(ctx, t.AssetID, ""))
	}
	var key gossh.PublicKey
	if len(t.HostKey) > 0 {
		if key, err = gossh.ParsePublicKey(t.HostKey); err != nil {
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
	return s.submitDirective(ctx, sc, leaseKey(kindSSH, t.ID), "scan_ssh:"+t.ID, jobID, body, sshTimeout())
}

// applySSHResult stores the outcome of a scan: the host key is pinned on
// the first successful run, a key other than the pinned one turns the run
// into a failure with runner.ReasonHostKeyChanged, and the run is recorded
// through ingest (which also marks the asset of a failed scan).
func (s *Service) applySSHResult(ctx context.Context, sender ingest.Sender, targetID string, res agentapi.ScanJobResult) error {
	t, err := s.st.GetScanTarget(ctx, targetID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("scansvc: scan target %s: %w", targetID, store.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("scansvc: scan target %s: %w", targetID, err)
	}
	if t.ScannerID != sender.AgentID {
		return forbidden("scan target %s is not assigned to scanner %q", t.ID, sender.AgentID)
	}
	status := store.ScanResult(res.Status)
	msg := ""
	if res.Message != nil {
		msg = *res.Message
	}
	fail := func(reason, detail string) {
		status, msg = store.ScanFailed, runner.Message(reason, detail)
		s.log.Warn("scan result rejected", "scan_target", t.ID, "reason", reason, "detail", detail)
	}
	seenFP := ""
	if res.HostKeyFingerprint != nil {
		seenFP = *res.HostKeyFingerprint
	}
	if status != store.ScanFailed {
		var seen gossh.PublicKey
		if res.HostKey != nil && len(*res.HostKey) > 0 {
			seen, err = gossh.ParsePublicKey(*res.HostKey)
			if err != nil || (seenFP != "" && gossh.FingerprintSHA256(seen) != seenFP) {
				seen = nil
				fail(runner.ReasonHostKeyUnavailable, "the reported host key is malformed or does not match its fingerprint")
			}
		}
		switch {
		case status == store.ScanFailed:
		case seen != nil && len(t.HostKey) == 0:
			switch err := s.st.SetScanTargetHostKey(ctx, t.ID, seen.Marshal()); {
			case errors.Is(err, store.ErrConflict):
				fail(runner.ReasonHostKeyChanged, "another host key was pinned meanwhile; offered "+gossh.FingerprintSHA256(seen))
			case err != nil:
				return fmt.Errorf("scansvc: pin host key of %s: %w", t.ID, err)
			default:
				s.log.Info("host key pinned", "scan_target", t.ID, "fingerprint", gossh.FingerprintSHA256(seen))
			}
		case len(t.HostKey) > 0:
			pinned, perr := gossh.ParsePublicKey(t.HostKey)
			want := ""
			if perr == nil {
				want = gossh.FingerprintSHA256(pinned)
			}
			got := seenFP
			if seen != nil {
				got = gossh.FingerprintSHA256(seen)
			}
			if got != "" && got != want {
				fail(runner.ReasonHostKeyChanged, "host key "+got+" does not match the pinned key "+want)
			}
		case seenFP != "":
			s.log.Warn("host key not pinned: the scanner reported only its fingerprint", "scan_target", t.ID, "fingerprint", seenFP)
		}
	}
	if status == store.ScanFailed && runner.ReasonOf(msg) == runner.ReasonHostKeyChanged {
		s.log.Warn("host key mismatch", "scan_target", t.ID, "message", msg)
	}
	return s.ing.RecordScanResult(ctx, sender, t.ID, ingest.ScanResult{
		Status: status, Message: msg, StartedAt: res.StartedAt, FinishedAt: res.FinishedAt,
	})
}

// sealSSHCredential seals a target's credential to the scanner for one job.
func sealSSHCredential(sc store.Agent, jobID string, cred store.Credential, secret runner.SSHCredential) ([]byte, error) {
	plain := agentapi.SSHCredentialSecret{Kind: agentapi.SshPassword}
	if cred.Kind == store.CredentialSSHKey {
		plain.Kind = agentapi.SshKey
	}
	if len(secret.PrivateKey) > 0 {
		k, p := string(secret.PrivateKey), string(secret.Passphrase)
		plain.PrivateKey = &k
		if p != "" {
			plain.Passphrase = &p
		}
	}
	if secret.Password != "" {
		plain.Password = &secret.Password
	}
	pt, err := json.Marshal(plain)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return seal(sc, jobID, "credential", pt)
}
