// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package runner

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/scanner/ssh"
)

// SSHCredential is the login secret of a scan target.
type SSHCredential struct {
	PrivateKey []byte
	Passphrase []byte
	Password   string
}

// SSHJob is one SSH collection.
type SSHJob struct {
	JobID    string
	TargetID string
	Address  string
	// Port defaults to 22.
	Port       int
	User       string
	Credential SSHCredential
	Sudo       bool
	// HostKey is the pinned host key (SSH wire format or authorized_keys
	// line). Empty means trust on first use.
	HostKey []byte
	// HostKeyFingerprint is the pinned key's fingerprint
	// ("SHA256:<base64>"). When set, HostKey must be set and match it;
	// a fingerprint alone cannot be enforced before credentials are sent,
	// so the job fails instead of trusting any key.
	HostKeyFingerprint string
	Policy             report.Policy
	// Sections to collect; empty means all.
	Sections []string
	// Timeout bounds the collection; zero means ssh.DefaultTimeout.
	Timeout time.Duration
	// GoSymbols is passed to the probe with the collection.
	GoSymbols *report.GoSymbolQuery
}

// RunSSH collects one host over SSH and submits its report and result. The
// report subject is the scan target. The result is ok, partial (sudo fell
// back or a section has reduced coverage) or failed with a reason code; it
// carries the host key the target presented. A host key that differs from
// the pinned one fails with ReasonHostKeyChanged; nothing is retried.
func RunSSH(ctx context.Context, job SSHJob, d Deps) (res Result, err error) {
	d = d.withDefaults()
	log := d.Logger.With("job_id", job.JobID, "scan_target", job.TargetID)
	start := d.Now()
	res = newResult(start)
	defer func() {
		if v := recover(); v != nil {
			res = newResult(start)
			res.fail(ReasonInternal, recovered(log, job.JobID, v).Error())
		}
		err = submit(ctx, d, job.JobID, &res)
	}()
	runSSH(ctx, job, d, &res, log)
	return res, nil
}

func runSSH(ctx context.Context, job SSHJob, d Deps, res *Result, log *slog.Logger) {
	if job.JobID == "" || job.TargetID == "" || job.Address == "" || job.User == "" {
		res.fail(ReasonInvalidJob, "job id, target, address and user are required")
		return
	}
	pinned, err := pinnedKey(job)
	if err != nil {
		res.fail(ReasonHostKeyUnavailable, err.Error())
		return
	}
	t := ssh.Target{
		Address: job.Address,
		Port:    job.Port,
		User:    job.User,
		Auth: ssh.Auth{
			PrivateKey: job.Credential.PrivateKey,
			Passphrase: job.Credential.Passphrase,
			Password:   job.Credential.Password,
		},
		Sudo:    job.Sudo,
		HostKey: pinned,
		Request: report.Request{Sections: slices.Clone(job.Sections), Policy: job.Policy, GoSymbols: job.GoSymbols},
		Timeout: job.Timeout,
	}
	out, err := d.sshCollect(ctx, t, ssh.Deps{Probe: d.probe(), Logger: d.Logger})
	if err != nil {
		var changed *ssh.HostKeyChangedError
		if errors.As(err, &changed) {
			fp := changed.Fingerprint
			res.HostKeyFingerprint = &fp
			key := changed.Key
			res.HostKey = &key
		}
		reason := sshReason(err)
		log.Warn("ssh collection failed", "reason", reason, "error", err)
		res.fail(reason, err.Error())
		return
	}
	if len(out.HostKey) > 0 {
		key := out.HostKey
		res.HostKey = &key
		if k, err := gossh.ParsePublicKey(out.HostKey); err == nil {
			fp := gossh.FingerprintSHA256(k)
			res.HostKeyFingerprint = &fp
		}
	}
	r := out.Report
	if r == nil {
		res.fail(ReasonCollectFailed, "the probe returned no report")
		return
	}
	r.Subject = &report.Subject{Kind: report.SubjectScanTarget, ScanTargetID: job.TargetID}
	enc, err := encodeReport(r)
	if err != nil {
		res.fail(ReasonCollectFailed, "encode report: "+err.Error())
		return
	}
	if err := d.Sink.SubmitReport(ctx, enc, job.JobID); err != nil {
		res.fail(ReasonSubmitFailed, err.Error())
		return
	}
	if out.SudoFallback != "" {
		res.partial(ReasonSudoFallback, out.SudoFallback)
	}
	if p := partialSections(r); len(p) > 0 {
		res.partial(ReasonPartialSections, strings.Join(p, ", "))
	}
	log.Info("ssh collection finished", "status", res.Status, "privileged", out.Privileged, "duration", out.Duration)
}

// pinnedKey checks the pinned key against its fingerprint.
func pinnedKey(job SSHJob) ([]byte, error) {
	if len(job.HostKey) == 0 {
		if job.HostKeyFingerprint != "" {
			return nil, errors.New("only a fingerprint of the pinned host key is known")
		}
		return nil, nil
	}
	k, err := gossh.ParsePublicKey(job.HostKey)
	if err != nil {
		var perr error
		if k, _, _, _, perr = gossh.ParseAuthorizedKey(job.HostKey); perr != nil {
			return nil, errors.New("the pinned host key cannot be parsed")
		}
	}
	if job.HostKeyFingerprint != "" && gossh.FingerprintSHA256(k) != job.HostKeyFingerprint {
		return nil, errors.New("the pinned host key does not match its fingerprint")
	}
	return k.Marshal(), nil
}

// sshReason maps a collection error to a reason code.
func sshReason(err error) string {
	if r, ok := ctxReason(err); ok {
		return r
	}
	var netErr *net.OpError
	switch {
	case errors.Is(err, ssh.ErrHostKeyChanged):
		return ReasonHostKeyChanged
	case errors.Is(err, ssh.ErrUnsupportedPlatform):
		return ReasonUnsupportedPlatform
	case errors.Is(err, ssh.ErrProbeRejected):
		return ReasonProbeRejected
	case errors.Is(err, ssh.ErrNoExecDir):
		return ReasonNoExecDir
	case errors.Is(err, ssh.ErrReportTooLarge):
		return ReasonReportTooLarge
	case strings.Contains(err.Error(), "unable to authenticate"):
		return ReasonAuthFailed
	case errors.As(err, &netErr):
		return ReasonConnectFailed
	}
	return ReasonCollectFailed
}

// partialSections lists the sections whose coverage is not full.
func partialSections(r *report.Report) []string {
	var out []string
	add := func(name string, m *report.SectionMeta) {
		if m != nil && !m.Unchanged && m.Coverage != "" && m.Coverage != report.CoverageFull {
			out = append(out, name)
		}
	}
	if r.Host != nil {
		add(report.SectionHost, &r.Host.SectionMeta)
	}
	if r.Packages != nil {
		add(report.SectionPackages, &r.Packages.SectionMeta)
	}
	if r.Artifacts != nil {
		add(report.SectionArtifacts, &r.Artifacts.SectionMeta)
	}
	if r.Processes != nil {
		add(report.SectionProcesses, &r.Processes.SectionMeta)
	}
	if r.Containers != nil {
		add(report.SectionContainers, &r.Containers.SectionMeta)
	}
	return out
}
