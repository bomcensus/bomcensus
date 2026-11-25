// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"io"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/server/scope"
)

// systemScoped runs every operation with the system data scope: agents are
// not bound to the scope of a console user, and their records carry their
// own scope.
type systemScoped struct{ h *Handlers }

var _ agentproto.API = systemScoped{}

func (s systemScoped) EnrollStart(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	return s.h.EnrollStart(scope.System(ctx), body)
}

func (s systemScoped) EnrollFinish(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	return s.h.EnrollFinish(scope.System(ctx), body)
}

func (s systemScoped) GetEnrollResult(ctx context.Context) (*dto.EnrollResult, error) {
	return s.h.GetEnrollResult(scope.System(ctx))
}

func (s systemScoped) RenewCert(ctx context.Context, req *dto.CertRenewRequest) (*dto.RenewedCert, error) {
	return s.h.RenewCert(scope.System(ctx), req)
}

func (s systemScoped) GetServerChain(ctx context.Context) (*dto.ServerChain, error) {
	return s.h.GetServerChain(scope.System(ctx))
}

func (s systemScoped) GetTrustBundle(ctx context.Context) (*dto.TrustBundle, error) {
	return s.h.GetTrustBundle(scope.System(ctx))
}

func (s systemScoped) Poll(ctx context.Context, req *dto.PollRequest) (*dto.PollResult, error) {
	return s.h.Poll(scope.System(ctx), req)
}

func (s systemScoped) UploadReport(ctx context.Context, params dto.UploadReportParams, report io.Reader) (*dto.ReportAccepted, error) {
	return s.h.UploadReport(scope.System(ctx), params, report)
}

func (s systemScoped) UploadK8sInventory(ctx context.Context, inv *dto.K8sInventory) error {
	return s.h.UploadK8sInventory(scope.System(ctx), inv)
}

func (s systemScoped) SubmitScanJobResult(ctx context.Context, jobID string, res *dto.ScanJobResult) error {
	return s.h.SubmitScanJobResult(scope.System(ctx), jobID, res)
}

func (s systemScoped) CheckUpdate(ctx context.Context, params dto.CheckUpdateParams) (*dto.UpdateCheck, error) {
	return s.h.CheckUpdate(scope.System(ctx), params)
}

func (s systemScoped) DownloadUpdateBundle(ctx context.Context, version string, params dto.DownloadUpdateBundleParams) (*agentproto.Download, error) {
	return s.h.DownloadUpdateBundle(scope.System(ctx), version, params)
}

func (s systemScoped) DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*agentproto.Download, error) {
	return s.h.DownloadProbe(scope.System(ctx), os, arch)
}
