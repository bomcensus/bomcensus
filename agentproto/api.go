// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package agentproto is the channel-neutral form of the agent protocol:
// its operations (API), its errors and the interfaces of the channels that
// carry it.
//
// A channel is an adapter with two ends. The agent end (ChannelFactory)
// implements API by sending each operation to the server; the server end
// (Gateway) receives operations and calls the server's API. The adapter
// owns everything about the wire, including how requests and responses are
// authenticated: the built-in HTTP channel (docs/PROTOCOL.md) signs them
// with HTTP Message Signatures, a channel of your own may use gRPC with
// mTLS or its own message signatures. The server's API enforces only what
// does not depend on the wire: the agent's state, the operations reserved
// for scanners and the enrollment protocol.
//
// The DTOs are in package agentproto/dto.
package agentproto

import (
	"context"
	"io"

	"github.com/bomcensus/bomcensus/agentproto/dto"
)

// API is the set of operations of the agent protocol (api/openapi/agent.yaml,
// operationId in parentheses).
//
// On the server, every operation except EnrollStart, EnrollFinish and
// GetServerChain needs the authenticated agent in its context (WithAgent);
// the connection facts are read with PeerFrom. On the agent, the channel
// authenticates every call with ChannelParams.Identity.
//
// Errors are *Error for answers of the server; any other error is a
// failure to reach it or to authenticate its answer.
type API interface {
	// EnrollStart is enrollment steps 2 to 3 (enrollStart). The enrollment
	// signatures cover the exact message bytes, so body and the answer are
	// carried unchanged.
	EnrollStart(ctx context.Context, body []byte) (*SignedMessage, error)
	// EnrollFinish is enrollment steps 4 to 5 (enrollFinish), with bytes
	// carried as for EnrollStart.
	EnrollFinish(ctx context.Context, body []byte) (*SignedMessage, error)
	// GetEnrollResult is the result of a pending enrollment
	// (getEnrollResult). Pending agents may call it.
	GetEnrollResult(ctx context.Context) (*dto.EnrollResult, error)
	// RenewCert renews the agent certificate (renewCert).
	RenewCert(ctx context.Context, req *dto.CertRenewRequest) (*dto.RenewedCert, error)
	// GetServerChain returns the chain of the server's response signing
	// key (getServerChain). It is not authenticated.
	GetServerChain(ctx context.Context) (*dto.ServerChain, error)
	// GetTrustBundle returns the current trust bundle (getTrustBundle).
	GetTrustBundle(ctx context.Context) (*dto.TrustBundle, error)
	// Poll reports the agent status and waits for directives (poll).
	Poll(ctx context.Context, req *dto.PollRequest) (*dto.PollResult, error)
	// UploadReport uploads a collection report (uploadReport).
	UploadReport(ctx context.Context, params dto.UploadReportParams, report io.Reader) (*dto.ReportAccepted, error)
	// UploadK8sInventory sends the inventory of one cluster
	// (uploadK8sInventory). Scanners only.
	UploadK8sInventory(ctx context.Context, inv *dto.K8sInventory) error
	// SubmitScanJobResult reports the outcome of a scan job
	// (submitScanJobResult). Scanners only.
	SubmitScanJobResult(ctx context.Context, jobID string, res *dto.ScanJobResult) error
	// CheckUpdate returns the deployed version and its manifest for a
	// platform (checkUpdate).
	CheckUpdate(ctx context.Context, params dto.CheckUpdateParams) (*dto.UpdateCheck, error)
	// DownloadUpdateBundle downloads a release bundle
	// (downloadUpdateBundle). The bundle is verified by its manifest.
	DownloadUpdateBundle(ctx context.Context, version string, params dto.DownloadUpdateBundleParams) (*Download, error)
	// DownloadProbe downloads the probe binary of the deployed version
	// (downloadProbe). Scanners only. The probe is verified by its code
	// signature.
	DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*Download, error)
}

// SignedMessage is an enrollment message: the exact bytes of the answer
// and the server's enrollment signature over them (docs/PROTOCOL.md §2).
type SignedMessage struct {
	Body      []byte
	Signature string
}

// Download is a self-authenticating download. The receiver closes Body.
type Download struct {
	Body io.ReadCloser
	// Size is the length of Body, or -1 when unknown.
	Size int64
	// Version is the version of a probe.
	Version string
}
