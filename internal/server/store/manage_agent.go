// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// AgentState is the stored lifecycle state of an agent. Online and offline
// are not stored; they follow from LastSeen (see Agent.Status).
type AgentState string

const (
	AgentApproved AgentState = "approved"
	AgentPending  AgentState = "pending"
	AgentRevoked  AgentState = "revoked"
)

// AgentStatus is the state shown in the console.
type AgentStatus string

const (
	AgentStatusOnline          AgentStatus = "online"
	AgentStatusOffline         AgentStatus = "offline"
	AgentStatusPendingApproval AgentStatus = "pending_approval"
	AgentStatusRevoked         AgentStatus = "revoked"
)

// ConnectMode is the direction of the TCP connection.
type ConnectMode string

const (
	ConnectModeConnect ConnectMode = "connect"
	ConnectModeListen  ConnectMode = "listen"
)

// TLSVerifyMode is how an agent verifies the server certificate.
type TLSVerifyMode string

const (
	TLSVerifyPinned TLSVerifyMode = "pinned"
	TLSVerifySystem TLSVerifyMode = "system"
	TLSVerifyNone   TLSVerifyMode = "none"
)

// Privilege is what the agent runs with. Empty means not yet reported.
type Privilege string

const (
	PrivilegePrivileged Privilege = "privileged"
	PrivilegeNonRoot    Privilege = "non_root"
)

// UpdateState is the agent's self-update progress.
type UpdateState string

const (
	UpdateUpToDate   UpdateState = "up_to_date"
	UpdatePending    UpdateState = "pending"
	UpdateUpdating   UpdateState = "updating"
	UpdateRolledBack UpdateState = "rolled_back"
)

// Agent is an enrolled agent or scanner.
type Agent struct {
	ID            string
	Kind          AgentKind
	Hostname      string
	Description   string // set by an administrator to tell agents apart; empty when none
	IdentityKey   []byte // Ed25519 public key; unique
	HPKEPublicKey []byte // scanners only
	RegisterKeyID string
	// ScopeID is the data scope, copied from the register key at
	// enrollment; empty for scanners, which are shared by every scope.
	ScopeID string
	State   AgentState

	Version            string
	OS                 string
	Arch               string
	ConnectMode        ConnectMode
	ListenAddress      string
	TLSMode            TLSVerifyMode
	ObservedIssuer     string // issuer of an unexpected server certificate the agent saw; empty when none
	Privilege          Privilege
	ExecHelper         bool
	Address            string
	TrustBundleVersion int64 // last trust bundle version the agent reported
	UpdateState        UpdateState
	// UpdateMessage is the detail the agent reported with UpdateState, for
	// example why a version was rolled back; empty when none.
	UpdateMessage string
	AssetID       string // empty until ingest links an asset
	// Features are the optional features reported in the last poll
	// (FeatureGoSymbols).
	Features []string
	// DetectDirIDs are the assigned detect directories and DetectPaths
	// their paths, both ordered by path. Read-only; see DetectDirs.
	DetectDirIDs []string
	DetectPaths  []string
	// Integrity is the agent's integrity mode (IntegrityInherit, ...).
	Integrity string

	EnrolledAt time.Time
	ApprovedAt *time.Time
	RevokedAt  *time.Time
	LastSeen   *time.Time

	// CertNotAfter is the latest expiry among the agent's unrevoked
	// certificates. Read-only; nil when there is none.
	CertNotAfter *time.Time
}

// Status derives the console status. An approved agent seen at or after
// onlineAfter is online.
func (a Agent) Status(onlineAfter time.Time) AgentStatus {
	switch a.State {
	case AgentPending:
		return AgentStatusPendingApproval
	case AgentRevoked:
		return AgentStatusRevoked
	}
	if a.LastSeen != nil && !a.LastSeen.Before(onlineAfter) {
		return AgentStatusOnline
	}
	return AgentStatusOffline
}

// AgentFilter narrows ListAgents. Zero fields do not filter.
type AgentFilter struct {
	Kind   AgentKind
	Status AgentStatus
	// OnlineAfter is the online threshold used by Status online and offline.
	OnlineAfter time.Time
	ConnectMode ConnectMode
	TLSMode     TLSVerifyMode
	// Q matches a case-insensitive substring of hostname, description,
	// address, ID, OS or listen address.
	Q string
	// Sort is one of hostname, version, address, last_seen, enrolled_at,
	// optionally prefixed with "-" for descending. Default hostname.
	Sort string
}

// AgentPollStatus is what an agent reports about itself on each poll. All
// fields replace the stored ones.
type AgentPollStatus struct {
	Hostname           string
	Version            string
	OS                 string
	Arch               string
	ConnectMode        ConnectMode
	ListenAddress      string
	TLSMode            TLSVerifyMode
	ObservedIssuer     string
	Privilege          Privilege
	ExecHelper         bool
	Address            string
	TrustBundleVersion int64
	UpdateState        UpdateState
	UpdateMessage      string
	Features           []string
	SeenAt             time.Time
}

// Optional agent and scanner features.
const (
	// FeatureGoSymbols: answers Go symbol queries (report.FeatureGoSymbols).
	FeatureGoSymbols = "go_symbols"
)

// HasFeature reports whether the agent reported feature f.
func (a Agent) HasFeature(f string) bool {
	for _, x := range a.Features {
		if x == f {
			return true
		}
	}
	return false
}

// AgentCounts are the dashboard numbers over agents and scanners together.
type AgentCounts struct {
	Online          int
	Offline         int
	PendingApproval int
	Revoked         int
	// NotPinned counts agents that are not revoked and do not use pinned TLS.
	NotPinned int
	// TrustBundleBehind counts approved agents whose reported trust bundle
	// version is below the current one.
	TrustBundleBehind int
	// TLSIntercepted counts agents that are not revoked and observed a
	// server certificate other than the server's own (ObservedIssuer set).
	TLSIntercepted int
}

// Agents stores agents and scanners.
type Agents interface {
	// CreateAgent stores a. ID is generated when empty; EnrolledAt defaults
	// to now; State must be approved or pending. Returns ErrConflict when
	// the identity key is already enrolled.
	CreateAgent(ctx context.Context, a Agent) (Agent, error)
	GetAgent(ctx context.Context, id string) (Agent, error)
	// LockAgent is GetAgent that holds a share lock on the agent until the
	// transaction ends, so that a concurrent revocation waits for it (or it
	// sees the revocation).
	LockAgent(ctx context.Context, id string) (Agent, error)
	GetAgentByIdentityKey(ctx context.Context, key []byte) (Agent, error)
	ListAgents(ctx context.Context, f AgentFilter, p Page) ([]Agent, int, error)
	// ApproveAgent moves a pending agent to approved. Approving an approved
	// agent is a no-op; a revoked one gives ErrInvalidState.
	ApproveAgent(ctx context.Context, id string, at time.Time) error
	// RevokeAgent marks the agent revoked, revokes all its certificates and
	// marks the asset it reported gone, in the same statement. The gone
	// asset leaves the inventory views, its findings resolve, and it is
	// purged after the retention. Revoking twice keeps the first time.
	RevokeAgent(ctx context.Context, id string, at time.Time) error
	// UpdateAgentPoll stores the status reported in a poll and sets
	// LastSeen to s.SeenAt.
	UpdateAgentPoll(ctx context.Context, id string, s AgentPollStatus) error
	// TouchAgent sets LastSeen when at is later than the stored value.
	TouchAgent(ctx context.Context, id string, at time.Time) error
	// SetAgentDescription replaces the description. ErrNotFound when the
	// agent does not exist.
	SetAgentDescription(ctx context.Context, id, description string) error
	// SetAgentAsset links the agent to an asset; an empty assetID unlinks.
	SetAgentAsset(ctx context.Context, id, assetID string) error
	// AdvanceAgentCounter stores value as the agent's message counter only
	// when it is greater than the stored one, atomically. It reports whether
	// the value was accepted. ErrNotFound when the agent does not exist.
	AdvanceAgentCounter(ctx context.Context, id string, value uint64) (bool, error)
	// AgentCounter returns the last accepted counter value (0 initially).
	AgentCounter(ctx context.Context, id string) (uint64, error)
	// CountAgents returns the dashboard numbers. onlineAfter is the online
	// threshold as in Agent.Status.
	CountAgents(ctx context.Context, onlineAfter time.Time) (AgentCounts, error)
}

// AgentCert is a certificate issued to an agent by the Agent CA.
type AgentCert struct {
	Serial    string // as formatted by the issuer; unique
	AgentID   string
	NotBefore time.Time
	NotAfter  time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// AgentCerts tracks issued agent certificates for revocation checks.
type AgentCerts interface {
	// InsertAgentCert stores c. CreatedAt defaults to now. ErrConflict when
	// the serial exists, ErrNotFound when the agent does not.
	InsertAgentCert(ctx context.Context, c AgentCert) error
	// ListAgentCerts returns the agent's certificates, newest first.
	ListAgentCerts(ctx context.Context, agentID string) ([]AgentCert, error)
	// IsAgentCertRevoked reports whether the certificate or its agent is
	// revoked. ErrNotFound for an unknown serial; callers must treat that as
	// revoked.
	IsAgentCertRevoked(ctx context.Context, serial string) (bool, error)
	// RevokeAgentCerts revokes every unrevoked certificate of the agent and
	// returns how many were revoked.
	RevokeAgentCerts(ctx context.Context, agentID string, at time.Time) (int64, error)
	// ListRevokedAgentCerts returns the certificates revoked at or after
	// since, directly or through their agent; a zero since returns every
	// revoked certificate. RevokedAt is the earlier of the two revocation
	// times.
	ListRevokedAgentCerts(ctx context.Context, since time.Time) ([]AgentCert, error)
}
