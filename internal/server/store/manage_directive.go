// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"encoding/json"
	"time"
)

// Directive is an instruction queued for one agent and delivered in its
// poll responses until the agent acknowledges it.
type Directive struct {
	ID      string
	AgentID string
	// Type is the directive type (collect, scan_ssh, ...).
	Type string
	// Payload is the directive as a JSON object, without its id.
	Payload json.RawMessage
	// DedupeKey, when set, is unique per agent among pending directives.
	DedupeKey   string
	CreatedAt   time.Time
	DeliveredAt *time.Time // last delivery
	AckedAt     *time.Time
	ExpiresAt   *time.Time // nil: never expires
}

// DirectiveQueue is the per-agent directive queue. A directive is pending
// until it is acknowledged or expires; a delivered but unacknowledged
// directive is pending and is delivered again.
type DirectiveQueue interface {
	// EnqueueDirective stores d. ID is generated when empty and CreatedAt
	// defaults to now. When d.DedupeKey is set and the agent already has a
	// pending directive with that key, nothing is stored and the existing
	// directive is returned with created false. ErrNotFound when the agent
	// does not exist.
	EnqueueDirective(ctx context.Context, d Directive) (out Directive, created bool, err error)
	// ListPendingDirectives returns up to limit pending directives of the
	// agent that have not expired at now, oldest first. limit <= 0 means
	// no limit.
	ListPendingDirectives(ctx context.Context, agentID string, now time.Time, limit int) ([]Directive, error)
	// MarkDirectivesDelivered records a delivery of the agent's directives.
	MarkDirectivesDelivered(ctx context.Context, agentID string, ids []string, at time.Time) error
	// AckDirectives acknowledges the agent's directives and returns how many
	// were pending. Unknown ids, ids of other agents and ids that are not
	// directive ids are ignored.
	AckDirectives(ctx context.Context, agentID string, ids []string, at time.Time) (int64, error)
	// DeleteExpiredDirectives removes directives that expired at or before
	// now and acknowledged directives acknowledged at or before ackedBefore.
	DeleteExpiredDirectives(ctx context.Context, now, ackedBefore time.Time) (int64, error)
}

// AgentEnrollment is what the server keeps from an agent's enrollment: the
// certificate request its certificates are issued from and the policy of the
// Register Key at the time of enrollment.
type AgentEnrollment struct {
	AgentID string
	// CSR is the DER PKCS#10 request for the agent's identity key.
	CSR             []byte
	AllowRelaxedTLS bool
	DefaultGroup    string
	DefaultTags     []string
	CreatedAt       time.Time
}

// AgentEnrollments stores AgentEnrollment records.
type AgentEnrollments interface {
	// PutAgentEnrollment inserts or replaces the record. CreatedAt defaults
	// to now. ErrNotFound when the agent does not exist.
	PutAgentEnrollment(ctx context.Context, e AgentEnrollment) error
	// GetAgentEnrollment returns ErrNotFound when there is no record.
	GetAgentEnrollment(ctx context.Context, agentID string) (AgentEnrollment, error)
}

// Directives groups what the agent-facing services keep per agent besides
// the agent record: the directive queue and the enrollment record.
type Directives interface {
	DirectiveQueue
	AgentEnrollments
}
