// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// ListenTargetState is the connection state of a listen target.
type ListenTargetState string

const (
	ListenNew          ListenTargetState = "new"
	ListenConnected    ListenTargetState = "connected"
	ListenDisconnected ListenTargetState = "disconnected"
	ListenFailed       ListenTargetState = "failed"
)

// ListenTarget is the address of a listen-mode agent the server dials.
type ListenTarget struct {
	ID            string
	Address       string // host:port; unique
	RegisterKeyID string // optional: the key the agent is expected to enroll with
	// ScopeID is the data scope: that of the register key when there is
	// one. Set on create.
	ScopeID         string
	AgentID         string // bound after enrollment
	State           ListenTargetState
	LastError       string
	LastConnectedAt *time.Time
	// LeaseOwner is the replica currently responsible for dialing; empty
	// when nobody holds the lease.
	LeaseOwner     string
	LeaseExpiresAt *time.Time
	CreatedAt      time.Time
	// AgentHostname is the hostname of the bound agent. Read-only; set by
	// ListListenTargets.
	AgentHostname string
}

// ListenTargetFilter narrows ListListenTargets. Zero fields do not filter.
type ListenTargetFilter struct {
	// Q is a case-insensitive substring of the address or of the bound
	// agent's hostname.
	Q     string
	State ListenTargetState
	// AgentIDs keeps targets bound to one of these agents.
	AgentIDs []string
	// Sort is one of address, agent, state, createdAt, lastConnectedAt,
	// optionally prefixed with "-" for descending. Default address.
	Sort string
}

// ListenTargets stores listen targets and the per-target dial lease that
// makes exactly one replica dial each target.
type ListenTargets interface {
	// CreateListenTarget stores t. ID is generated when empty, State
	// defaults to new and CreatedAt to now. ErrConflict when the address
	// exists.
	CreateListenTarget(ctx context.Context, t ListenTarget) (ListenTarget, error)
	GetListenTarget(ctx context.Context, id string) (ListenTarget, error)
	// ListListenTargets returns targets in f.Sort order and the total count.
	ListListenTargets(ctx context.Context, f ListenTargetFilter, p Page) ([]ListenTarget, int, error)
	// UpdateListenTarget replaces the address and register key of t.ID.
	// A changed address resets the state to new and clears the last error;
	// the bound agent and the lease are kept. ErrConflict when the address
	// is taken.
	UpdateListenTarget(ctx context.Context, t ListenTarget) (ListenTarget, error)
	DeleteListenTarget(ctx context.Context, id string) error
	// BindListenTargetAgent records the agent enrolled at the target.
	// Binding the same agent again is a no-op; a different one gives
	// ErrConflict.
	BindListenTargetAgent(ctx context.Context, id, agentID string) error

	// AcquireListenLeases takes up to limit targets whose lease is free or
	// expired at now, renews those already held by owner, and returns all
	// targets owner holds afterwards. limit <= 0 means no limit on new
	// acquisitions.
	AcquireListenLeases(ctx context.Context, owner string, ttl time.Duration, now time.Time, limit int) ([]ListenTarget, error)
	// RenewListenLease extends the lease when owner still holds it, even if
	// it has expired but nobody took it over. It reports whether owner holds
	// the lease afterwards.
	RenewListenLease(ctx context.Context, id, owner string, ttl time.Duration, now time.Time) (bool, error)
	// ReleaseListenLease gives up the lease if owner holds it.
	ReleaseListenLease(ctx context.Context, id, owner string) error
	// RecordListenState stores the connection state. Only the lease holder
	// may write it; ErrConflict otherwise. state connected also sets
	// LastConnectedAt to at.
	RecordListenState(ctx context.Context, id, owner string, state ListenTargetState, lastError string, at time.Time) error
}
