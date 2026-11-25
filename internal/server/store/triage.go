// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Triage rule scopes.
const (
	TriageScopePURL  = "purl"
	TriageScopeAsset = "asset"
	TriageScopeGroup = "group"
)

// TriageStatusNotAffected is the only status a rule records for now
// (CycloneDX VEX not_affected).
const TriageStatusNotAffected = "not_affected"

// TriageJustifications are the CycloneDX VEX justifications a rule may give.
var TriageJustifications = []string{
	"code_not_present", "code_not_reachable", "requires_configuration", "requires_environment",
	"protected_at_runtime", "protected_by_mitigating_control",
}

// TriageRule is a judgment that a vulnerability does not affect a scope.
type TriageRule struct {
	ID string
	// ScopeID is the data scope the rule applies in. Asset rules have the
	// scope of their asset.
	ScopeID    string
	VulnID     string
	ScopeKind  string
	ScopeValue string
	// PURLLike is the LIKE pattern of a purl scope.
	PURLLike      string
	Status        string
	Justification string
	Note          string
	// ExpiresAt is nil for a rule that holds until revoked.
	ExpiresAt *time.Time
	// ExpiredAt is when the expiry was processed (triage_expire).
	ExpiredAt *time.Time
	CreatedBy string
	CreatedAt time.Time
	RevokedAt *time.Time
	RevokedBy string
}

// Active reports whether the rule defers findings at t.
func (r TriageRule) Active(t time.Time) bool {
	return r.RevokedAt == nil && (r.ExpiresAt == nil || r.ExpiresAt.After(t))
}

// TriageRuleRow is a rule with the open findings it decides now.
type TriageRuleRow struct {
	TriageRule
	Findings int
	Assets   int
}

// FindingTriage is the rule that decides a finding.
type FindingTriage struct {
	Rule TriageRule
	// Active is false when the rule expired: the finding is back.
	Active bool
}

// Triage event kinds.
const (
	TriageEventCreated = "created"
	TriageEventRevoked = "revoked"
	TriageEventExpired = "expired"
)

// TriageEvent is something that happened to a rule.
type TriageEvent struct {
	ID       int64
	Rule     TriageRule
	Kind     string
	At       time.Time
	Actor    string
	Findings int
}

// Triage stores triage rules.
type Triage interface {
	// CreateTriageRule stores r (ID and CreatedAt are set) with a created
	// event.
	CreateTriageRule(ctx context.Context, r TriageRule) (TriageRule, error)
	// RevokeTriageRule ends a rule with a revoked event; ErrInvalidState
	// when already revoked.
	RevokeTriageRule(ctx context.Context, id, by string, at time.Time) (TriageRule, error)
	// ExpireTriageRules marks the rules whose expiry passed by at and are
	// not marked yet, each with an expired event, and returns them.
	ExpireTriageRules(ctx context.Context, at time.Time) ([]TriageEvent, error)
	// ListTriageEvents returns events after afterID, oldest first, at most
	// limit.
	ListTriageEvents(ctx context.Context, afterID int64, limit int) ([]TriageEvent, error)
	GetTriageRule(ctx context.Context, id string) (TriageRule, error)
	// ListTriageRules returns rules, newest first, with the open findings
	// each decides at at; revoked ones only when asked.
	ListTriageRules(ctx context.Context, at time.Time, includeRevoked bool) ([]TriageRuleRow, error)
}
