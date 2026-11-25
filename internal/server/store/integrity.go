// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Integrity modes of an agent or scan target.
const (
	IntegrityInherit = "inherit"
	IntegrityOn      = "on"
	IntegrityOff     = "off"
)

// Statuses of an integrity finding.
const (
	IntegrityModified = "modified"
	IntegrityMissing  = "missing"
)

// Scopes of an integrity allow rule.
const (
	IntegrityScopeAsset = "asset"
	IntegrityScopeFleet = "fleet"
)

// FeatureIntegrity: runs package file integrity passes
// (report.FeatureIntegrity).
const FeatureIntegrity = "integrity"

// IntegrityObservation is one finding as a chunk reports it.
type IntegrityObservation struct {
	Path, Status                 string
	PkgType, Package, Version    string
	Arch, Algo, Expected, Actual string
	ActualSHA256                 string
	Size                         int64
	Mtime, Ctime                 *time.Time
}

// IntegrityChunk is the result of one chunk of a pass.
type IntegrityChunk struct {
	AssetID string
	// PassKey is the collector's pass id.
	PassKey string
	At      time.Time
	Done    bool
	// Cursor is where the next chunk starts; stored for SSH targets.
	Cursor    string
	UTCOffset int
	Checked   int64
	Excluded  int64
	// Unreadable counts files the probe could not read.
	Unreadable int64
	Coverage   string // full, partial or none
	Reason     string
	Findings   []IntegrityObservation
}

// IntegrityPass is a pass over an asset's package files.
type IntegrityPass struct {
	ID          string
	AssetID     string
	PassKey     string
	StartedAt   time.Time
	LastChunkAt time.Time
	CompletedAt *time.Time
	Checked     int64
	Excluded    int64
	Unreadable  int64
	Coverage    string
	Reason      string
	Cursor      string
	UTCOffset   *int
}

// IntegrityFinding is an open finding on one asset.
type IntegrityFinding struct {
	ID        string
	AssetID   string
	AssetName string
	// Collector is "agent" or "ssh": how the asset is collected.
	Collector string
	IntegrityObservation
	FirstSeen time.Time
	LastSeen  time.Time
	// AllowedBy is the id of an active rule that hides the finding.
	AllowedBy string
}

// IntegrityGroup is the open findings with the same path, status and actual
// content, over all assets.
type IntegrityGroup struct {
	Path, Status, ActualSHA256 string
	// Package, Version, Algo, Expected and Actual are those of one of the
	// findings; the findings of other assets may name another version.
	PkgType, Package, Version string
	Algo, Expected, Actual    string
	Assets                    int
	FirstSeen                 time.Time
	LastSeen                  time.Time
	// AllowedAssets counts the assets on which an active rule hides it.
	AllowedAssets int
}

// IntegrityFilter narrows the integrity views. Zero fields do not filter.
type IntegrityFilter struct {
	Status  string
	AssetID string
	// Q matches a case-insensitive substring of the path, the package or
	// an asset name.
	Q string
	// Path, Status and SHA256 select one group (ListIntegrityFindings).
	Path   string
	SHA256 *string
	// IncludeAllowed also returns findings hidden by an allow rule.
	IncludeAllowed bool
}

// IntegritySummary are the numbers of the integrity page.
type IntegritySummary struct {
	// Groups and Assets count visible open findings, grouped and by asset.
	Groups int
	Assets int
	// Rules counts active allow rules.
	Rules int
	// Tracked counts current assets with any pass; Completed those whose
	// last completed pass ended at or after CompletedAfter.
	Tracked   int
	Completed int
}

// IntegrityAllowRule hides findings with its key.
type IntegrityAllowRule struct {
	ID string
	// ScopeID is the data scope the rule applies in. Asset rules have the
	// scope of their asset.
	ScopeID      string
	Scope        string
	AssetID      string // scope asset
	AssetName    string // read-only
	Path         string
	Status       string
	ActualSHA256 string
	Note         string
	CreatedBy    string
	CreatedAt    time.Time
	RevokedBy    string
	RevokedAt    *time.Time
	// Hidden counts the open findings the rule hides now. Read-only.
	Hidden int
}

// Integrity stores package file integrity results and allow rules.
type Integrity interface {
	// RecordIntegrityChunk stores a chunk: it creates or continues the
	// pass, upserts the findings, resolves open findings of the same path
	// with another content, and, when the chunk ends the pass, resolves
	// the asset's open findings that the pass did not report.
	RecordIntegrityChunk(ctx context.Context, c IntegrityChunk) error
	// LastIntegrityPass returns the asset's most recent pass, or
	// ErrNotFound.
	LastIntegrityPass(ctx context.Context, assetID string) (IntegrityPass, error)
	// LastCompletedIntegrityPass returns the asset's most recently
	// completed pass, or ErrNotFound.
	LastCompletedIntegrityPass(ctx context.Context, assetID string) (IntegrityPass, error)
	// ListIntegrityGroups groups the open findings of current assets by
	// path, status and actual SHA-256, most assets first.
	ListIntegrityGroups(ctx context.Context, f IntegrityFilter, p Page) ([]IntegrityGroup, int, error)
	// ListIntegrityFindings lists open findings of current assets.
	ListIntegrityFindings(ctx context.Context, f IntegrityFilter, p Page) ([]IntegrityFinding, int, error)
	// IntegritySummary counts for the integrity page; completedAfter is
	// the threshold of IntegritySummary.Completed.
	IntegritySummary(ctx context.Context, completedAfter time.Time) (IntegritySummary, error)
	// CreateIntegrityAllowRule stores r. ID is generated; CreatedAt
	// defaults to now. ErrInvalid for a malformed rule, ErrNotFound for
	// an unknown asset.
	CreateIntegrityAllowRule(ctx context.Context, r IntegrityAllowRule) (IntegrityAllowRule, error)
	// ListIntegrityAllowRules lists active rules, newest first, with
	// revoked ones too when includeRevoked.
	ListIntegrityAllowRules(ctx context.Context, includeRevoked bool, p Page) ([]IntegrityAllowRule, int, error)
	// RevokeIntegrityAllowRule revokes an active rule. ErrNotFound when
	// there is no such active rule.
	RevokeIntegrityAllowRule(ctx context.Context, id, by string, at time.Time) error
	// SetAgentIntegrity and SetScanTargetIntegrity store the integrity
	// mode (IntegrityInherit, IntegrityOn, IntegrityOff).
	SetAgentIntegrity(ctx context.Context, id, mode string) error
	SetScanTargetIntegrity(ctx context.Context, id, mode string) error
}
