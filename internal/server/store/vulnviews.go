// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// SeverityCounts counts vulnerabilities by rating.
type SeverityCounts struct {
	Critical, High, Medium, Low, Unknown int
}

// ExposureCounts counts locations (asset and container) by exposure.
type ExposureCounts struct {
	Listening, Running, Installed, Unknown int
}

// ProcessCount is how many loading processes run an executable.
type ProcessCount struct {
	Exe   string
	Count int
}

// VulnComponentRow aggregates the open findings of one component.
type VulnComponentRow struct {
	Component Component
	VulnIDs   []string
	// HotVulnIDs are the critical and high ones.
	HotVulnIDs []string
	KEVVulnIDs []string
	Severity   SeverityCounts
	MaxScore   *float64
	MaxEPSS    *float64
	Exposure   ExposureCounts
	Assets     int
	// FixedVersions are the distinct fixed versions of its
	// vulnerabilities; Unfixed counts those without one.
	FixedVersions []string
	Unfixed       int
	Processes     []ProcessCount
}

// VulnCveRow aggregates the open findings of one vulnerability.
type VulnCveRow struct {
	Meta       VulnMeta
	Components int
	// ComponentNames are the names of the affected components (for search).
	ComponentNames []string
	Assets         int
	Exposure       ExposureCounts
}

// OpenFindingFilter selects open findings; at least one field is set.
type OpenFindingFilter struct {
	AssetID     string
	ComponentID string
	VulnID      string
}

// OpenFinding is an open finding with what the console shows of it.
type OpenFinding struct {
	ID          string
	AssetID     string
	AssetName   string
	AssetKind   AssetKind
	Container   string
	Layer       string
	ImageDigest string
	Component   Component
	VulnID      string
	Exposure    string
	Processes   []FindingProcessRef
	FirstSeen   time.Time
	// Locations and Method of the component at this place.
	Locations []string
	Method    string
	// Match of the vulnerability to the component (the package advisory
	// when there is one).
	Match ComponentVuln
	Meta  VulnMeta
}

// VulnViews reads findings for the console.
type VulnViews interface {
	// VulnComponents aggregates open findings by component.
	VulnComponents(ctx context.Context) ([]VulnComponentRow, error)
	// VulnCves aggregates open findings by vulnerability.
	VulnCves(ctx context.Context) ([]VulnCveRow, error)
	// OpenFindings lists the open findings f selects.
	OpenFindings(ctx context.Context, f OpenFindingFilter) ([]OpenFinding, error)
	// GetVulnMeta returns ErrNotFound for an unknown id.
	GetVulnMeta(ctx context.Context, vulnID string) (VulnMeta, error)
	// CountFindingAssets counts assets with an open finding.
	CountFindingAssets(ctx context.Context) (int, error)
}
