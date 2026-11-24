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
	// Deferred counts the deferred findings among them (only when they
	// are included).
	Deferred int
}

// VulnCveRow aggregates the open findings of one vulnerability.
type VulnCveRow struct {
	Meta       VulnMeta
	Components int
	// ComponentNames are the names of the affected components (for search).
	ComponentNames []string
	Assets         int
	Exposure       ExposureCounts
	Deferred       int
}

// VulnViewOptions are the options of the aggregated views.
type VulnViewOptions struct {
	// At decides which triage rules are in force (now when zero).
	At time.Time
	// IncludeDeferred keeps findings that an active rule defers.
	IncludeDeferred bool
}

// OpenFindingFilter selects open findings; at least one of the ID fields
// or Exe is set.
type OpenFindingFilter struct {
	AssetID     string
	ComponentID string
	VulnID      string
	// Exe keeps findings a process with this executable loads.
	Exe string
	At  time.Time
}

// VulnProcessRow aggregates open findings by the executable of the
// processes that load the vulnerable components.
type VulnProcessRow struct {
	Exe        string
	Assets     int
	Processes  int
	Listening  int
	Components int
	VulnIDs    []string
	KEV        int
	MaxScore   *float64
	Severity   SeverityCounts
}

// VulnImageRow aggregates the vulnerabilities of an image's content.
type VulnImageRow struct {
	Digest     string
	Tags       []string
	Components int
	VulnIDs    []string
	KEV        int
	MaxScore   *float64
	MaxEPSS    *float64
	Severity   SeverityCounts
	// Containers and Assets running the image now.
	Containers int
	Assets     int
}

// ImageVuln is one vulnerability of a component in an image's content.
type ImageVuln struct {
	Component Component
	Match     ComponentVuln
	Meta      VulnMeta
	Locations []string
	Deferred  bool
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
	// Triage is the rule that decides the finding, nil without one.
	Triage *FindingTriage
}

// VulnViews reads findings for the console.
type VulnViews interface {
	// VulnComponents aggregates open findings by component.
	VulnComponents(ctx context.Context, o VulnViewOptions) ([]VulnComponentRow, error)
	// VulnCves aggregates open findings by vulnerability.
	VulnCves(ctx context.Context, o VulnViewOptions) ([]VulnCveRow, error)
	// VulnProcesses aggregates open findings by loading executable.
	VulnProcesses(ctx context.Context, o VulnViewOptions) ([]VulnProcessRow, error)
	// VulnImages aggregates the vulnerabilities of image contents; rules
	// with a component scope apply.
	VulnImages(ctx context.Context, o VulnViewOptions) ([]VulnImageRow, error)
	// ImageVulns lists the vulnerabilities of one image's content.
	ImageVulns(ctx context.Context, digest string, at time.Time) ([]ImageVuln, error)
	// CountDeferred counts the vulnerabilities whose open findings an
	// active rule defers.
	CountDeferred(ctx context.Context, at time.Time) (int, error)
	// OpenFindings lists the open findings f selects.
	OpenFindings(ctx context.Context, f OpenFindingFilter) ([]OpenFinding, error)
	// GetVulnMeta returns ErrNotFound for an unknown id.
	GetVulnMeta(ctx context.Context, vulnID string) (VulnMeta, error)
	// CountFindingAssets counts assets with an open finding that is not
	// deferred.
	CountFindingAssets(ctx context.Context, at time.Time) (int, error)
}
