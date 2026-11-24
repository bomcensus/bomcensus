// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Exposure of a finding, most exposed first.
const (
	ExposureListening = "listening"
	ExposureRunning   = "running"
	ExposureInstalled = "installed"
	ExposureUnknown   = "unknown"
)

// Layers of a finding's component.
const (
	FindingLayerAsset   = ""
	FindingLayerRuntime = LayerRuntime
	FindingLayerImage   = LayerImage
)

// FindingSource is a vulnerable component present on an asset.
type FindingSource struct {
	Container   string
	Layer       string
	ImageDigest string
	Component   Component
	// Locations are the component's file paths in the asset or container.
	Locations []string
	// InUse is the in-use flag of a component installed on the asset
	// itself or in a container's runtime layer.
	InUse   bool
	VulnIDs []string
}

// FindingProcess is a process of an asset, with what links it to
// components.
type FindingProcess struct {
	Container   string
	Pod         string
	PID         int
	Exe         string
	SHA256      string
	ComponentID string
	// Packages are the OS packages it loads; nil when unknown.
	Packages []string
	Libs     []MappedLib
	// Ports are its listening sockets on non-loopback addresses
	// ("tcp/443").
	Ports []string
}

// FindingStamp identifies the state FindingInputs were read in.
type FindingStamp struct {
	SeenAt       time.Time
	Gone         bool
	VulnsVersion int64
}

// FindingInputs is what the findings of one asset are computed from, read
// in one snapshot.
type FindingInputs struct {
	Stamp FindingStamp
	Kind  AssetKind
	Gone  bool
	// Sources is empty for a gone asset.
	Sources   []FindingSource
	Processes []FindingProcess
	// ProcessCoverage is the coverage of the processes section by
	// container ("" for the asset itself).
	ProcessCoverage map[string]Coverage
	// HashComponents maps executable and library hashes of the processes
	// to the source components with a file of that hash.
	HashComponents map[string][]string
}

// FindingProcessRef is a process kept on a finding.
type FindingProcessRef struct {
	PID   int      `json:"pid"`
	Exe   string   `json:"exe"`
	Pod   string   `json:"pod,omitempty"`
	Ports []string `json:"ports,omitempty"`
}

// FindingRow is a finding as computed.
type FindingRow struct {
	Container   string
	Layer       string
	ImageDigest string
	ComponentID string
	VulnID      string
	Exposure    string
	Processes   []FindingProcessRef
}

// FindingsChange counts what ApplyFindings changed.
type FindingsChange struct {
	Opened   int
	Resolved int
}

// Findings stores computed findings.
type Findings interface {
	// DirtyFindingAssets returns up to limit assets whose findings are out
	// of date: never computed, or seen, gone or with changed
	// vulnerabilities since the stamp of the last computation.
	DirtyFindingAssets(ctx context.Context, limit int) ([]string, error)
	// FindingInputs reads what the findings of an asset are computed from.
	FindingInputs(ctx context.Context, assetID string) (FindingInputs, error)
	// ApplyFindings makes rows the open findings of the asset: new ones
	// open, missing ones resolve, kept ones get the new exposure. stamp
	// (from FindingInputs) is recorded as what they were computed from.
	ApplyFindings(ctx context.Context, assetID string, rows []FindingRow, stamp FindingStamp) (FindingsChange, error)
}
