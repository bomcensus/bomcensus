// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"encoding/json"
	"time"
)

// Reachability of a finding from the functions linked into its Go
// executables. Empty when not known.
const (
	ReachSymbolPresent = "symbol_present"
	ReachSymbolAbsent  = "symbol_absent"
)

// GoImport is a package of a Go vulnerability with its vulnerable
// functions, as the Go vulnerability database lists them. GOOS and GOARCH,
// when set, restrict the vulnerability to those targets.
type GoImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
}

// Names returns the package qualified names of the import's functions.
func (g GoImport) Names() []string {
	out := make([]string, 0, len(g.Symbols))
	for _, s := range g.Symbols {
		out = append(out, g.Path+"."+s)
	}
	return out
}

// Applies reports whether the import concerns a binary for goos and goarch.
// An unknown target ("") is assumed to be concerned.
func (g GoImport) Applies(goos, goarch string) bool {
	in := func(list []string, v string) bool {
		if len(list) == 0 || v == "" {
			return true
		}
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	return in(g.GOOS, goos) && in(g.GOARCH, goarch)
}

// GoBinary is a Go executable.
type GoBinary struct {
	Path   string
	SHA256 string
	GOOS   string
	GOARCH string
}

// GoBinaryScope is where Go executables are replaced: an image by digest,
// or an asset's container ("" for the asset itself) and layer.
type GoBinaryScope struct {
	Digest    string
	AssetID   string
	Container string
	Layer     string
}

// FindingGoBinary is a Go executable a finding's component can be in.
type FindingGoBinary struct {
	Container string
	Layer     string
	// ImageDigest is set for image content shared by digest.
	ImageDigest string
	GoBinary
}

// Answers about a function in a Go executable.
const (
	GoSymbolPresent    = "present"
	GoSymbolAbsent     = "absent"
	GoSymbolNotChecked = "not_checked"
)

// GoSymbolResult is one answer of an asset's collector.
type GoSymbolResult struct {
	SHA256    string
	Name      string
	Result    string
	Reason    string
	CheckedAt time.Time
}

// GoSymbolQuery is a query waiting for an asset's next collection. Query is
// a report.GoSymbolQuery.
type GoSymbolQuery struct {
	AssetID   string
	Container string
	Query     json.RawMessage
	CreatedAt time.Time
}

// WorkloadGoSymbolQuery is a waiting query of a Kubernetes workload
// container.
type WorkloadGoSymbolQuery struct {
	Namespace    string
	WorkloadKind string
	WorkloadName string
	GoSymbolQuery
}

// GoSymbols stores Go executables, the questions asked about them and the
// answers.
type GoSymbols interface {
	// ReplaceGoBinaries makes bins the Go executables of the scope. With
	// opts.KeepMissing the ones not in bins are kept.
	ReplaceGoBinaries(ctx context.Context, scope GoBinaryScope, bins []GoBinary, opts ReplaceOptions) error
	// SaveGoSymbolResults stores answers for the asset and marks its
	// findings out of date.
	SaveGoSymbolResults(ctx context.Context, assetID string, results []GoSymbolResult) error
	// GoSymbolAssets returns up to limit assets that have open findings
	// with vulnerable functions and an unknown reachability, and no query
	// created after since.
	GoSymbolAssets(ctx context.Context, since time.Time, limit int) ([]string, error)
	// PutGoSymbolQuery stores or replaces the waiting query of an asset's
	// container scope.
	PutGoSymbolQuery(ctx context.Context, q GoSymbolQuery) error
	// GoSymbolQueryFor returns the waiting query of an asset's container
	// scope, or ErrNotFound.
	GoSymbolQueryFor(ctx context.Context, assetID, container string) (GoSymbolQuery, error)
	// DeleteGoSymbolQuery removes the waiting query once it was answered.
	DeleteGoSymbolQuery(ctx context.Context, assetID, container string) error
	// ClusterGoSymbolQueries returns the waiting queries of the current
	// workloads of a cluster.
	ClusterGoSymbolQueries(ctx context.Context, clusterID string) ([]WorkloadGoSymbolQuery, error)
}
