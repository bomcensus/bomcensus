// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// DetectorTableRevision is one edit of the known-software detector table.
// The newest revision is in effect; a Reset revision returns to the
// server's default table.
type DetectorTableRevision struct {
	ID int64
	// YAML is the table as the administrator saved it, empty for Reset.
	YAML string
	// Digest is the digest of the parsed table (internal/detectors),
	// empty for Reset.
	Digest    string
	Reset     bool
	CreatedAt time.Time
	CreatedBy string
}

// DetectorTableUsage counts the approved agents of one kind by the
// detector table digest they reported.
type DetectorTableUsage struct {
	Kind AgentKind
	// Reported is false for agents that do not report a digest (older
	// versions); their probe uses its built-in table.
	Reported bool
	// Digest is empty for agents that hold no table.
	Digest string
	Count  int
}

// DetectorTables stores the edits of the detector table. The table is
// global data: it is not scoped.
type DetectorTables interface {
	// LatestDetectorTable returns the newest revision, ErrNotFound when
	// the table was never edited.
	LatestDetectorTable(ctx context.Context) (DetectorTableRevision, error)
	// GetDetectorTable returns one revision.
	GetDetectorTable(ctx context.Context, id int64) (DetectorTableRevision, error)
	// AddDetectorTable stores a new revision; ID is assigned and
	// CreatedAt defaults to now.
	AddDetectorTable(ctx context.Context, r DetectorTableRevision) (DetectorTableRevision, error)
	// ListDetectorTables returns up to limit revisions, newest first,
	// without their YAML.
	ListDetectorTables(ctx context.Context, limit int) ([]DetectorTableRevision, error)
	// DetectorTableUsage counts the approved agents in the scope of ctx,
	// and the scanners, by kind and reported digest.
	DetectorTableUsage(ctx context.Context) ([]DetectorTableUsage, error)
}
