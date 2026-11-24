// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// DetectDir is a directory walked for software on the agents and scan
// targets it is assigned to. Hosts without any only report running
// software.
type DetectDir struct {
	ID          string
	Path        string // absolute and clean
	Description string
	CreatedAt   time.Time

	// Agents and ScanTargets count the assignments. Read-only.
	Agents      int
	ScanTargets int
}

// DetectDirs stores detect directories and their assignments.
type DetectDirs interface {
	// CreateDetectDir stores d. ID is generated when empty; CreatedAt
	// defaults to now. ErrConflict when the path exists.
	CreateDetectDir(ctx context.Context, d DetectDir) (DetectDir, error)
	// ListDetectDirs returns every directory ordered by path.
	ListDetectDirs(ctx context.Context) ([]DetectDir, error)
	GetDetectDir(ctx context.Context, id string) (DetectDir, error)
	// UpdateDetectDir replaces path and description. ErrConflict when
	// another directory has the path.
	UpdateDetectDir(ctx context.Context, d DetectDir) (DetectDir, error)
	// DeleteDetectDir removes the directory and its assignments.
	DeleteDetectDir(ctx context.Context, id string) error
	// SetAgentDetectDirs replaces the directories of an agent. ErrNotFound
	// when the agent or one of the directories does not exist.
	SetAgentDetectDirs(ctx context.Context, agentID string, dirIDs []string) error
	// SetScanTargetDetectDirs replaces the directories of a scan target.
	// ErrNotFound when the target or one of the directories does not exist.
	SetScanTargetDetectDirs(ctx context.Context, targetID string, dirIDs []string) error
}
