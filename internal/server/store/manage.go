// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"encoding/json"
	"errors"
)

// Manage covers sessions, register keys, agents, PKI material, releases,
// scan targets, credentials, feed servers and settings. Services should depend on the
// narrowest of the embedded interfaces they need.
type Manage interface {
	Sessions
	RegisterKeys
	EnrollSessions
	Agents
	AgentCerts
	PKI
	Releases
	Credentials
	ScanTargets
	DetectDirs
	ListenTargets
	Settings
	Directives
	ScanLeases
	FeedServers
	DetectorTables
}

// ErrInUse is returned when a record cannot be deleted because another record
// refers to it.
var ErrInUse = errors.New("store: in use")

// ErrInvalidState is returned when an operation does not apply to the current
// state of a record, such as approving a revoked agent.
var ErrInvalidState = errors.New("store: invalid state")

// ErrInvalid is returned when a value is rejected by a constraint of the
// store, such as an unknown enum value or an out-of-range number.
var ErrInvalid = errors.New("store: invalid value")

// Settings is a small key/value store for configuration that has no table of
// its own. Values are JSON documents.
type Settings interface {
	// GetSetting returns ErrNotFound when the key was never written.
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
	// PutSetting inserts or replaces the value of key.
	PutSetting(ctx context.Context, key string, value json.RawMessage) error
}
