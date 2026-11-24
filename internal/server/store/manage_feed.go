// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// FeedInstance is the key that identifies this installation to feed servers.
type FeedInstance struct {
	PublicKey    string // "x25519 <base64>"
	EncryptedKey []byte // sealed by the caller
	CreatedAt    time.Time
}

// FeedServerStatus is the connection state of a feed server.
type FeedServerStatus string

const (
	FeedServerNever      FeedServerStatus = "never"
	FeedServerConnected  FeedServerStatus = "connected"
	FeedServerKeyChanged FeedServerStatus = "key_changed"
	FeedServerError      FeedServerStatus = "error"
)

// FeedSource is the freshness of one data source of a feed server.
type FeedSource struct {
	Name      string     `json:"name"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	ChangedAt *time.Time `json:"changed_at,omitempty"`
	Healthy   *bool      `json:"healthy,omitempty"`
}

// FeedServer is a registered feed server.
type FeedServer struct {
	ID        string
	Name      string
	URL       string
	Builtin   bool
	Active    bool
	Enabled   bool
	Telemetry bool
	// ServerKey is the trusted key, empty before the first contact.
	ServerKey    string
	KeyTrustedAt *time.Time
	// PresentedKey is a key the server presented that differs from
	// ServerKey; set while Status is FeedServerKeyChanged.
	PresentedKey     string
	PresentedAt      *time.Time
	Status           FeedServerStatus
	LastError        string
	LastErrorAt      *time.Time
	LastOKAt         *time.Time
	Grade            string
	SessionExpiresAt *time.Time
	// Revision and RulesDigest are nil before the first status check.
	Revision        *int64
	RulesDigest     *string
	Sources         []FeedSource
	StatusCheckedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// FeedServerCreate are the fields of a new feed server.
type FeedServerCreate struct {
	Name      string
	URL       string
	Telemetry bool
}

// FeedServerUpdate changes the fields that are not nil.
type FeedServerUpdate struct {
	Name      *string
	Enabled   *bool
	Telemetry *bool
}

// FeedSession is what a successful contact reports.
type FeedSession struct {
	Grade     string
	ExpiresAt time.Time
}

// FeedData is the data state a feed server reports.
type FeedData struct {
	Revision    int64
	RulesDigest string
	Sources     []FeedSource
}

// FeedServers stores the feed servers and the instance key.
type FeedServers interface {
	// GetFeedInstance returns ErrNotFound before the key is created.
	GetFeedInstance(ctx context.Context) (FeedInstance, error)
	// CreateFeedInstance stores the key unless one exists; it returns the
	// stored one either way.
	CreateFeedInstance(ctx context.Context, in FeedInstance) (FeedInstance, error)

	// ListFeedServers returns the servers, built-in first, then by name.
	ListFeedServers(ctx context.Context) ([]FeedServer, error)
	GetFeedServer(ctx context.Context, id string) (FeedServer, error)
	// GetActiveFeedServer returns ErrNotFound when no server is active.
	GetActiveFeedServer(ctx context.Context) (FeedServer, error)
	// CreateFeedServer returns ErrConflict when the URL is taken.
	CreateFeedServer(ctx context.Context, in FeedServerCreate) (FeedServer, error)
	// UpdateFeedServer applies u. Disabling the active server returns
	// ErrInvalidState.
	UpdateFeedServer(ctx context.Context, id string, u FeedServerUpdate) (FeedServer, error)
	// DeleteFeedServer returns ErrInvalidState for the built-in or the
	// active server.
	DeleteFeedServer(ctx context.Context, id string) error
	// ActivateFeedServer makes id the only active server. A disabled server
	// returns ErrInvalidState.
	ActivateFeedServer(ctx context.Context, id string) (FeedServer, error)

	// TrustFeedServerKey stores key as the server key if none is stored
	// yet. It returns the key stored afterwards, which differs from key
	// when another replica stored one first.
	TrustFeedServerKey(ctx context.Context, id, key string) (string, error)
	// RecordFeedServerKeyChange sets the key_changed state with the
	// presented key.
	RecordFeedServerKeyChange(ctx context.Context, id, presented string) error
	// AcceptFeedServerKey replaces the server key with the presented key
	// if it equals key; ErrInvalidState otherwise.
	AcceptFeedServerKey(ctx context.Context, id, key string) (FeedServer, error)
	// RecordFeedServerOK sets the connected state. It leaves a server in
	// the key_changed state alone.
	RecordFeedServerOK(ctx context.Context, id string, s FeedSession) error
	// RecordFeedServerError sets the error state with msg. It leaves a
	// server in the key_changed state alone.
	RecordFeedServerError(ctx context.Context, id, msg string) error
	// RecordFeedData stores the data state.
	RecordFeedData(ctx context.Context, id string, d FeedData) error
}
