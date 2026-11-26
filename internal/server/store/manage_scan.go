// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// CredentialKind is the type of secret a credential holds.
type CredentialKind string

const (
	CredentialSSHKey      CredentialKind = "ssh_key"
	CredentialSSHPassword CredentialKind = "ssh_password"
	CredentialKubeconfig  CredentialKind = "kubeconfig"
)

// Credential is a secret used for remote collection.
type Credential struct {
	ID       string
	Name     string // unique within the scope
	ScopeID  string
	Kind     CredentialKind
	Username string
	// Secret is encrypted by the caller. Only GetCredentialWithSecret fills
	// it.
	Secret []byte
	// PublicKeyFingerprint is the OpenSSH SHA-256 fingerprint of the public
	// key of an ssh_key credential; empty for other kinds.
	PublicKeyFingerprint string
	CreatedBy            string
	CreatedAt            time.Time
	// UsedBy is the number of scan targets that refer to the credential.
	// Read-only. Kubernetes cluster references are not counted here.
	UsedBy int
}

// Credentials stores credentials for remote collection.
type Credentials interface {
	// CreateCredential stores c. ID is generated when empty; CreatedAt
	// defaults to now. ErrConflict when the name exists.
	CreateCredential(ctx context.Context, c Credential) (Credential, error)
	// ListCredentials returns credentials ordered by name, without secrets.
	ListCredentials(ctx context.Context) ([]Credential, error)
	// GetCredential returns the credential without its secret.
	GetCredential(ctx context.Context, id string) (Credential, error)
	GetCredentialWithSecret(ctx context.Context, id string) (Credential, error)
	// UpdateCredentialSecret replaces username, secret and public key
	// fingerprint of the credential c.ID. Name and kind are kept.
	UpdateCredentialSecret(ctx context.Context, c Credential) (Credential, error)
	// DeleteCredential fails with ErrInUse while a scan target refers to
	// the credential. Kubernetes cluster references are checked by the
	// caller, in the same transaction.
	DeleteCredential(ctx context.Context, id string) error
}

// ScanResult is the outcome of a scan run.
type ScanResult string

const (
	ScanOK      ScanResult = "ok"
	ScanPartial ScanResult = "partial"
	ScanFailed  ScanResult = "failed"
)

// ScanRun is the record of the last scan of a target.
type ScanRun struct {
	At       time.Time
	Result   ScanResult
	Message  string
	Duration time.Duration // stored with millisecond precision
}

// ScanTarget is an SSH host collected without an agent.
type ScanTarget struct {
	ID           string
	Name         string
	ScopeID      string // set on create
	Address      string
	Port         int
	CredentialID string
	ScannerID    string // empty means the embedded scanner
	Sudo         bool
	// HostKey is the pinned SSH host key in wire format; nil until the first
	// connection stores it.
	HostKey []byte
	// IntervalMinutes is the scan schedule; 0 means on demand only.
	IntervalMinutes int
	AssetID         string
	LastRun         *ScanRun
	CreatedAt       time.Time
	// DetectDirIDs are the assigned detect directories and DetectPaths
	// their paths, both ordered by path. Read-only; see DetectDirs.
	DetectDirIDs []string
	DetectPaths  []string
	// Integrity is the target's integrity mode (IntegrityInherit, ...).
	// Create and update store it; empty means IntegrityInherit.
	Integrity string
}

// ScanTargetFilter narrows ListScanTargets. Zero fields do not filter.
type ScanTargetFilter struct {
	Q            string // case-insensitive substring of name or address
	ScopeID      string
	ScannerID    string
	CredentialID string
	// LastResult keeps targets whose last run had this result.
	LastResult ScanResult
	// Sort is one of name, address, lastRun, optionally prefixed with "-"
	// for descending. Default name. Targets never run sort lowest.
	Sort string
}

// ScanTargets stores SSH scan targets.
type ScanTargets interface {
	// CreateScanTarget stores t. ID is generated when empty; CreatedAt
	// defaults to now. ErrNotFound when the credential or scanner does not
	// exist.
	CreateScanTarget(ctx context.Context, t ScanTarget) (ScanTarget, error)
	GetScanTarget(ctx context.Context, id string) (ScanTarget, error)
	// ListScanTargets returns targets in f.Sort order and the total count.
	ListScanTargets(ctx context.Context, f ScanTargetFilter, p Page) ([]ScanTarget, int, error)
	// UpdateScanTarget replaces name, address, port, credential, scanner,
	// sudo, interval and integrity mode. Host key, asset and last run are
	// kept.
	UpdateScanTarget(ctx context.Context, t ScanTarget) error
	DeleteScanTarget(ctx context.Context, id string) error
	// SetScanTargetHostKey pins key when none is pinned. Setting the same
	// key again is a no-op; a different key gives ErrConflict.
	SetScanTargetHostKey(ctx context.Context, id string, key []byte) error
	// ClearScanTargetHostKey removes the pinned host key; the next
	// connection pins the key it sees.
	ClearScanTargetHostKey(ctx context.Context, id string) error
	// SetScanTargetAsset links the target to an asset; empty unlinks.
	SetScanTargetAsset(ctx context.Context, id, assetID string) error
	// RecordScanRun stores the outcome of a run.
	RecordScanRun(ctx context.Context, id string, run ScanRun) error
	// ListDueScanTargets returns scheduled targets of the scanner (empty
	// scannerID means the embedded scanner) that have never run or whose
	// last run is at least the interval before now, oldest first. limit <= 0
	// means 1000.
	ListDueScanTargets(ctx context.Context, scannerID string, now time.Time, limit int) ([]ScanTarget, error)
}
