// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// AgentKind distinguishes host agents from scanners.
type AgentKind string

const (
	AgentKindAgent   AgentKind = "agent"
	AgentKindScanner AgentKind = "scanner"
)

// ApprovalMode decides whether an enrollment is approved immediately.
type ApprovalMode string

const (
	ApprovalAuto   ApprovalMode = "auto"
	ApprovalManual ApprovalMode = "manual"
)

// Reasons a register key cannot be used. ConsumeRegisterKey and
// RegisterKey.Usable return these.
var (
	ErrRegisterKeyRevoked   = errors.New("store: register key revoked")
	ErrRegisterKeyExpired   = errors.New("store: register key expired")
	ErrRegisterKeyExhausted = errors.New("store: register key exhausted")
)

// RegisterKeyIDLen is the length of a register key ID: 8 random bytes in
// unpadded base64url.
const RegisterKeyIDLen = 11

// RegisterKey is the server side of an enrollment string: the key ID, the
// public key and the policy. The private seed is never stored.
type RegisterKey struct {
	ID   string
	Name string
	// ScopeID is the data scope of the key and of the agents enrolled with
	// it; empty for scanner keys, which are shared by every scope.
	ScopeID         string
	PublicKey       []byte // Ed25519
	Target          AgentKind
	ExpiresAt       *time.Time
	AllowedCIDRs    []netip.Prefix // empty means any source address
	MaxUses         int            // 0 means unlimited
	UsedCount       int
	Approval        ApprovalMode
	AllowRelaxedTLS bool
	DefaultGroup    string
	DefaultTags     []string
	CreatedBy       string
	CreatedAt       time.Time
	RevokedAt       *time.Time
}

// Usable reports why the key cannot enroll at now, or nil. The source
// address check is separate (AllowsAddr).
func (k RegisterKey) Usable(now time.Time) error {
	switch {
	case k.RevokedAt != nil:
		return ErrRegisterKeyRevoked
	case k.ExpiresAt != nil && !now.Before(*k.ExpiresAt):
		return ErrRegisterKeyExpired
	case k.MaxUses > 0 && k.UsedCount >= k.MaxUses:
		return ErrRegisterKeyExhausted
	}
	return nil
}

// AllowsAddr reports whether addr falls inside the allowed source ranges.
func (k RegisterKey) AllowsAddr(addr netip.Addr) bool {
	if len(k.AllowedCIDRs) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, p := range k.AllowedCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RegisterKeyFilter narrows ListRegisterKeys. Zero fields do not filter.
type RegisterKeyFilter struct {
	Q       string // case-insensitive substring of name or ID
	Target  AgentKind
	ScopeID string
	// State is valid, exhausted, expired or revoked (see Usable), judged
	// at Now.
	State string
	Now   time.Time
	// Sort is one of name, target, state, expiresAt, usedCount, approval,
	// createdAt, optionally prefixed with "-" for descending. Default
	// -createdAt. state orders valid, exhausted, expired, revoked.
	Sort string
}

// RegisterKeys stores register keys.
type RegisterKeys interface {
	// CreateRegisterKey stores k. ID must be set by the caller (it is derived
	// together with the enrollment string). CreatedAt defaults to now.
	// Returns ErrConflict when the ID exists.
	CreateRegisterKey(ctx context.Context, k RegisterKey) (RegisterKey, error)
	GetRegisterKey(ctx context.Context, id string) (RegisterKey, error)
	// ListRegisterKeys returns keys in f.Sort order and the total count.
	ListRegisterKeys(ctx context.Context, f RegisterKeyFilter, p Page) ([]RegisterKey, int, error)
	// RevokeRegisterKey sets the revocation time. Revoking twice keeps the
	// first time.
	RevokeRegisterKey(ctx context.Context, id string, at time.Time) error
	// ConsumeRegisterKey atomically counts one use and returns the updated
	// key. It fails with ErrRegisterKeyRevoked, ErrRegisterKeyExpired or
	// ErrRegisterKeyExhausted without counting, or ErrNotFound. Call it in
	// the same transaction that creates the agent so a failed enrollment
	// does not use up the key.
	ConsumeRegisterKey(ctx context.Context, id string, now time.Time) (RegisterKey, error)
}
