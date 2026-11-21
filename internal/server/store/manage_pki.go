// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Names of PKI objects. Other names are allowed.
const (
	PKIWebCA                 = "web-ca"
	PKIWebLeaf               = "web-leaf"
	PKIAgentTLSCA            = "agent-tls-ca"
	PKIAgentTLSLeaf          = "agent-tls-leaf"
	PKIAgentTLSClient        = "agent-tls-client"
	PKIAgentTLSAnchorPending = "agent-tls-anchor-pending"
	PKIAgentCA               = "agent-ca"
)

// Common PKI object states. The store does not interpret State.
const (
	PKIStateActive  = "active"
	PKIStatePending = "pending"
	PKIStateRetired = "retired"
)

// PKIObject is a named certificate chain with its private key.
type PKIObject struct {
	Name         string
	CertChainPEM []byte // leaf first
	EncryptedKey []byte // encrypted by the caller; nil when there is no key
	State        string
	// Version starts at 1 and grows by one on every successful put.
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TLSEndpoint selects one of the two server TLS configurations.
type TLSEndpoint string

const (
	TLSEndpointWeb   TLSEndpoint = "web"
	TLSEndpointAgent TLSEndpoint = "agent"
)

// TLSMode is how a TLS endpoint gets its certificate.
type TLSMode string

const (
	TLSModeAuto   TLSMode = "auto"
	TLSModeManual TLSMode = "manual"
)

// TLSSetting is the mode of one TLS endpoint.
type TLSSetting struct {
	Endpoint  TLSEndpoint
	Mode      TLSMode
	UpdatedAt time.Time // zero when never set
}

// PKI stores certificate material shared by all server replicas.
type PKI interface {
	GetPKIObject(ctx context.Context, name string) (PKIObject, error)
	// ListPKIObjects returns all objects ordered by name.
	ListPKIObjects(ctx context.Context) ([]PKIObject, error)
	// PutPKIObject writes o if the stored version equals expectVersion; 0
	// means the object must not exist yet. It returns the stored object with
	// its new version, or ErrConflict when another writer won. A replica that
	// gets ErrConflict on first start must re-read and use the winner's CA.
	PutPKIObject(ctx context.Context, o PKIObject, expectVersion int64) (PKIObject, error)
	// DeletePKIObject removes the object if its version equals
	// expectVersion; ErrConflict otherwise, ErrNotFound when missing.
	DeletePKIObject(ctx context.Context, name string, expectVersion int64) error

	// GetTLSSetting returns the mode of the endpoint, auto when never set.
	GetTLSSetting(ctx context.Context, endpoint TLSEndpoint) (TLSSetting, error)
	// PutTLSSetting stores s. UpdatedAt defaults to now.
	PutTLSSetting(ctx context.Context, s TLSSetting) error

	// TrustBundleVersion returns the current trust bundle version (0 before
	// the first bump).
	TrustBundleVersion(ctx context.Context) (int64, error)
	// BumpTrustBundleVersion increments the version and returns the new one.
	BumpTrustBundleVersion(ctx context.Context) (int64, error)
}
