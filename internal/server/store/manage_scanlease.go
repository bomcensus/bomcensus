// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// ScanLease marks a scan job in flight for a key (a scan target, the sync
// or the exec collection of a cluster). A lease is held while ExpiresAt is
// after now; a released lease stays as a record of the last attempt until
// it is deleted.
type ScanLease struct {
	Key   string
	Owner string // job id
	// AcquiredAt is when Owner took the lease.
	AcquiredAt time.Time
	ExpiresAt  time.Time
}

// ScanLeases keeps at most one scan job in flight per key across server
// replicas. Every operation is a single atomic statement.
type ScanLeases interface {
	// AcquireScanLease takes key for owner until now+ttl when nobody holds
	// it at now. An owner that holds it already extends it. It reports
	// whether owner holds the lease.
	AcquireScanLease(ctx context.Context, key, owner string, ttl time.Duration, now time.Time) (bool, error)
	// RenewScanLease extends owner's lease to now+ttl. It reports false
	// when owner does not hold the lease at now.
	RenewScanLease(ctx context.Context, key, owner string, ttl time.Duration, now time.Time) (bool, error)
	// ReleaseScanLease ends owner's lease at now; a lease of another owner
	// is kept.
	ReleaseScanLease(ctx context.Context, key, owner string, now time.Time) error
	// GetScanLease returns the lease record of key, held or not;
	// ErrNotFound when there is none.
	GetScanLease(ctx context.Context, key string) (ScanLease, error)
	// DeleteExpiredScanLeases removes leases that ended at or before t.
	DeleteExpiredScanLeases(ctx context.Context, t time.Time) (int64, error)
}
