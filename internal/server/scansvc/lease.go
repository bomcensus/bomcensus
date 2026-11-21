// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"context"
	"errors"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Embedded jobs hold a short lease that is renewed while they run, so the
// lease of a replica that died ends soon.
const (
	embeddedLeaseTTL   = 5 * time.Minute
	embeddedLeaseRenew = time.Minute
)

// Lease is a scan lease as the service sees it.
type Lease struct {
	Holder string // job id
	Until  time.Time
	// Started is when the lease was taken. It survives the release, so
	// schedulers can space attempts.
	Started time.Time
}

// Active reports whether the lease is held at now.
func (l Lease) Active(now time.Time) bool { return l.Holder != "" && now.Before(l.Until) }

// leases adapts store.ScanLeases.
type leases struct {
	st  store.ScanLeases
	now func() time.Time
}

func (l leases) Acquire(ctx context.Context, key, holder string, now, until time.Time) (bool, error) {
	return l.st.AcquireScanLease(ctx, key, holder, until.Sub(now), now)
}

func (l leases) Renew(ctx context.Context, key, holder string, ttl time.Duration) (bool, error) {
	return l.st.RenewScanLease(ctx, key, holder, ttl, l.now().UTC())
}

func (l leases) Release(ctx context.Context, key, holder string) error {
	return l.st.ReleaseScanLease(ctx, key, holder, l.now().UTC())
}

func (l leases) Get(ctx context.Context, key string) (Lease, error) {
	sl, err := l.st.GetScanLease(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return Lease{}, nil
	}
	if err != nil {
		return Lease{}, err
	}
	return Lease{Holder: sl.Owner, Until: sl.ExpiresAt, Started: sl.AcquiredAt}, nil
}

// keepLease renews holder's lease until the returned function is called,
// which then releases it.
func (s *Service) keepLease(ctx context.Context, key, holder string) (release func()) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(embeddedLeaseRenew)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				ok, err := s.leases.Renew(rctx, key, holder, embeddedLeaseTTL)
				cancel()
				if err != nil || !ok {
					s.log.Warn("cannot renew scan lease", "lease", key, "job_id", holder, "held", ok, "error", err)
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.leases.Release(rctx, key, holder); err != nil {
			s.log.Warn("cannot release scan lease", "lease", key, "error", err)
		}
	}
}
