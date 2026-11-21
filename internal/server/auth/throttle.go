// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package auth

import (
	"sync"
	"time"
)

// LimiterConfig tunes a Limiter. Zero fields take the defaults.
type LimiterConfig struct {
	// Threshold is the number of failed attempts that starts a lockout
	// (default 5).
	Threshold int
	// BaseLockout is the first lockout (default 30 s). Every further failure
	// doubles it, up to MaxLockout (default 15 min).
	BaseLockout time.Duration
	MaxLockout  time.Duration
	// Forget drops the failure count after this long without a failure
	// (default 1 h).
	Forget time.Duration
	// MaxEntries bounds the number of tracked keys (default 10000).
	MaxEntries int
	Now        func() time.Time
}

// Limiter counts failed logins per key (a client address, a username) in
// memory. It is per server process; replicas count separately.
type Limiter struct {
	cfg     LimiterConfig
	mu      sync.Mutex
	entries map[string]*limiterEntry
}

type limiterEntry struct {
	failures    int
	last        time.Time
	lockedUntil time.Time
}

// NewLimiter returns a Limiter.
func NewLimiter(cfg LimiterConfig) *Limiter {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	}
	if cfg.BaseLockout <= 0 {
		cfg.BaseLockout = 30 * time.Second
	}
	if cfg.MaxLockout < cfg.BaseLockout {
		cfg.MaxLockout = 15 * time.Minute
		if cfg.MaxLockout < cfg.BaseLockout {
			cfg.MaxLockout = cfg.BaseLockout
		}
	}
	if cfg.Forget <= 0 {
		cfg.Forget = time.Hour
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Limiter{cfg: cfg, entries: map[string]*limiterEntry{}}
}

// Attempt registers an attempt for all keys. When any key is locked it
// returns the time left and false, and counts nothing. Otherwise the attempt
// counts as a failure for every key until Succeeded clears them; counting
// before the outcome is known keeps concurrent attempts from slipping past
// the threshold.
func (l *Limiter) Attempt(keys ...string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	var wait time.Duration
	for _, k := range keys {
		if e := l.entries[k]; e != nil && now.Before(e.lockedUntil) {
			wait = max(wait, e.lockedUntil.Sub(now))
		}
	}
	if wait > 0 {
		return wait, false
	}
	if len(l.entries)+len(keys) > l.cfg.MaxEntries {
		l.prune(now)
	}
	for _, k := range keys {
		e := l.entries[k]
		if e == nil {
			e = &limiterEntry{}
			l.entries[k] = e
		} else if now.Sub(e.last) > l.cfg.Forget {
			*e = limiterEntry{}
		}
		e.failures++
		e.last = now
		if n := e.failures - l.cfg.Threshold; n >= 0 {
			d := l.cfg.BaseLockout
			for i := 0; i < n && d < l.cfg.MaxLockout; i++ {
				d *= 2
			}
			e.lockedUntil = now.Add(min(d, l.cfg.MaxLockout))
		}
	}
	return 0, true
}

// Succeeded clears the keys after a successful login.
func (l *Limiter) Succeeded(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}

// prune drops forgotten entries, then unlocked ones if still too many.
func (l *Limiter) prune(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.last) > l.cfg.Forget && !now.Before(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.cfg.MaxEntries {
		return
	}
	for k, e := range l.entries {
		if !now.Before(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
}
