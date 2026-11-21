// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package enrollsvc

import (
	"sync"
	"time"
)

// maxTracked bounds the number of key ids the limiter remembers.
const maxTracked = 10000

// limiter counts failed enrollment attempts per key id in fixed windows.
// It is per process; replicas count separately.
type limiter struct {
	max    int
	window time.Duration

	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	start    time.Time
	failures int
}

func newLimiter(max int, window time.Duration) *limiter {
	if max <= 0 {
		max = 10
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &limiter{max: max, window: window, entries: make(map[string]*limitEntry)}
}

// check returns a *RateLimitError when the key id is blocked at now.
func (l *limiter) check(keyID string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[keyID]
	if e == nil {
		return nil
	}
	end := e.start.Add(l.window)
	if !now.Before(end) {
		delete(l.entries, keyID)
		return nil
	}
	if e.failures >= l.max {
		return &RateLimitError{RetryAfter: end.Sub(now)}
	}
	return nil
}

// fail counts a failure of the key id.
func (l *limiter) fail(keyID string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[keyID]
	if e != nil && !now.Before(e.start.Add(l.window)) {
		e = nil
	}
	if e == nil {
		if len(l.entries) >= maxTracked {
			l.prune(now)
		}
		e = &limitEntry{start: now}
		l.entries[keyID] = e
	}
	e.failures++
}

// prune drops ended windows, and everything if that is not enough.
func (l *limiter) prune(now time.Time) {
	for k, e := range l.entries {
		if !now.Before(e.start.Add(l.window)) {
			delete(l.entries, k)
		}
	}
	if len(l.entries) >= maxTracked {
		clear(l.entries)
	}
}
