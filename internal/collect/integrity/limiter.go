// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package integrity

import (
	"context"
	"time"
)

// limiter paces reads to a byte rate. It lets a short burst through so that
// small files are not delayed one by one.
type limiter struct {
	rate  float64 // bytes per second
	burst time.Duration
	next  time.Time
	now   func() time.Time
	sleep func(context.Context, time.Duration) bool
}

func newLimiter(bytesPerSec int64, now func() time.Time, sleep func(context.Context, time.Duration) bool) *limiter {
	return &limiter{rate: float64(bytesPerSec), burst: 200 * time.Millisecond, now: now, sleep: sleep}
}

// wait accounts for n bytes read and sleeps when the reads are ahead of the
// rate. It returns false when ctx ended.
func (l *limiter) wait(ctx context.Context, n int) bool {
	if l.rate <= 0 || n <= 0 {
		return ctx.Err() == nil
	}
	now := l.now()
	if l.next.Before(now) {
		l.next = now
	}
	l.next = l.next.Add(time.Duration(float64(n) / l.rate * float64(time.Second)))
	if d := l.next.Sub(now); d > l.burst {
		return l.sleep(ctx, d)
	}
	return ctx.Err() == nil
}

// sleepCtx sleeps for d or until ctx ends; it returns false in the latter
// case.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
