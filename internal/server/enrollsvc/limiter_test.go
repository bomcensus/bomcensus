// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package enrollsvc

import (
	"errors"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	t0 := time.Unix(1_800_000_000, 0)
	if err := l.check("k", t0); err != nil {
		t.Fatal(err)
	}
	l.fail("k", t0)
	if err := l.check("k", t0); err != nil {
		t.Fatalf("after one failure: %v", err)
	}
	l.fail("k", t0.Add(time.Second))
	err := l.check("k", t0.Add(2*time.Second))
	var rl *RateLimitError
	if !errors.Is(err, ErrRateLimited) || !errors.As(err, &rl) || rl.RetryAfter != 58*time.Second {
		t.Fatalf("blocked: %v", err)
	}
	if err := l.check("other", t0); err != nil {
		t.Fatalf("other key: %v", err)
	}
	if err := l.check("k", t0.Add(time.Minute)); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestLimiterBounded(t *testing.T) {
	l := newLimiter(1, time.Minute)
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < maxTracked+10; i++ {
		l.fail(string(rune(i)), t0)
	}
	if len(l.entries) > maxTracked {
		t.Fatalf("%d entries", len(l.entries))
	}
}
