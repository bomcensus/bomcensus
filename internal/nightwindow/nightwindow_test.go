// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package nightwindow

import (
	"testing"
	"time"
)

func TestWindowAround(t *testing.T) {
	loc := time.FixedZone("KST", 9*3600)
	at := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, loc) }
	cases := []struct {
		name     string
		from, to string
		now      time.Time
		wantFrom time.Time
		wantTo   time.Time
	}{
		{"before", "02:00", "05:00", at(25, 1, 0), at(25, 2, 0), at(25, 5, 0)},
		{"inside", "02:00", "05:00", at(25, 3, 0), at(25, 2, 0), at(25, 5, 0)},
		{"after", "02:00", "05:00", at(25, 6, 0), at(26, 2, 0), at(26, 5, 0)},
		{"midnight, evening", "23:00", "03:00", at(25, 23, 30), at(25, 23, 0), at(26, 3, 0)},
		{"midnight, morning", "23:00", "03:00", at(26, 1, 0), at(25, 23, 0), at(26, 3, 0)},
		{"midnight, day", "23:00", "03:00", at(26, 12, 0), at(26, 23, 0), at(27, 3, 0)},
		{"whole day", "04:00", "04:00", at(25, 12, 0), at(25, 4, 0), at(26, 4, 0)},
	}
	for _, c := range cases {
		w, err := Parse(c.from, c.to)
		if err != nil {
			t.Fatal(err)
		}
		from, to := w.Around(c.now, loc)
		if !from.Equal(c.wantFrom) || !to.Equal(c.wantTo) {
			t.Errorf("%s: %s..%s, want %s..%s", c.name, from, to, c.wantFrom, c.wantTo)
		}
	}
	if _, err := Parse("2:00", "05:00"); err == nil {
		t.Error("bad time accepted")
	}
}

func TestWindowJitter(t *testing.T) {
	from := time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC)
	a := Jitter("agent-a", from, 3*time.Hour)
	if a != Jitter("agent-a", from, 3*time.Hour) {
		t.Error("jitter not stable")
	}
	if a < 0 || a >= 90*time.Minute {
		t.Errorf("jitter %s outside the first half", a)
	}
	seen := map[time.Duration]bool{}
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		seen[Jitter(id, from, 3*time.Hour)] = true
	}
	if len(seen) < 4 {
		t.Error("jitter does not spread agents")
	}
}
