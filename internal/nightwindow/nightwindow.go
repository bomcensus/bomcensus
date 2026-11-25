// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package nightwindow computes the daily time windows in which background
// work such as package file integrity passes runs, in a host's local time.
// Agents and the server (for SSH targets) use the same rules.
package nightwindow

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// Window is a daily time window in minutes after local midnight. End <=
// Start crosses midnight; End == Start is the whole day.
type Window struct{ Start, End int }

// Parse reads "HH:MM" start and end times.
func Parse(from, to string) (Window, error) {
	parse := func(s string) (int, error) {
		t, err := time.Parse("15:04", s)
		if err != nil || len(s) != 5 {
			return 0, fmt.Errorf("window: %q is not HH:MM", s)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	a, err := parse(from)
	if err != nil {
		return Window{}, err
	}
	b, err := parse(to)
	if err != nil {
		return Window{}, err
	}
	return Window{a, b}, nil
}

// Length is the duration of one window.
func (w Window) Length() time.Duration {
	m := (w.End - w.Start + 1440) % 1440
	if m == 0 {
		m = 1440
	}
	return time.Duration(m) * time.Minute
}

// Around returns the window that contains t, or the next one when t is
// outside every window, in absolute times.
func (w Window) Around(t time.Time, loc *time.Location) (from, to time.Time) {
	lt := t.In(loc)
	day := time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, loc)
	for off := -1; off <= 1; off++ {
		d := day.AddDate(0, 0, off)
		from = time.Date(d.Year(), d.Month(), d.Day(), w.Start/60, w.Start%60, 0, 0, loc)
		to = from.Add(w.Length())
		if t.Before(to) {
			return from, to
		}
	}
	return from, to
}

// Jitter spreads subjects over the first half of a window, the same way
// for one subject and window start.
func Jitter(subject string, from time.Time, length time.Duration) time.Duration {
	span := length / 2
	if span <= 0 {
		return 0
	}
	h := sha256.Sum256([]byte(subject + "|" + from.UTC().Format(time.RFC3339)))
	return time.Duration(binary.BigEndian.Uint64(h[:8]) % uint64(span))
}

// Location is the zone of a host with the given UTC offset in seconds, or
// fallback when the offset is unknown.
func Location(offset *int, fallback *time.Location) *time.Location {
	if offset == nil {
		return fallback
	}
	return time.FixedZone("host", *offset)
}
