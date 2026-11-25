// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package integritysvc

import (
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestNextChunk(t *testing.T) {
	p := DefaultPolicy()
	off := 9 * 3600 // the host is in UTC+9; the window is 02:00-05:00 there
	at := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, time.FixedZone("", off)) }

	// No pass yet, the host's zone unknown: the server's zone is used.
	if _, ok := NextChunk(p, "t1", nil, time.Date(2026, 11, 25, 12, 0, 0, 0, time.Local)); ok {
		t.Error("chunk outside the window")
	}

	done := at(24, 3, 0)
	last := &store.IntegrityPass{PassKey: "old", StartedAt: at(24, 2, 40), CompletedAt: &done, UTCOffset: &off}
	// 04:30 local is inside the window and after any jitter (<= 03:30).
	c, ok := NextChunk(p, "t1", last, at(25, 4, 30))
	if !ok || c.Query.PassID == "" || c.Query.PassID == "old" || c.Query.Cursor != "" {
		t.Fatalf("new pass: %+v %v", c, ok)
	}
	if c.Limit != ChunkLength {
		t.Errorf("limit %s", c.Limit)
	}
	if c.Query.MaxReadMBps != 20 {
		t.Errorf("query %+v", c.Query)
	}
	// Near the end the chunk is cut to the window.
	c, ok = NextChunk(p, "t1", last, at(25, 4, 50))
	if !ok || c.Limit != 10*time.Minute {
		t.Errorf("near the end: %+v %v", c, ok)
	}
	if _, ok := NextChunk(p, "t1", last, at(25, 4, 59)); ok {
		t.Error("chunk a minute before the end")
	}

	// The same night after a pass started: nothing.
	started := &store.IntegrityPass{PassKey: "p", StartedAt: at(25, 3, 0), CompletedAt: &done, UTCOffset: &off}
	if _, ok := NextChunk(p, "t1", started, at(25, 4, 30)); ok {
		t.Error("second pass in one night")
	}

	// An unfinished pass continues at its cursor.
	open := &store.IntegrityPass{PassKey: "p", StartedAt: at(24, 3, 0), Cursor: "deb/x", UTCOffset: &off}
	c, ok = NextChunk(p, "t1", open, at(25, 4, 30))
	if !ok || c.Query.PassID != "p" || c.Query.Cursor != "deb/x" {
		t.Errorf("continue: %+v %v", c, ok)
	}
	// A pass unfinished for two weeks is replaced.
	open.StartedAt = at(1, 3, 0)
	c, ok = NextChunk(p, "t1", open, at(25, 4, 30))
	if !ok || c.Query.PassID == "p" {
		t.Errorf("stale pass continued: %+v", c)
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Policy){
		"window":   func(p *Policy) { p.WindowStart = "2:00" },
		"interval": func(p *Policy) { p.IntervalDays = 0 },
		"rate":     func(p *Policy) { p.MaxReadMBps = 5000 },
		"rehash":   func(p *Policy) { p.FullRehashDays = 0 },
		"exclude":  func(p *Policy) { p.ExcludePaths = []string{"usr"} },
	} {
		p := DefaultPolicy()
		mut(&p)
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	p := DefaultPolicy()
	p.ExcludePaths = []string{" /a ", "", "/a", "/b"}
	if got := p.Normalize().ExcludePaths; len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Errorf("normalized %v", got)
	}
	for mode, want := range map[string]bool{store.IntegrityOn: true, store.IntegrityOff: false, store.IntegrityInherit: true, "": true} {
		if Enabled(mode, true) != want {
			t.Errorf("Enabled(%q, true) != %v", mode, want)
		}
	}
	if Enabled(store.IntegrityInherit, false) {
		t.Error("inherit ignores the default")
	}
}
