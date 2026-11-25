// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scansvc

import (
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestSSHIntegritySchedule(t *testing.T) {
	f := newFixture(t, true)
	tg := f.target("", 0)
	// A first collection links the target to its asset.
	must(t, f.svc.RequestRun(f.ctx, tg.ID))
	f.waitDone()
	f.waitLease(leaseKey(kindSSH, tg.ID))
	tg, err := f.db.GetScanTarget(f.ctx, tg.ID)
	must(t, err)
	if tg.AssetID == "" || tg.LastRun == nil {
		t.Fatalf("target after the collection: %+v", tg)
	}
	lastRun := tg.LastRun.At

	pol := integritysvc.DefaultPolicy()
	pol.WindowStart, pol.WindowEnd = "00:00", "00:00" // all day; jitter <= 12:00
	_, err = integritysvc.Save(f.ctx, f.db, pol)
	must(t, err)
	y, m, d := time.Now().Date()
	now := time.Date(y, m, d, 23, 30, 0, 0, time.Local)
	f.svc.now = func() time.Time { return now }

	must(t, f.svc.ScheduleSSHIntegrity(f.ctx))
	f.waitDone()
	f.waitLease(leaseKey(kindIntegrity, tg.ID))
	f.run.mu.Lock()
	job := f.run.ssh[len(f.run.ssh)-1]
	f.run.mu.Unlock()
	if job.Integrity == nil || job.Integrity.PassID == "" || job.Integrity.Cursor != "" || job.Policy.MaxRuntimeSeconds != 25*60 {
		t.Fatalf("first chunk %+v policy %+v", job.Integrity, job.Policy)
	}
	pass := job.Integrity.PassID
	p, err := f.db.LastIntegrityPass(f.ctx, tg.AssetID)
	must(t, err)
	if p.PassKey != pass || p.Cursor != "x" {
		t.Fatalf("pass %+v", p)
	}
	// The chunk is not a scan of the target.
	tg, err = f.db.GetScanTarget(f.ctx, tg.ID)
	must(t, err)
	if !tg.LastRun.At.Equal(lastRun) {
		t.Errorf("integrity chunk recorded as a scan run: %+v", tg.LastRun)
	}

	// The next chunk continues the pass at its cursor, cut to the window.
	now = now.Add(20 * time.Minute)
	must(t, f.svc.ScheduleSSHIntegrity(f.ctx))
	f.waitDone()
	f.waitLease(leaseKey(kindIntegrity, tg.ID))
	f.run.mu.Lock()
	job = f.run.ssh[len(f.run.ssh)-1]
	n := len(f.run.ssh)
	f.run.mu.Unlock()
	if job.Integrity.PassID != pass || job.Integrity.Cursor != "x" || job.Policy.MaxRuntimeSeconds != 10*60 {
		t.Errorf("second chunk %+v policy %+v", job.Integrity, job.Policy)
	}

	// Switched off for the target: nothing more.
	must(t, f.db.SetScanTargetIntegrity(f.ctx, tg.ID, store.IntegrityOff))
	now = now.Add(time.Minute)
	must(t, f.svc.ScheduleSSHIntegrity(f.ctx))
	time.Sleep(50 * time.Millisecond)
	f.run.mu.Lock()
	if len(f.run.ssh) != n {
		t.Error("chunk started for a target with integrity off")
	}
	f.run.mu.Unlock()
}

func TestSSHIntegrityBackoff(t *testing.T) {
	f := newFixture(t, true)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	f.svc.now = func() time.Time { return now }
	if f.svc.backingOff("t", nil, now) {
		t.Error("backing off before any attempt")
	}
	f.svc.markTried("t", now)
	if !f.svc.backingOff("t", nil, now.Add(time.Minute)) {
		t.Error("no backoff after an attempt without result")
	}
	if f.svc.backingOff("t", &store.IntegrityPass{LastChunkAt: now.Add(time.Second)}, now.Add(time.Minute)) {
		t.Error("backoff although the chunk left a result")
	}
	if f.svc.backingOff("t", nil, now.Add(integrityBackoff)) {
		t.Error("backoff after the wait")
	}
}
