// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
	"github.com/bomcensus/bomcensus/internal/agent/state"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/report"
)

func TestNormalizeServerURL(t *testing.T) {
	good := map[string]string{
		"https://h:8443":           "https://h:8443",
		"https://h:8443/":          "https://h:8443",
		"https://h:8443/agent/v1/": "https://h:8443",
		"https://h/prefix":         "https://h/prefix",
	}
	for in, want := range good {
		if got, err := NormalizeServerURL(in); err != nil || got != want {
			t.Errorf("%s: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"http://h", "h:8443", "https://user@h", "https://h?x=1", ""} {
		if _, err := NormalizeServerURL(in); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

func TestRuntimeExtension(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	srv.Start()
	st, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tuning := Options{MinPollInterval: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
	_, err = Enroll(ctx, EnrollOptions{
		State: st, Kind: KindScanner, Version: "1.0.0", Token: srv.Token.String(), ServerURL: srv.URL,
		Host:          dto.HostFacts{Hostname: "scanner", Arch: "amd64", Os: dto.OsRelease{Family: "linux"}},
		HPKEPublicKey: []byte("public key"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A runtime of another kind refuses the state directory.
	if _, err := New(Options{State: st, Kind: KindAgent}); err == nil {
		t.Fatal("agent runtime opened a scanner state directory")
	}

	opts := tuning
	opts.State, opts.Kind, opts.Version = st, KindScanner, "1.0.0"
	rt, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var handled, ticks, uploaded atomic.Int32
	rt.Handle("scan_ssh", func(ctx context.Context, d dto.Directive) error {
		sd, err := d.AsScanSshDirective()
		if err != nil || sd.JobId != "job-1" {
			return errors.New("unexpected directive")
		}
		handled.Add(1)
		var buf bytes.Buffer
		rep := &report.Report{SchemaVersion: report.SchemaVersion, CollectedAt: time.Now(), Subject: &report.Subject{Kind: report.SubjectSelf}}
		if err := report.Encode(&buf, rep); err != nil {
			return err
		}
		return rt.SubmitReport(ctx, buf.Bytes(), ReportMeta{JobID: sd.JobId})
	})
	rt.AddTask(Task{Name: "tick", Interval: func() time.Duration { return 20 * time.Millisecond }, Run: func(context.Context) error {
		ticks.Add(1)
		return nil
	}})
	rt.OnUploaded(func(_ context.Context, m ReportMeta) {
		if m.JobID == "job-1" && m.ReportID != "" {
			uploaded.Add(1)
		}
	})
	sentinel := errors.New("stop requested")
	var acksSent atomic.Bool
	rt.OnStatus(func(_ context.Context, req *dto.PollRequest) {
		acksSent.Store(req.AckedDirectives != nil && len(*req.AckedDirectives) == 2)
	})
	rt.OnPoll(func(context.Context) {
		if acksSent.Load() && uploaded.Load() > 0 && ticks.Load() > 2 {
			rt.Stop(sentinel)
		}
	})
	srv.Queue(map[string]any{"type": "scan_ssh", "id": "s1", "job_id": "job-1", "scan_target_id": "t", "address": "10.0.0.1",
		"port": 22, "username": "u", "sudo": false, "credential": "AA==", "policy": map[string]any{"exec_version": false, "collect_cmdline": false, "scan_containers": false}})
	srv.Queue(map[string]any{"type": "k8s_sync", "id": "s2"})

	if err := rt.Run(ctx); !errors.Is(err, sentinel) {
		t.Fatalf("Run = %v", err)
	}
	if handled.Load() != 1 {
		t.Fatalf("handler ran %d times", handled.Load())
	}
	if !srv.Acked("s1") || !srv.Acked("s2") {
		t.Fatal("directives not acknowledged")
	}
	if len(srv.Reports()) != 1 {
		t.Fatalf("%d reports", len(srv.Reports()))
	}
}

func TestWaitIntervalFollowsShorterInterval(t *testing.T) {
	old := taskRecheck
	taskRecheck = 10 * time.Millisecond
	t.Cleanup(func() { taskRecheck = old })

	var cur atomic.Int64
	cur.Store(int64(time.Hour))
	interval := func() time.Duration { return time.Duration(cur.Load()) }
	go func() {
		time.Sleep(30 * time.Millisecond)
		cur.Store(int64(50 * time.Millisecond))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	due, ok := waitInterval(ctx, interval, time.Hour)
	if !due || !ok {
		t.Fatalf("due=%v ok=%v", due, ok)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("waited %v after the interval was shortened", el)
	}

	cur.Store(0)
	due, ok = waitInterval(ctx, interval, time.Hour)
	if due || !ok {
		t.Fatalf("disabled interval: due=%v ok=%v", due, ok)
	}
	cancel()
	if _, ok := waitInterval(ctx, interval, time.Hour); ok {
		t.Fatal("cancelled context reported ok")
	}
}

func TestRevokedIsTerminal(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	srv.Start()
	st, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	enr, err := Enroll(ctx, EnrollOptions{
		State: st, Kind: KindAgent, Version: "1.0.0", Token: srv.Token.String(), ServerURL: srv.URL,
		Host: dto.HostFacts{Hostname: "host", Arch: "amd64", Os: dto.OsRelease{Family: "linux"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tuning := Options{
		State: st, Kind: KindAgent, Version: "1.0.0",
		MinPollInterval: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		RevokedBackoff: 200 * time.Millisecond, MaxRevokedBackoff: 300 * time.Millisecond,
	}

	// Revoked while running, on the open mTLS connection: Run ends.
	rt, err := New(tuning)
	if err != nil {
		t.Fatal(err)
	}
	var polls atomic.Int32
	rt.OnPoll(func(context.Context) {
		if polls.Add(1) == 2 {
			srv.Revoke(enr.AgentID)
		}
	})
	if err := rt.Run(ctx); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Run = %v, want ErrRevoked", err)
	}
	rec, err := st.LoadRevocation()
	if err != nil || rec == nil || rec.Count != 1 {
		t.Fatalf("revocation record %+v, %v", rec, err)
	}

	// A restarted agent waits, asks once and stops again with a longer wait
	// recorded.
	for run := 2; run <= 3; run++ {
		before := srv.Requests()
		rt, err = New(tuning)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := rt.Run(ctx); !errors.Is(err, ErrRevoked) {
			t.Fatalf("run %d: Run = %v, want ErrRevoked", run, err)
		}
		if el := time.Since(start); el < 200*time.Millisecond {
			t.Fatalf("run %d: stopped after %v without waiting", run, el)
		}
		if n := srv.Requests() - before; n > 2 {
			t.Fatalf("run %d: %d signed requests", run, n)
		}
		if rec, _ := st.LoadRevocation(); rec == nil || rec.Count != run {
			t.Fatalf("run %d: revocation record %+v", run, rec)
		}
	}
	if w := revokedWait(1, 5*time.Minute, time.Hour); w != 5*time.Minute {
		t.Fatalf("first wait %v", w)
	}
	if w := revokedWait(10, 5*time.Minute, time.Hour); w != time.Hour {
		t.Fatalf("capped wait %v", w)
	}
}

func TestStaleRevocationRecordCleared(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	srv.Start()
	st, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Enroll(ctx, EnrollOptions{
		State: st, Kind: KindAgent, Version: "1.0.0", Token: srv.Token.String(), ServerURL: srv.URL,
		Host: dto.HostFacts{Hostname: "host", Arch: "amd64", Os: dto.OsRelease{Family: "linux"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRevocation(&state.Revocation{Count: 1, FirstSeen: time.Now(), LastSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	rt, err := New(Options{
		State: st, Kind: KindAgent, Version: "1.0.0",
		MinPollInterval: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		RevokedBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Without the certificate the approved agent is refused with
	// client_certificate_mismatch; it then reconnects with it.
	sentinel := errors.New("polled")
	rt.OnPoll(func(context.Context) { rt.Stop(sentinel) })
	if err := rt.Run(ctx); !errors.Is(err, sentinel) {
		t.Fatalf("Run = %v", err)
	}
	if rec, err := st.LoadRevocation(); err != nil || rec != nil {
		t.Fatalf("revocation record %+v, %v", rec, err)
	}
}
