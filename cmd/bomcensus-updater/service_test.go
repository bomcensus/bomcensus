// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
	"github.com/bomcensus/bomcensus/internal/updater"
)

type fakeAgent struct {
	pid      uint32
	restarts int
}

func (f *fakeAgent) PID() (uint32, error) { return f.pid, nil }

func (f *fakeAgent) Restart(context.Context) error {
	f.restarts++
	f.pid += 100
	return nil
}

type svcEnv struct {
	t       *testing.T
	tr      *signtest.Trust
	install string
	spool   string
	now     time.Time
	agent   *fakeAgent
}

func newSvcEnv(t *testing.T) *svcEnv {
	e := &svcEnv{t: t, tr: signtest.Install(t), now: time.Now(), agent: &fakeAgent{}}
	dir := t.TempDir()
	e.install = filepath.Join(dir, "install")
	e.spool = filepath.Join(dir, "spool")
	for _, d := range []string{e.install, e.spool} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *svcEnv) put(v string) {
	e.t.Helper()
	data := e.tr.SignELF(e.t, signtest.ELF(e.t, runtime.GOARCH))
	m := &sign.Manifest{Version: v, IssuedAt: e.now.Add(-time.Minute), ExpiresAt: e.now.Add(time.Hour),
		Files: []sign.File{signtest.FileEntry("linux", runtime.GOARCH, updater.AgentName, data)}}
	mb, sig := e.tr.SignManifest(e.t, m)
	var buf bytes.Buffer
	if err := release.Write(context.Background(), &buf, mb, sig,
		[]release.File{{OS: "linux", Arch: runtime.GOARCH, Name: updater.AgentName, Data: data}}); err != nil {
		e.t.Fatal(err)
	}
	e.file(updater.BundleName(v), buf.Bytes())
}

func (e *svcEnv) file(name string, data []byte) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.spool, name), data, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *svcEnv) watcher() *watcher {
	return e.watcherLog(io.Discard)
}

func (e *svcEnv) watcherLog(out io.Writer) *watcher {
	log := slog.New(slog.NewTextHandler(out, nil))
	return &watcher{
		opts:   updater.Options{InstallDir: e.install, Logger: log, Now: func() time.Time { return e.now }},
		spool:  e.spool,
		limits: updater.BootLimits{MaxAttempts: 2, PendingTimeout: time.Hour},
		agent:  e.agent,
		log:    log,
		now:    func() time.Time { return e.now },
	}
}

func (e *svcEnv) state() *updater.State {
	e.t.Helper()
	st, err := updater.Status(context.Background(), e.install)
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// installPending installs 1.0.0 confirmed and 1.1.0 pending through the
// watcher, as the service would.
func (e *svcEnv) installPending(w *watcher) {
	e.t.Helper()
	ctx := context.Background()
	e.put("1.0.0")
	if err := w.tick(ctx); !errors.Is(err, errSwitched) {
		e.t.Fatalf("install 1.0.0: %v", err)
	}
	e.file(updater.ConfirmName("1.0.0"), nil)
	if err := w.tick(ctx); err != nil {
		e.t.Fatalf("confirm: %v", err)
	}
	e.put("1.1.0")
	if err := w.tick(ctx); !errors.Is(err, errSwitched) {
		e.t.Fatalf("install 1.1.0: %v", err)
	}
}

func TestWatcherInstallRestartsAgent(t *testing.T) {
	e := newSvcEnv(t)
	e.agent.pid = 10
	w := e.watcher()
	ctx := context.Background()
	if err := w.start(ctx); err != nil || w.switched {
		t.Fatalf("start: %v switched=%v", err, w.switched)
	}
	if err := w.tick(ctx); err != nil {
		t.Fatalf("idle tick: %v", err)
	}
	e.installPending(w)
	if e.agent.restarts != 2 {
		t.Fatalf("agent restarted %d times, want 2", e.agent.restarts)
	}
	st := e.state()
	if st.Current != "1.1.0" || st.Pending == nil || st.Pending.Attempts != 0 {
		t.Fatalf("state %+v", st)
	}
}

func TestWatcherCountsAgentStarts(t *testing.T) {
	e := newSvcEnv(t)
	w := e.watcher()
	ctx := context.Background()
	e.installPending(w)

	// The service manager starts the new updater: its boot check counts
	// the agent start the old updater just made.
	w = e.watcher()
	if err := w.start(ctx); err != nil || w.switched {
		t.Fatalf("start: %v switched=%v", err, w.switched)
	}
	if got := e.state().Pending.Attempts; got != 1 {
		t.Fatalf("attempts after start %d", got)
	}
	if err := w.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.state().Pending.Attempts; got != 1 {
		t.Fatalf("attempts without a new agent process %d", got)
	}
	// The agent crashes and is restarted by its recovery action.
	e.agent.pid = 0
	if err := w.tick(ctx); err != nil {
		t.Fatal(err)
	}
	e.agent.pid = 555
	if err := w.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.state().Pending.Attempts; got != 2 {
		t.Fatalf("attempts after a restart %d", got)
	}
	e.agent.pid = 556
	restarts := e.agent.restarts
	if err := w.tick(ctx); !errors.Is(err, errSwitched) {
		t.Fatalf("third start: %v", err)
	}
	st := e.state()
	if st.Current != "1.0.0" || st.Pending != nil || e.agent.restarts != restarts+1 {
		t.Fatalf("not rolled back: %+v restarts=%d", st, e.agent.restarts)
	}
}

func TestWatcherSkipsStartCountedAtBoot(t *testing.T) {
	e := newSvcEnv(t)
	e.installPending(e.watcher())
	// Boot: the updater starts before the agent.
	e.agent.pid = 0
	w := e.watcher()
	ctx := context.Background()
	if err := w.start(ctx); err != nil {
		t.Fatal(err)
	}
	e.agent.pid = 42
	if err := w.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.state().Pending.Attempts; got != 1 {
		t.Fatalf("attempts %d, want 1", got)
	}
}

func TestWatcherPendingTimeout(t *testing.T) {
	e := newSvcEnv(t)
	e.agent.pid = 7
	w := e.watcher()
	e.installPending(w)
	ctx := context.Background()
	if err := w.tick(ctx); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(2 * time.Hour)
	if err := w.tick(ctx); !errors.Is(err, errSwitched) {
		t.Fatalf("timeout tick: %v", err)
	}
	if st := e.state(); st.Current != "1.0.0" || len(st.Failed) != 1 {
		t.Fatalf("state %+v", st)
	}
}

func TestWatcherRollbackAtStart(t *testing.T) {
	e := newSvcEnv(t)
	e.agent.pid = 7
	e.installPending(e.watcher())
	e.now = e.now.Add(2 * time.Hour)
	w := e.watcher()
	ctx := context.Background()
	if err := w.start(ctx); err != nil || !w.switched {
		t.Fatalf("start: %v switched=%v", err, w.switched)
	}
	restarts := e.agent.restarts
	if err := w.run(ctx, time.Hour); !errors.Is(err, errSwitched) || e.agent.restarts != restarts+1 {
		t.Fatalf("run after a rollback at start: %v restarts=%d", err, e.agent.restarts)
	}
}

// An updater restart while the agent keeps running is not an agent start.
func TestWatcherRestartDoesNotCount(t *testing.T) {
	e := newSvcEnv(t)
	e.installPending(e.watcher())
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := e.watcher().start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	st := e.state()
	if st.Current != "1.1.0" || st.Pending == nil || st.Pending.Attempts != 1 {
		t.Fatalf("state %+v", st)
	}
}

// A first install has no version to roll back to. Its expired pending mark
// is tried once, not on every poll.
func TestWatcherExpireWithoutPrevious(t *testing.T) {
	e := newSvcEnv(t)
	e.agent.pid = 7
	var out bytes.Buffer
	w := e.watcherLog(&out)
	ctx := context.Background()
	e.put("1.0.0")
	if err := w.tick(ctx); !errors.Is(err, errSwitched) {
		t.Fatalf("install: %v", err)
	}
	w = e.watcherLog(&out)
	if err := w.start(ctx); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(2 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := w.tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(out.String(), "no previous version"); n != 1 {
		t.Fatalf("rollback tried %d times:\n%s", n, out.String())
	}
	if st := e.state(); st.Current != "1.0.0" || st.Pending == nil {
		t.Fatalf("state %+v", st)
	}
}

// Entries Apply refuses and leaves in place do not start Apply on every
// poll; a changed entry does.
func TestWatcherRefusedSpoolEntry(t *testing.T) {
	e := newSvcEnv(t)
	var out bytes.Buffer
	w := e.watcherLog(&out)
	ctx := context.Background()
	dir := filepath.Join(e.spool, updater.RollbackName)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(out.String(), "spool entry refused"); n != 1 {
		t.Fatalf("refused %d times:\n%s", n, out.String())
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(dir, later, later); err != nil {
		t.Fatal(err)
	}
	if err := w.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "spool entry refused"); n != 2 {
		t.Fatalf("changed entry: refused %d times", n)
	}
}
