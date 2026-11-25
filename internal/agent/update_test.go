// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// These tests use the Linux install layout (a symlink named current) and an
// agent that runs the updater itself. On Windows the updater service does
// both; internal/updater covers that flow.

//go:build !windows

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
	"github.com/bomcensus/bomcensus/internal/agent/update"
	"github.com/bomcensus/bomcensus/internal/sign"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
	"github.com/bomcensus/bomcensus/internal/updater"
)

type updateEnv struct {
	install string
	spool   string
	mu      sync.Mutex
	calls   []string
}

func (e *updateEnv) runUpdater(_ context.Context, args ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, strings.Join(args, " "))
	return nil
}

func (e *updateEnv) called(cmd string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.ContainsFunc(e.calls, func(c string) bool { return strings.HasPrefix(c, cmd+" ") })
}

func newUpdateEnv(t *testing.T, running string) *updateEnv {
	t.Helper()
	dir := t.TempDir()
	e := &updateEnv{install: filepath.Join(dir, "opt"), spool: filepath.Join(dir, "update-spool")}
	e.installVersion(t, running)
	return e
}

func (e *updateEnv) installVersion(t *testing.T, v string) {
	t.Helper()
	vd := filepath.Join(e.install, "versions", v)
	if err := os.MkdirAll(vd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vd, updater.AgentName), []byte("agent "+v), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(e.install, ".current.tmp")
	if err := os.Symlink(filepath.Join("versions", v), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(e.install, "current")); err != nil {
		t.Fatal(err)
	}
}

func (e *updateEnv) options(o *Options, running string) {
	o.DisableUpdates = false
	o.InstallDir = e.install
	o.UpdateSpool = e.spool
	o.RunUpdater = e.runUpdater
	o.UpdateWatchInterval = 50 * time.Millisecond
	o.Executable = filepath.Join(e.install, "versions", running, updater.AgentName)
	o.Version = running
}

func release(t *testing.T, tr *signtest.Trust, v string) *fakeserver.Update {
	t.Helper()
	agentBin := []byte("new agent " + v)
	now := time.Now()
	manifest, sig := tr.SignManifest(t, &sign.Manifest{
		Version:   v,
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
		Files:     []sign.File{signtest.FileEntry("linux", runtime.GOARCH, updater.AgentName, agentBin)},
	})
	bundle := make([]byte, 64<<10)
	_, _ = rand.Read(bundle)
	return &fakeserver.Update{Version: v, Manifest: manifest, Sig: sig, Bundle: bundle}
}

func TestUpdateDownloadAndReexec(t *testing.T) {
	tr := signtest.Install(t)
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	e := newUpdateEnv(t, "1.0.0")
	u := release(t, tr, "1.1.0")
	h.srv.SetUpdate(u)
	r := h.start(func(o *Options) { e.options(o, "1.0.0") })

	bundlePath := filepath.Join(e.spool, updater.BundleName("1.1.0"))
	h.wait("bundle in the spool", func() bool {
		b, err := os.ReadFile(bundlePath)
		return err == nil && bytes.Equal(b, u.Bundle)
	})
	h.wait("updater started", func() bool { return e.called("apply") })
	if !e.called("boot-check") {
		t.Fatal("boot-check was not run at start")
	}
	des, _ := os.ReadDir(e.spool)
	for _, de := range des {
		if strings.HasSuffix(de.Name(), ".part") {
			t.Fatalf("partial download left: %s", de.Name())
		}
	}

	// The updater switches current; the agent asks to be re-executed.
	e.installVersion(t, "1.1.0")
	var err error
	select {
	case err = <-r.done:
		r.done <- err
	case <-time.After(15 * time.Second):
		t.Fatal("agent did not stop for re-execution")
	}
	var re *update.ReexecError
	if !errors.As(err, &re) {
		t.Fatalf("Run returned %v", err)
	}
	want := filepath.Join(e.install, "versions", "1.1.0", updater.AgentName)
	if re.Path != want || re.Version != "1.1.0" {
		t.Fatalf("re-exec %s (%s), want %s", re.Path, re.Version, want)
	}
}

func TestUpdateNeverDowngrades(t *testing.T) {
	tr := signtest.Install(t)
	for _, v := range []string{"0.9.0", "1.0.0"} {
		t.Run(v, func(t *testing.T) {
			h := newHarness(t, fakeserver.Options{})
			if err := h.enroll(nil); err != nil {
				t.Fatal(err)
			}
			e := newUpdateEnv(t, "1.0.0")
			h.srv.SetUpdate(release(t, tr, v))
			h.start(func(o *Options) { e.options(o, "1.0.0") })
			h.wait("polls", func() bool { return len(h.srv.Polls()) >= 5 })
			if _, err := os.Stat(filepath.Join(e.spool, updater.BundleName(v))); !os.IsNotExist(err) {
				t.Fatal("bundle downloaded")
			}
			if e.called("apply") {
				t.Fatal("updater started")
			}
		})
	}
}

func TestUpdateRejectsUnsignedManifest(t *testing.T) {
	signtest.Install(t)
	other := signtest.NewTrust(t)
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	e := newUpdateEnv(t, "1.0.0")
	h.srv.SetUpdate(release(t, other, "1.1.0"))
	h.start(func(o *Options) { e.options(o, "1.0.0") })
	h.wait("polls", func() bool { return len(h.srv.Polls()) >= 5 })
	if _, err := os.Stat(filepath.Join(e.spool, updater.BundleName("1.1.0"))); !os.IsNotExist(err) {
		t.Fatal("bundle of an unverifiable release downloaded")
	}
}

func TestUpdateConfirmAfterPoll(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	e := newUpdateEnv(t, "1.1.0")
	st := updater.State{
		SchemaVersion: updater.StateSchemaVersion,
		Current:       "1.1.0",
		Previous:      "1.0.0",
		Pending:       &updater.Pending{Version: "1.1.0", Since: time.Now().Add(-time.Minute), Attempts: 1},
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.install, "state.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	h.start(func(o *Options) { e.options(o, "1.1.0") })
	confirm := filepath.Join(e.spool, updater.ConfirmName("1.1.0"))
	h.wait("confirmation written", func() bool { _, err := os.Stat(confirm); return err == nil })
	h.wait("updater started", func() bool { return e.called("apply") })
	if p := h.srv.Polls()[0]; p.Update.State != dto.UpdateStatePending || p.Update.PreviousVersion == nil || *p.Update.PreviousVersion != "1.0.0" {
		t.Fatalf("update status = %+v", p.Update)
	}
}

// A pending version that runs but is never confirmed (the server cannot be
// reached) asks the updater for a rollback after the pending timeout,
// without waiting for a restart and its boot check.
func TestUpdatePendingTimeoutRequestsRollback(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	e := newUpdateEnv(t, "1.1.0")
	st := updater.State{
		SchemaVersion: updater.StateSchemaVersion,
		Current:       "1.1.0",
		Previous:      "1.0.0",
		Pending:       &updater.Pending{Version: "1.1.0", Since: time.Now().Add(-time.Hour), Attempts: 1},
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.install, "state.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	h.srv.SetPollFail(true)
	h.start(func(o *Options) {
		e.options(o, "1.1.0")
		o.UpdatePendingTimeout = 30 * time.Minute
	})
	rollback := filepath.Join(e.spool, updater.RollbackName)
	h.wait("rollback requested", func() bool { _, err := os.Stat(rollback); return err == nil })
	h.wait("updater started", func() bool { return e.called("apply") })
	if _, err := os.Stat(filepath.Join(e.spool, updater.ConfirmName("1.1.0"))); err == nil {
		t.Fatal("unconfirmed version was confirmed")
	}
}

func TestUpdateSystemdRunsNoUpdater(t *testing.T) {
	tr := signtest.Install(t)
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	e := newUpdateEnv(t, "1.0.0")
	h.srv.SetUpdate(release(t, tr, "1.1.0"))
	h.start(func(o *Options) {
		e.options(o, "1.0.0")
		o.Systemd = true
	})
	h.wait("bundle in the spool", func() bool {
		_, err := os.Stat(filepath.Join(e.spool, updater.BundleName("1.1.0")))
		return err == nil
	})
	time.Sleep(100 * time.Millisecond)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.calls) != 0 {
		t.Fatalf("updater run with systemd: %v", e.calls)
	}
}

func TestDeriveInstallDir(t *testing.T) {
	cases := map[string]string{
		"/opt/bomcensus/versions/1.2.3/bomcensus-agent":  "/opt/bomcensus",
		"/usr/local/bin/bomcensus-agent":                 "",
		"/opt/bomcensus/versions/latest/bomcensus-agent": "",
	}
	for exe, want := range cases {
		got, ok := update.DeriveInstallDir(exe)
		if got != want || ok != (want != "") {
			t.Errorf("%s: got %q %v, want %q", exe, got, ok, want)
		}
	}
}
