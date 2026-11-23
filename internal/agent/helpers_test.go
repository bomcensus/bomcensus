// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
)

var (
	probeDir string
	probeBin string
	probeErr error
	probeMu  sync.Mutex
)

func TestMain(m *testing.M) {
	code := m.Run()
	if probeDir != "" {
		os.RemoveAll(probeDir)
	}
	os.Exit(code)
}

// fakeProbe builds testdata/fakeprobe once per test binary.
func fakeProbe(t *testing.T) string {
	t.Helper()
	probeMu.Lock()
	defer probeMu.Unlock()
	if probeBin == "" && probeErr == nil {
		goBin, err := exec.LookPath("go")
		if err != nil {
			t.Skip("go toolchain not available")
		}
		probeDir, probeErr = os.MkdirTemp("", "bomcensus-fakeprobe-")
		if probeErr == nil {
			out := filepath.Join(probeDir, "bomcensus-probe")
			if runtime.GOOS == "windows" {
				out += ".exe"
			}
			cmd := exec.Command(goBin, "build", "-o", out, "./testdata/fakeprobe")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if b, err := cmd.CombinedOutput(); err != nil {
				probeErr = fmt.Errorf("build fake probe: %w\n%s", err, b)
			} else {
				probeBin = out
			}
		}
	}
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	return probeBin
}

// syncBuffer collects log output from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t        *testing.T
	srv      *fakeserver.Server
	stateDir string
	logs     *syncBuffer
	log      *slog.Logger
	reqFile  string
	variant  string
	agents   []*running
}

func newHarness(t *testing.T, opts fakeserver.Options) *harness {
	t.Helper()
	srv := fakeserver.New(t, opts)
	srv.Start()
	dir := t.TempDir()
	logs := &syncBuffer{}
	h := &harness{
		t:        t,
		srv:      srv,
		stateDir: filepath.Join(dir, "state"),
		logs:     logs,
		log:      slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		reqFile:  filepath.Join(dir, "probe-requests"),
		variant:  filepath.Join(dir, "probe-variant"),
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent log:\n%s", logs.String())
		}
	})
	return h
}

func testRuntime() core.Options {
	return core.Options{
		MinPollInterval:    20 * time.Millisecond,
		MaxBackoff:         200 * time.Millisecond,
		PendingInterval:    50 * time.Millisecond,
		SpoolRetryInterval: 100 * time.Millisecond,
	}
}

func (h *harness) enrollOptions() EnrollOptions {
	return EnrollOptions{
		StateDir:  h.stateDir,
		ServerURL: h.srv.URL,
		Token:     h.srv.Token.String(),
		Version:   "1.0.0",
		Logger:    h.log,
		Runtime:   testRuntime(),
	}
}

func (h *harness) enroll(mut func(*EnrollOptions)) error {
	h.t.Helper()
	o := h.enrollOptions()
	if mut != nil {
		mut(&o)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return Enroll(ctx, o)
}

func (h *harness) runOptions() Options {
	return Options{
		StateDir:       h.stateDir,
		DisableUpdates: true,
		ProbePath:      fakeProbe(h.t),
		ProbeSocket:    filepath.Join(h.t.TempDir(), "absent.sock"),
		ProbeEnv:       []string{"FAKEPROBE_REQUESTS=" + h.reqFile, "FAKEPROBE_VARIANT_FILE=" + h.variant},
		Version:        "1.0.0",
		Logger:         h.log,
		Runtime:        testRuntime(),
	}
}

// running is an agent started with start.
type running struct {
	cancel context.CancelFunc
	done   chan error
}

func (h *harness) start(mut func(*Options)) *running {
	h.t.Helper()
	o := h.runOptions()
	if mut != nil {
		mut(&o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- Run(ctx, o) }()
	h.t.Cleanup(func() { r.stop() })
	h.agents = append(h.agents, r)
	return r
}

// stopAll stops every agent started by start.
func (h *harness) stopAll() {
	h.t.Helper()
	for _, r := range h.agents {
		if err := r.stop(); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (r *running) stop() error {
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(15 * time.Second):
		return fmt.Errorf("agent did not stop")
	}
}

func (h *harness) wait(what string, cond func() bool) {
	h.t.Helper()
	if err := fakeserver.Wait(15*time.Second, cond); err != nil {
		h.t.Fatalf("%s: %v", what, err)
	}
}
