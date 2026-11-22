// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// probeBinary builds the command once, statically, as it is shipped.
func probeBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bomcensus-probe-test-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "bomcensus-probe")
		if runtime.GOOS == "windows" {
			binPath += ".exe"
		}
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags",
			"-s -w -X github.com/bomcensus/bomcensus/internal/version.Version=9.9.9-test", "-o", binPath, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = errors.New(err.Error() + ": " + string(out))
		}
	})
	if buildErr != nil {
		t.Fatalf("build: %v", buildErr)
	}
	return binPath
}

func runProbe(t *testing.T, stdin string, args ...string) (stdout, stderr []byte, code int) {
	t.Helper()
	cmd := exec.Command(probeBinary(t), args...)
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatal(err)
	}
	return o.Bytes(), e.Bytes(), code
}

func TestVersion(t *testing.T) {
	out, _, code := runProbe(t, "", "version")
	if code != 0 || strings.TrimSpace(string(out)) != "9.9.9-test" {
		t.Errorf("version: %d %q", code, out)
	}
}

func TestCollect(t *testing.T) {
	req := `{"sections":["host","packages","processes"],"known_digests":{"host":"x"},"policy":{"exec_version":true,"collect_cmdline":true}}`
	for _, args := range [][]string{{"collect"}, {"collect", "--no-sandbox", "--log-level", "debug"}} {
		out, stderr, code := runProbe(t, req, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d\n%s", args, code, stderr)
		}
		rep, err := report.Decode(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("%v: decode: %v\n%s", args, err, stderr)
		}
		if rep.ProbeVersion != "9.9.9-test" || rep.Host == nil || rep.Packages == nil || rep.Processes == nil || rep.Artifacts != nil {
			t.Errorf("%v: report = %+v", args, rep)
		}
		if rep.Host.Unchanged || rep.Host.Hostname == "" {
			t.Errorf("%v: host = %+v", args, rep.Host)
		}
		if len(rep.Cache) == 0 {
			t.Errorf("%v: no cache", args)
		}
		sandboxed := bytes.Contains(stderr, []byte(sandboxLogMarker))
		if (args[len(args)-1] == "collect") != sandboxed {
			t.Errorf("%v: sandbox log mismatch:\n%s", args, stderr)
		}
		t.Logf("%v: %d bytes, %d processes, %d packages", args, len(out), len(rep.Processes.Processes), len(rep.Packages.Packages))
	}
}

func TestCollectBadRequest(t *testing.T) {
	out, stderr, code := runProbe(t, "{not json", "collect")
	if code != 1 || len(out) != 0 {
		t.Errorf("exit %d, %d bytes on stdout\n%s", code, len(out), stderr)
	}
	if _, _, code := runProbe(t, "", "collect", "--log-level", "loud"); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
	if _, _, code := runProbe(t, "", "frobnicate"); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
}
