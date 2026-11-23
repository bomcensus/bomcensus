// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/report"
)

// serveHostReport answers every connection on a new socket with a report
// whose host section names hostname, and records the requests.
func serveHostReport(t *testing.T, hostname string) (string, <-chan []byte) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "probe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var out bytes.Buffer
	err = report.Encode(&out, &report.Report{
		SchemaVersion: report.SchemaVersion,
		ProbeVersion:  "test",
		Host: &report.HostSection{
			SectionMeta: report.SectionMeta{Coverage: report.CoverageFull},
			Hostname:    hostname, MachineID: "0123456789abcdef0123456789abcdef", Arch: "x86_64",
			OS: report.OS{Family: "linux", ID: "ubuntu", VersionID: "24.04"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reqs := make(chan []byte, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			reqs <- b
			_, _ = c.Write(out.Bytes())
			c.Close()
		}
	}()
	return sock, reqs
}

func TestEnrollHostFactsFromProbe(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	sock, reqs := serveHostReport(t, "node-from-probe")
	if err := h.enroll(func(o *EnrollOptions) { o.ProbeSocket = sock }); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-reqs:
		if !strings.Contains(string(b), `"sections":["host"]`) {
			t.Errorf("probe request %s", b)
		}
	default:
		t.Fatal("the probe was not asked")
	}
	found := false
	for _, b := range h.srv.Bodies() {
		if bytes.Contains(b, []byte(`"hostname":"node-from-probe"`)) {
			found = true
		}
	}
	if !found {
		t.Error("the enrollment request does not carry the probe's host facts")
	}
}

func TestEnrollProbeSocketMissing(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	err := h.enroll(func(o *EnrollOptions) {
		o.ProbeSocket = filepath.Join(t.TempDir(), "absent.sock")
		o.ProbeWait = 100 * time.Millisecond
	})
	if err == nil || !strings.Contains(err.Error(), "host facts from the probe") {
		t.Fatalf("enroll without the probe: %v", err)
	}
	if len(h.srv.Agents()) != 0 {
		t.Error("enrolled without host facts")
	}
}

// An approved enrollment needs no host facts, so a missing probe must not
// hold up the init container on later starts.
func TestEnrollApprovedSkipsProbe(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &state.Enrollment{Kind: string(core.KindAgent), ServerURL: "https://server.invalid:8443", ServerName: "server.invalid",
		ConnectMode: core.ModeConnect, TLSMode: "pinned", AgentID: "01a1fc83-4a09-77b9-a499-ef0449ae1388",
		Status: state.StatusApproved, EnrolledAt: time.Now()}
	e.SetPin([32]byte{1})
	if err := st.SaveEnrollment(e); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	start := time.Now()
	code := Main([]string{"enroll", "--if-not-enrolled", "--state-dir", dir, "--probe-socket", filepath.Join(dir, "absent.sock")}, io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v: the probe was waited for", d)
	}
}

func TestInitStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	owner := []string{"init-state", "--dir", dir, "--owner", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())}
	if code := Main(owner, io.Discard, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %v, want 0700", fi.Mode().Perm())
	}
	// A later start must not need read access to the directory: as root
	// without CAP_DAC_READ_SEARCH it is no more readable than this one.
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	if err := InitStateDir(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("directory without permissions: %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("after a second run: %v, %v", fi.Mode(), err)
	}

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := InitStateDir(link, os.Getuid(), os.Getgid()); err == nil {
		t.Error("symbolic link accepted")
	}
	for _, args := range [][]string{
		{"init-state", "--dir", dir},
		{"init-state", "--dir", dir, "--owner", "1"},
		{"init-state", "--dir", dir, "--owner", "a:b"},
	} {
		if code := Main(args, io.Discard, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
