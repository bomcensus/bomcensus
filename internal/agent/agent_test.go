// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/internal/fakeserver"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/report"
)

func loadState(t *testing.T, dir string) (*state.Enrollment, *state.Identity, *pki.TrustBundle) {
	t.Helper()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	enr, err := st.LoadEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	tb, err := st.LoadTrustBundle()
	if err != nil {
		t.Fatal(err)
	}
	return enr, id, tb
}

// assertNoSecret checks that neither the enrollment string nor its secret
// appear in the state directory, the logs or the request bodies.
func assertNoSecret(t *testing.T, h *harness) {
	t.Helper()
	tok := h.srv.Token
	needles := map[string][]byte{
		"token":         []byte(tok.String()),
		"secret b64url": []byte(base64.RawURLEncoding.EncodeToString(tok.Secret[:])),
		"secret b64":    []byte(base64.StdEncoding.EncodeToString(tok.Secret[:])),
		"secret hex":    []byte(hex.EncodeToString(tok.Secret[:])),
		"secret raw":    tok.Secret[:],
		"register key":  tok.PrivateKey(),
	}
	check := func(where string, data []byte) {
		for name, n := range needles {
			if bytes.Contains(data, n) {
				t.Errorf("%s contains the %s", where, name)
			}
		}
	}
	// The agent may still be running and replacing files.
	err := filepath.WalkDir(h.stateDir, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		check(p, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check("log", []byte(h.logs.String()))
	for _, b := range h.srv.Bodies() {
		check("request body", b)
	}
}

func TestEnrollApproved(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	enr, id, tb := loadState(t, h.stateDir)
	if enr.Status != state.StatusApproved || enr.AgentID != "agent-1" || enr.ConnectMode != "connect" || enr.TLSMode != "pinned" {
		t.Fatalf("enrollment = %+v", enr)
	}
	if got, err := enr.PinHash(); err != nil || got != h.srv.Pin {
		t.Fatalf("pin = %x, %v", got, err)
	}
	if id.Cert == nil {
		t.Fatal("no certificate")
	}
	if got, err := pki.AgentIDFromCert(id.Cert); err != nil || got != "agent-1" {
		t.Fatalf("certificate agent id = %q, %v", got, err)
	}
	if tb == nil || tb.Version != 1 || !tb.HasAnchor(h.srv.Pin) {
		t.Fatalf("trust bundle = %+v", tb)
	}
	agents := h.srv.Agents()
	if len(agents) != 1 || !agents[0].Pub.Equal(id.Key.Public()) {
		t.Fatal("server has another identity key")
	}
	fi, err := os.Stat(h.stateDir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %v, %v", fi.Mode(), err)
	}
	fi, err = os.Stat(filepath.Join(h.stateDir, "identity.pem"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %v, %v", fi.Mode(), err)
	}
	assertNoSecret(t, h)

	if err := h.enroll(nil); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("second enrollment: %v", err)
	}
}

func TestEnrollRejectsWrongPin(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	other := fakeserver.New(t, fakeserver.Options{})
	err := h.enroll(func(o *EnrollOptions) { o.Token = other.Token.String() })
	if err == nil {
		t.Fatal("enrollment with a token of another server succeeded")
	}
	if len(h.srv.Agents()) != 0 {
		t.Fatal("server enrolled an agent")
	}
}

func TestEnrollPendingThenApproved(t *testing.T) {
	h := newHarness(t, fakeserver.Options{ManualApproval: true})
	done := make(chan error, 1)
	go func() { done <- h.enroll(nil) }()
	h.wait("pending enrollment polled", func() bool { return h.srv.EnrollResultRequests() >= 2 })
	enr, id, tb := loadState2(t, h.stateDir)
	if enr.Status != state.StatusPending || id.Cert != nil || tb != nil {
		t.Fatalf("pending state = %+v cert=%v bundle=%v", enr, id.Cert != nil, tb != nil)
	}
	h.srv.Approve("agent-1")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("enrollment did not finish")
	}
	enr, id, tb = loadState(t, h.stateDir)
	if enr.Status != state.StatusApproved || id.Cert == nil || tb == nil {
		t.Fatalf("approved state = %+v", enr)
	}
	assertNoSecret(t, h)
}

// loadState2 reads the state while another goroutine holds the lock, from
// a copy of the files.
func loadState2(t *testing.T, dir string) (*state.Enrollment, *state.Identity, *pki.TrustBundle) {
	t.Helper()
	tmp := t.TempDir()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if de.IsDir() || de.Name() == "lock" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, de.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return loadState(t, tmp)
}

func TestPendingResumedByRun(t *testing.T) {
	h := newHarness(t, fakeserver.Options{ManualApproval: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		o := h.enrollOptions()
		done <- Enroll(ctx, o)
	}()
	h.wait("pending", func() bool { return h.srv.EnrollResultRequests() >= 1 })
	cancel()
	<-done

	h.start(nil)
	h.wait("run polls enroll/result", func() bool { return h.srv.EnrollResultRequests() >= 3 })
	if len(h.srv.Reports()) != 0 || len(h.srv.Polls()) != 0 {
		t.Fatal("pending agent polled or uploaded")
	}
	h.srv.Approve("agent-1")
	h.wait("report after approval", func() bool { return len(h.srv.Reports()) >= 1 })
}

func sectionsOf(r *report.Report) map[string]*report.SectionMeta {
	out := map[string]*report.SectionMeta{}
	if r.Host != nil {
		out[report.SectionHost] = &r.Host.SectionMeta
	}
	if r.Packages != nil {
		out[report.SectionPackages] = &r.Packages.SectionMeta
	}
	if r.Artifacts != nil {
		out[report.SectionArtifacts] = &r.Artifacts.SectionMeta
	}
	if r.Processes != nil {
		out[report.SectionProcesses] = &r.Processes.SectionMeta
	}
	if r.Containers != nil {
		out[report.SectionContainers] = &r.Containers.SectionMeta
	}
	return out
}

func lastPoll(h *harness) agentapi.PollRequest {
	p := h.srv.Polls()
	if len(p) == 0 {
		return agentapi.PollRequest{}
	}
	return p[len(p)-1]
}

func TestCollectUploadAndDirectives(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	h.start(nil)
	h.wait("first report", func() bool { return len(h.srv.Reports()) >= 1 })
	first := h.srv.Reports()[0]
	secs := sectionsOf(first)
	if len(secs) != len(report.AllSections) {
		t.Fatalf("first report has sections %v", secs)
	}
	for name, m := range secs {
		if m.Unchanged || m.Digest == "" {
			t.Fatalf("section %s: %+v", name, m)
		}
	}
	if first.Subject == nil || first.Subject.Kind != report.SubjectSelf || len(first.Cache) != 0 {
		t.Fatalf("subject %+v, cache %d bytes", first.Subject, len(first.Cache))
	}
	if c := first.Containers.Containers[0]; c.InitPID != 0 || c.UpperDir != "" {
		t.Fatal("probe-internal container hints were uploaded")
	}
	h.wait("digests reported", func() bool {
		return lastPoll(h).SectionDigests[report.SectionPackages] == first.Packages.Digest
	})

	// Unchanged sections are not re-sent; changed ones are.
	if err := os.WriteFile(h.variant, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.srv.Queue(map[string]any{"type": "collect", "id": "d-collect", "sections": []string{}})
	h.srv.Queue(map[string]any{"type": "frobnicate", "id": "d-unknown"})
	h.wait("second report", func() bool { return len(h.srv.Reports()) >= 2 })
	second := h.srv.Reports()[1]
	for name, m := range sectionsOf(second) {
		changed := name == report.SectionPackages
		if m.Unchanged == changed {
			t.Errorf("section %s: unchanged=%v", name, m.Unchanged)
		}
	}
	if second.Host.Hostname != "" || len(second.Processes.Processes) != 0 {
		t.Error("unchanged sections carry items")
	}
	if len(second.Packages.Packages) != 2 {
		t.Error("changed section has no items")
	}
	h.wait("directives acknowledged", func() bool { return h.srv.Acked("d-collect") && h.srv.Acked("d-unknown") })

	// A full collection of one section ignores the known digest.
	h.srv.Queue(map[string]any{"type": "collect", "id": "d-full", "sections": []string{"host"}, "full": true})
	h.wait("third report", func() bool { return len(h.srv.Reports()) >= 3 })
	third := h.srv.Reports()[2]
	if s := sectionsOf(third); len(s) != 1 || third.Host == nil || third.Host.Unchanged || third.Host.Hostname == "" {
		t.Fatalf("full host collection: %+v", s)
	}

	// The probe cache is kept and passed back.
	reqs, err := os.ReadFile(h.reqFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(reqs)), "\n")
	if len(lines) < 3 || !strings.Contains(lines[1], `"cache":{"runs":1}`) || !strings.Contains(lines[2], `"cache":{"runs":2}`) {
		t.Fatalf("probe requests:\n%s", reqs)
	}
	if strings.Contains(lines[2], "known_digests\":{\"host\"") {
		t.Fatal("full collection sent known digests")
	}
	if p := lastPoll(h); p.Privilege.Level != agentapi.NonRoot || p.Version != "1.0.0" || p.ConnectMode != agentapi.Connect || p.TlsMode != agentapi.Pinned {
		t.Fatalf("poll status = %+v", p)
	}
	if p := lastPoll(h); p.ObservedServerCert == nil || p.ObservedServerCert.Sha256 != hexFingerprint(h.srv.Leaf) {
		t.Fatalf("observed certificate = %+v", p.ObservedServerCert)
	}
}

func TestSpoolAndOrderedRetry(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	h.srv.SetUploadFail(true)
	r := h.start(nil)
	spool := filepath.Join(h.stateDir, "spool")
	countSpool := func() int {
		des, _ := os.ReadDir(spool)
		n := 0
		for _, de := range des {
			if strings.HasSuffix(de.Name(), ".report") {
				n++
			}
		}
		return n
	}
	h.wait("first report spooled", func() bool { return countSpool() == 1 })
	h.srv.Queue(map[string]any{"type": "collect", "id": "c2", "sections": []string{"host", "packages"}})
	h.wait("second report spooled", func() bool { return countSpool() == 2 })
	if d := lastPoll(h).SectionDigests; len(d) != 0 {
		t.Fatalf("digests updated before upload: %v", d)
	}
	// Spooled reports survive a restart.
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	h.srv.SetUploadFail(false)
	h.start(nil)
	h.wait("spooled reports uploaded", func() bool { return countSpool() == 0 && len(h.srv.Reports()) >= 2 })
	h.wait("second report uploaded", func() bool {
		reps := h.srv.Reports()
		return reps[len(reps)-1].ProbeVersion == "fake-2"
	})
	// Delivery is at least once: an upload cancelled by the shutdown can
	// still reach the server, and the report is then sent again. The order
	// must hold regardless.
	var order []string
	for _, r := range h.srv.Reports() {
		if len(order) == 0 || order[len(order)-1] != r.ProbeVersion {
			order = append(order, r.ProbeVersion)
		}
	}
	if strings.Join(order, ",") != "fake-1,fake-2" {
		t.Fatalf("upload order: %v", order)
	}
	h.wait("digests after upload", func() bool { return len(lastPoll(h).SectionDigests) == len(report.AllSections) })
}

func TestCounterPersistsAcrossRestart(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	r := h.start(nil)
	h.wait("polls", func() bool { return len(h.srv.Polls()) >= 5 })
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	before := h.srv.CounterOf("agent-1")
	h.start(nil)
	n := len(h.srv.Polls())
	h.wait("polls after restart", func() bool { return len(h.srv.Polls()) >= n+5 })
	cs := h.srv.Agents()[0].Counters
	for i := 1; i < len(cs); i++ {
		if cs[i] <= cs[i-1] {
			t.Fatalf("counters not increasing: %v", cs)
		}
	}
	if h.srv.CounterOf("agent-1") <= before {
		t.Fatal("no progress after restart")
	}
	if strings.Contains(h.logs.String(), "counter_replayed") {
		t.Fatal("agent reused a counter")
	}
}

func TestCounterRecoversFromServer(t *testing.T) {
	h := newHarness(t, fakeserver.Options{})
	if err := h.enroll(nil); err != nil {
		t.Fatal(err)
	}
	r := h.start(nil)
	h.wait("polls", func() bool { return len(h.srv.Polls()) >= 3 })
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	// Simulate a state restore: the counter file is lost.
	if err := os.Remove(filepath.Join(h.stateDir, "counter")); err != nil {
		t.Fatal(err)
	}
	n := len(h.srv.Polls())
	h.start(nil)
	h.wait("polls after counter loss", func() bool { return len(h.srv.Polls()) >= n+3 })
}

func hexFingerprint(c *x509.Certificate) string {
	fp := pki.Fingerprint(c)
	return hex.EncodeToString(fp[:])
}
