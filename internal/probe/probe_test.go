// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect/artifact"
	"github.com/bomcensus/bomcensus/internal/report"
)

// hostRequest asks for the sections that are quick on a real host.
func hostRequest() report.Request {
	return report.Request{
		Sections: []string{report.SectionHost, report.SectionPackages, report.SectionProcesses},
		Policy:   report.DefaultPolicy(),
	}
}

func TestRunRealHost(t *testing.T) {
	rep, err := Run(context.Background(), hostRequest(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host == nil || rep.Packages == nil || rep.Processes == nil {
		t.Fatalf("missing sections: %+v", rep)
	}
	if rep.Artifacts != nil || rep.Containers != nil {
		t.Error("sections that were not requested are present")
	}
	if rep.Host.Hostname == "" || rep.Host.Kernel == "" {
		t.Errorf("host = %+v", rep.Host)
	}
	if rep.Privilege.Level == "" || rep.Privilege.UID != os.Geteuid() {
		t.Errorf("privilege = %+v", rep.Privilege)
	}
	if os.Geteuid() != 0 && rep.Privilege.Level == report.PrivilegePrivileged && len(rep.Privilege.Capabilities) == 0 {
		t.Errorf("unprivileged user reported as privileged")
	}
	for _, p := range rep.Processes.Processes {
		if p.PID == os.Getpid() {
			t.Error("the probe's own process is reported")
		}
	}
	if self, err := os.Readlink("/proc/self/ns/mnt"); err == nil && rep.Processes.ProbeMountNS == 0 {
		t.Errorf("probe mount namespace not reported, own is %s", self)
	}
	for name, m := range sectionMetas(rep) {
		if m.Digest == "" || m.CollectedAt.IsZero() {
			t.Errorf("%s: digest %q collected %v", name, m.Digest, m.CollectedAt)
		}
		t.Logf("%s: coverage %s %s", name, m.Coverage, m.Reason)
	}
	if len(rep.Cache) == 0 {
		t.Error("no cache returned")
	}
}

func TestRunRealHostDigests(t *testing.T) {
	first, err := Run(context.Background(), hostRequest(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	req := hostRequest()
	req.Cache = first.Cache
	second, err := Run(context.Background(), req, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d1, d2 := digests(first), digests(second)
	for _, name := range []string{report.SectionHost, report.SectionPackages} {
		if d1[name] != d2[name] {
			t.Errorf("%s digest changed: %s → %s", name, d1[name], d2[name])
		}
	}
	if d1[report.SectionProcesses] != d2[report.SectionProcesses] {
		// Other processes may come and go between the runs.
		t.Logf("process digest changed between runs")
	}

	req = hostRequest()
	req.KnownDigests = d2
	third, err := Run(context.Background(), req, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*report.SectionMeta{&third.Host.SectionMeta, &third.Packages.SectionMeta} {
		if !s.Unchanged {
			t.Errorf("section with known digest %s not marked unchanged", s.Digest)
		}
	}
	if len(third.Packages.Packages) != 0 || third.Host.Hostname != "" {
		t.Error("unchanged sections carry items")
	}
}

func TestRunTimeLimit(t *testing.T) {
	req := report.Request{
		Sections: []string{report.SectionProcesses, report.SectionArtifacts},
		Policy:   report.DefaultPolicy(),
	}
	req.Policy.MaxRuntimeSeconds = 1
	start := time.Now()
	rep, err := Run(context.Background(), req, Options{Grace: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	if took > 10*time.Second {
		t.Errorf("run took %s with a 1 s limit", took)
	}
	p, a := rep.Processes, rep.Artifacts
	if p == nil || a == nil {
		t.Fatal("sections missing after the time limit")
	}
	if p.Coverage == report.CoverageFull && p.DurationMs >= 1000 {
		t.Errorf("processes ran %d ms past the limit and are reported complete", p.DurationMs)
	}
	if a.Coverage == report.CoverageFull {
		t.Errorf("artifacts coverage full after a 1 s run over the whole host")
	}
	t.Logf("after %s: processes %s (%s, %d items); artifacts %s (%s, %d items)", took.Round(time.Millisecond),
		p.Coverage, p.Reason, len(p.Processes), a.Coverage, a.Reason, len(a.Artifacts))
}

func TestRunHardStop(t *testing.T) {
	// A section that ignores the deadline is abandoned after the grace
	// period and reported without coverage.
	r := &runner{hardStop: time.Now().Add(50 * time.Millisecond), limit: time.Second, ctx: context.Background()}
	release := make(chan struct{})
	defer close(release)
	if r.bounded(func() { <-release }) {
		t.Fatal("blocked section not abandoned")
	}
	if m := r.skipped(true); m.Coverage != report.CoverageNone || !strings.Contains(m.Reason, "did not finish") {
		t.Errorf("meta = %+v", m)
	}
}

func TestOpenJars(t *testing.T) {
	jar := t.TempDir() + "/held.jar"
	if err := os.WriteFile(jar, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(jar)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Skip(err)
	}
	if !isJVM("/usr/lib/jvm/x/bin/java") || isJVM(self) {
		t.Fatal("isJVM")
	}
	held := openJar{path: jar, fd: int(f.Fd())}
	if got := processJars("/proc/self/fd", 10); !slices.Contains(got, held) {
		t.Errorf("open jar not found: %v", got)
	}
	// A deleted archive is still listed, by its path, with the descriptor
	// that reads it.
	if err := os.Remove(jar); err != nil {
		t.Fatal(err)
	}
	if got := processJars("/proc/self/fd", 10); !slices.Contains(got, held) {
		t.Errorf("deleted open jar not found: %v", got)
	}
	ix := openFileIndex{}
	k, _ := rootKeyOf("/proc/self/root")
	ix[k] = map[string][]artifact.OpenRef{jar: {{PID: os.Getpid(), FD: held.fd}}}
	if m := ix.forRoot("/"); len(m[jar]) != 1 {
		t.Errorf("forRoot(/) = %v", m)
	}
}
