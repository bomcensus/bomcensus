// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package integrity

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// fakeRoot is a dpkg system with packages p1..pN, each owning
// /usr/bin/p<i> and /usr/share/p<i>/data, and p1 a conffile.
type fakeRoot struct {
	t    *testing.T
	root string
	n    int
}

func newFakeRoot(t *testing.T, n int) *fakeRoot {
	t.Helper()
	r := &fakeRoot{t: t, root: t.TempDir(), n: n}
	r.writeStatus(map[int]string{})
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("p%d", i)
		files := []string{"usr/bin/" + name, "usr/share/" + name + "/data"}
		var list, sums strings.Builder
		for _, f := range files {
			content := "content of " + f
			r.write(f, content)
			list.WriteString("/" + f + "\n")
			sums.WriteString(md5hex(content) + "  " + f + "\n")
		}
		if i == 1 {
			r.write("etc/p1.conf", "original")
			list.WriteString("/etc/p1.conf\n")
			sums.WriteString(md5hex("original") + "  etc/p1.conf\n")
		}
		r.write("var/lib/dpkg/info/"+name+".list", list.String())
		r.write("var/lib/dpkg/info/"+name+".md5sums", sums.String())
	}
	return r
}

func (r *fakeRoot) write(rel, content string) {
	r.t.Helper()
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// writeStatus writes the status file; versions overrides "1.0".
func (r *fakeRoot) writeStatus(versions map[int]string) {
	var b strings.Builder
	for i := 1; i <= r.n; i++ {
		v := versions[i]
		if v == "" {
			v = "1.0"
		}
		fmt.Fprintf(&b, "Package: p%d\nStatus: install ok installed\nArchitecture: all\nVersion: %s\n", i, v)
		if i == 1 {
			b.WriteString("Conffiles:\n /etc/p1.conf " + md5hex("original") + "\n")
		}
		b.WriteString("\n")
	}
	r.write("var/lib/dpkg/status", b.String())
}

func (r *fakeRoot) env() *collect.Env { return collect.NewEnv().WithRoot(r.root) }

func quiet() Options {
	return Options{HostBusy: func() bool { return false }, PackageManagerBusy: func() bool { return false }}
}

func run(t *testing.T, env *collect.Env, q report.IntegrityQuery, o Options) *report.IntegritySection {
	t.Helper()
	if q.PassID == "" {
		q.PassID = "pass-1"
	}
	if q.MaxReadMBps == 0 {
		q.MaxReadMBps = report.MaxIntegrityReadMBps
	}
	return Check(context.Background(), env, q, time.Now().Add(time.Minute), o)
}

func findingFor(sec *report.IntegritySection, p string) *report.IntegrityFinding {
	for i := range sec.Findings {
		if sec.Findings[i].Path == p {
			return &sec.Findings[i]
		}
	}
	return nil
}

func TestCleanSystem(t *testing.T) {
	r := newFakeRoot(t, 3)
	sec := run(t, r.env(), report.IntegrityQuery{}, quiet())
	if len(sec.Findings) != 0 {
		t.Fatalf("findings on a clean system: %+v", sec.Findings)
	}
	if !sec.PassDone || sec.Cursor != "" || sec.Coverage != report.CoverageFull {
		t.Errorf("done %v cursor %q coverage %s (%s)", sec.PassDone, sec.Cursor, sec.Coverage, sec.Reason)
	}
	if sec.Packages != 3 || sec.Checked != 6 || sec.Excluded != 1 {
		t.Errorf("packages %d checked %d excluded %d; want 3, 6, 1", sec.Packages, sec.Checked, sec.Excluded)
	}
	if sec.PassID != "pass-1" {
		t.Errorf("pass id %q", sec.PassID)
	}
}

func TestModifiedAndMissing(t *testing.T) {
	r := newFakeRoot(t, 3)
	r.write("usr/bin/p2", "malware")
	r.write("etc/p1.conf", "edited by the admin")
	if err := os.Remove(filepath.Join(r.root, "usr/share/p3/data")); err != nil {
		t.Fatal(err)
	}
	sec := run(t, r.env(), report.IntegrityQuery{}, quiet())
	if len(sec.Findings) != 2 {
		t.Fatalf("findings %+v", sec.Findings)
	}
	f := findingFor(sec, "/usr/bin/p2")
	if f == nil {
		t.Fatal("modified file not reported")
	}
	want := report.IntegrityFinding{PkgType: "deb", Package: "p2", Version: "1.0", Arch: "all", Path: "/usr/bin/p2",
		Status: report.IntegrityModified, Algo: "md5", Expected: md5hex("content of usr/bin/p2"),
		Actual: md5hex("malware"), ActualSHA256: sha256hex("malware"), Size: 7}
	got := *f
	if got.Mtime.IsZero() || got.Ctime.IsZero() {
		t.Error("times missing")
	}
	got.Mtime, got.Ctime = time.Time{}, time.Time{}
	if got != want {
		t.Errorf("modified:\n got %+v\nwant %+v", got, want)
	}
	if got.SHA256() != sha256hex("malware") {
		t.Errorf("SHA256() = %s", got.SHA256())
	}
	m := findingFor(sec, "/usr/share/p3/data")
	if m == nil || m.Status != report.IntegrityMissing || m.Actual != "" || m.SHA256() != "" {
		t.Errorf("missing: %+v", m)
	}
	if findingFor(sec, "/etc/p1.conf") != nil {
		t.Error("conffile reported")
	}
}

func TestExcludePaths(t *testing.T) {
	r := newFakeRoot(t, 3)
	r.write("usr/bin/p2", "changed")
	r.write("usr/share/p3/data", "changed")
	sec := run(t, r.env(), report.IntegrityQuery{ExcludePaths: []string{"/usr/bin/p2", "/usr/share/**/data"}}, quiet())
	if len(sec.Findings) != 0 {
		t.Errorf("excluded files reported: %+v", sec.Findings)
	}
	// p2's binary, three data files and p1's conffile.
	if sec.Excluded != 5 {
		t.Errorf("excluded %d, want 5", sec.Excluded)
	}
}

func TestSymlinkedFileIsFollowed(t *testing.T) {
	r := newFakeRoot(t, 1)
	// The file is replaced by a link to other content.
	r.write("opt/evil", "evil")
	p := filepath.Join(r.root, "usr/bin/p1")
	os.Remove(p)
	if err := os.Symlink("/opt/evil", p); err != nil {
		t.Fatal(err)
	}
	sec := run(t, r.env(), report.IntegrityQuery{}, quiet())
	f := findingFor(sec, "/usr/bin/p1")
	if f == nil || f.Actual != md5hex("evil") {
		t.Errorf("link to other content: %+v", f)
	}
}

// A file rewritten with its old mtime restored is detected although the
// cache knows the file: the ctime changed.
func TestCacheDoesNotHideRewrite(t *testing.T) {
	r := newFakeRoot(t, 2)
	env := r.env()
	first := run(t, env, report.IntegrityQuery{}, quiet())
	if len(first.Findings) != 0 {
		t.Fatal(first.Findings)
	}
	c := loadCache(first.Cache, time.Now())
	if len(c.entries) != 4 {
		t.Fatalf("cache has %d entries, want 4", len(c.entries))
	}
	p := filepath.Join(r.root, "usr/bin/p2")
	fi, _ := os.Stat(p)
	time.Sleep(10 * time.Millisecond)
	r.write("usr/bin/p2", "content of usr/bin/pX") // same size
	if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	second := run(t, env, report.IntegrityQuery{Cache: first.Cache}, quiet())
	if f := findingFor(second, "/usr/bin/p2"); f == nil || f.Actual != md5hex("content of usr/bin/pX") {
		t.Errorf("rewrite hidden by the cache: %+v", second.Findings)
	}
}

func TestCacheMalformed(t *testing.T) {
	for _, raw := range []string{``, `"garbage"`, `"i1:!!!"`, `{}`, `"i1:AAAA"`} {
		c := loadCache([]byte(raw), time.Now())
		if len(c.entries) != 0 {
			t.Errorf("%s: %d entries", raw, len(c.entries))
		}
	}
	c := loadCache(nil, time.Now())
	c.put(statKey{Dev: 1, Ino: 2, Size: 3}, "sha256", make([]byte, 32))
	c.put(statKey{Dev: 1, Ino: 3}, "md5", make([]byte, 5)) // wrong size
	back := loadCache(c.marshal(), time.Now())
	if len(back.entries) != 1 {
		t.Errorf("round trip kept %d entries", len(back.entries))
	}
	if _, ok := back.get(statKey{Dev: 1, Ino: 2, Size: 3}, "sha256"); !ok {
		t.Error("entry lost")
	}
	if _, ok := back.get(statKey{Dev: 1, Ino: 2, Size: 3}, "md5"); ok {
		t.Error("entry found under another algorithm")
	}
	old := loadCache(c.marshal(), time.Now().Add((cacheRetentionDays+2)*24*time.Hour))
	if len(old.entries) != 0 {
		t.Error("expired entries kept")
	}
}

// fakeClock advances by step on every reading.
type fakeClock struct {
	now  time.Time
	step time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.now = c.now.Add(c.step)
	return c.now
}

func TestChunksMatchOneRun(t *testing.T) {
	r := newFakeRoot(t, 12)
	r.write("usr/bin/p3", "x")
	r.write("usr/share/p9/data", "y")
	r.write("usr/bin/p12", "z")
	env := r.env()
	whole := run(t, env, report.IntegrityQuery{}, quiet())

	var got []string
	q := report.IntegrityQuery{PassID: "p", MaxReadMBps: report.MaxIntegrityReadMBps}
	chunks := 0
	for {
		chunks++
		if chunks > 50 {
			t.Fatal("pass does not finish")
		}
		clock := &fakeClock{now: time.Unix(1_800_000_000, 0), step: time.Second}
		o := quiet()
		o.Now = clock.Now
		sec := Check(context.Background(), env, q, clock.now.Add(12*time.Second), o)
		for _, f := range sec.Findings {
			got = append(got, f.Path)
		}
		if sec.PassDone {
			break
		}
		if sec.Cursor == q.Cursor {
			t.Fatalf("chunk %d made no progress", chunks)
		}
		q.Cursor, q.Cache = sec.Cursor, sec.Cache
	}
	if chunks < 2 {
		t.Fatalf("one chunk only; the deadline did not cut the pass")
	}
	var want []string
	for _, f := range whole.Findings {
		want = append(want, f.Path)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("chunked %v, whole %v", got, want)
	}
}

func TestPackageManagerBusy(t *testing.T) {
	r := newFakeRoot(t, 2)
	r.write("usr/bin/p2", "changed")
	o := quiet()
	o.PackageManagerBusy = func() bool { return true }
	sec := run(t, r.env(), report.IntegrityQuery{Cursor: "deb/p1/all/1.0"}, o)
	if sec.Coverage != report.CoverageNone || sec.PassDone || sec.Cursor != "deb/p1/all/1.0" || len(sec.Findings) != 0 || sec.Reason == "" {
		t.Errorf("busy: %+v", sec)
	}
}

// A package upgraded while it was read is not reported.
func TestUpgradeDuringCheckDropsFinding(t *testing.T) {
	r := newFakeRoot(t, 2)
	r.write("usr/bin/p2", "half written")
	o := quiet()
	o.HostBusy = func() bool {
		r.writeStatus(map[int]string{2: "1.1"})
		return false
	}
	sec := run(t, r.env(), report.IntegrityQuery{}, o)
	if len(sec.Findings) != 0 {
		t.Errorf("finding of an upgraded package kept: %+v", sec.Findings)
	}
}

func TestHostBusyPauses(t *testing.T) {
	r := newFakeRoot(t, 1)
	calls := 0
	slept := time.Duration(0)
	o := quiet()
	o.HostBusy = func() bool { calls++; return calls < 3 }
	o.Sleep = func(_ context.Context, d time.Duration) bool { slept += d; return true }
	sec := run(t, r.env(), report.IntegrityQuery{}, o)
	if !sec.PassDone || slept != 2*pressurePause {
		t.Errorf("done %v, slept %s", sec.PassDone, slept)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	var slept time.Duration
	l := newLimiter(1<<20, func() time.Time { return now },
		func(_ context.Context, d time.Duration) bool { slept += d; now = now.Add(d); return true })
	for range 10 {
		l.wait(context.Background(), 1<<20)
	}
	// 10 MiB at 1 MiB/s, minus the first second read without delay and the
	// burst allowance.
	if slept < 9*time.Second || slept > 10*time.Second {
		t.Errorf("slept %s for 10 MiB at 1 MiB/s", slept)
	}
}

func TestMatcher(t *testing.T) {
	m := newMatcher([]string{"/opt/app", "/usr/lib/python3/**/__pycache__/**", "/var/*.log", "relative"})
	for p, want := range map[string]bool{
		"/opt/app":                               true,
		"/opt/app/bin/x":                         true,
		"/opt/application":                       false,
		"/usr/lib/python3/a/b/__pycache__/x.pyc": true,
		"/usr/lib/python3/__pycache__/x.pyc":     true,
		"/usr/lib/python3/a/b/x.py":              false,
		"/var/app.log":                           true,
		"/var/log/app.log":                       false,
		"/proc/1/exe":                            true,
		"/relative":                              false,
	} {
		if got := m.match(p); got != want {
			t.Errorf("match(%s) = %v, want %v", p, got, want)
		}
	}
}
