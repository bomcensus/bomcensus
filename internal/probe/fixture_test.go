// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	imageA   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imageB   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestA  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	ct1ID    = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	ct2ID    = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"
	ct3ID    = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	ct4ID    = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4"
	ct1PID   = 4242
	ct2PID   = 4243
	ct3PID   = 4244
	upperDir = "/var/lib/docker/overlay2/m1/diff"
)

// testFixture is a fake host: a root with a dpkg database, jars, a Go
// binary and Docker state, and a proc tree whose container init processes
// point at fake container roots.
type testFixture struct {
	root, proc string
	fooJar     string // real path of the package-owned jar
}

func write(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func jarBytes(t *testing.T, group, artifactID, ver string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/maven/" + group + "/" + artifactID + "/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("groupId=" + group + "\nartifactId=" + artifactID + "\nversion=" + ver + "\n"))
	w, _ = zw.Create("META-INF/MANIFEST.MF")
	w.Write([]byte("Manifest-Version: 1.0\r\n\r\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dpkgStatus(pkgs ...string) []byte {
	var b strings.Builder
	for _, p := range pkgs {
		name, ver, _ := strings.Cut(p, "=")
		b.WriteString("Package: " + name + "\nStatus: install ok installed\nArchitecture: amd64\nVersion: " + ver + "\nMaintainer: Test <t@example.com>\n\n")
	}
	return []byte(b.String())
}

func osRelease(id, ver string) []byte {
	return []byte("ID=" + id + "\nVERSION_ID=\"" + ver + "\"\nPRETTY_NAME=\"" + id + " " + ver + "\"\n")
}

func dockerConfig(id, name, image, ref string, running bool, pid int, started string) []byte {
	cfg := map[string]any{
		"ID": id, "Name": "/" + name, "Image": image, "Driver": "overlay2",
		"State":  map[string]any{"Running": running, "Pid": pid, "StartedAt": started},
		"Config": map[string]any{"Image": ref},
	}
	b, _ := json.Marshal(cfg)
	return b
}

func newFixture(t *testing.T, withGo bool) *testFixture {
	t.Helper()
	dir := t.TempDir()
	f := &testFixture{root: filepath.Join(dir, "root"), proc: filepath.Join(dir, "proc")}
	r := func(p string) string { return filepath.Join(f.root, p) }

	write(t, r("/etc/os-release"), osRelease("debian", "12"))
	write(t, r("/var/lib/dpkg/status"), dpkgStatus("libfoo-java=1.2.3-1", "bash=5.2.15-2"))
	write(t, r("/var/lib/dpkg/info/libfoo-java.list"), []byte("/.\n/usr\n/usr/share\n/usr/share/java\n/usr/share/java/foo.jar\n"))
	f.fooJar = r("/usr/share/java/foo.jar")
	write(t, f.fooJar, jarBytes(t, "com.example", "foo", "1.2.3"))
	write(t, r("/opt/app/lib/bar.jar"), jarBytes(t, "org.example", "bar", "2.0.0"))
	if withGo {
		bin, err := os.ReadFile(buildGoTool(t))
		if err != nil {
			t.Fatal(err)
		}
		write(t, r("/usr/local/bin/gotool"), bin)
		os.Chmod(r("/usr/local/bin/gotool"), 0o755)
	}

	// Docker state: two running containers of image A, one of image B whose
	// root cannot be read, and one that is stopped.
	d := r("/var/lib/docker")
	write(t, filepath.Join(d, "containers", ct1ID, "config.v2.json"), dockerConfig(ct1ID, "app-1", imageA, "example/app:1", true, ct1PID, "2026-01-01T00:00:00Z"))
	write(t, filepath.Join(d, "containers", ct2ID, "config.v2.json"), dockerConfig(ct2ID, "app-2", imageA, "example/app:1", true, ct2PID, "2026-01-02T00:00:00Z"))
	write(t, filepath.Join(d, "containers", ct3ID, "config.v2.json"), dockerConfig(ct3ID, "other", imageB, "example/other:2", true, ct3PID, "2026-01-03T00:00:00Z"))
	write(t, filepath.Join(d, "containers", ct4ID, "config.v2.json"), dockerConfig(ct4ID, "stopped", imageB, "example/other:2", false, 0, "2026-01-04T00:00:00Z"))
	repos := map[string]any{"Repositories": map[string]any{
		"example/app":   map[string]string{"example/app:1": imageA, "example/app@" + digestA: imageA},
		"example/other": map[string]string{"example/other:2": imageB, "example/other@" + digestB: imageB},
	}}
	rb, _ := json.Marshal(repos)
	write(t, filepath.Join(d, "image/overlay2/repositories.json"), rb)
	for _, id := range []string{imageA, imageB} {
		write(t, filepath.Join(d, "image/overlay2/imagedb/content/sha256", strings.TrimPrefix(id, "sha256:")), []byte(`{"os":"linux","architecture":"amd64","rootfs":{"diff_ids":[]}}`))
	}
	write(t, filepath.Join(d, "image/overlay2/layerdb/mounts", ct1ID, "mount-id"), []byte("m1"))
	write(t, r(upperDir+"/app/runtime.jar"), jarBytes(t, "org.example", "runtime", "0.1"))

	// Container roots, reached through <proc>/<pid>/root. As in a real proc
	// tree, ct1's is a symbolic link; ct2's is a plain directory; ct3's
	// points nowhere.
	ct1 := filepath.Join(dir, "ct1-rootfs")
	write(t, filepath.Join(ct1, "etc/os-release"), osRelease("alpine", "3.20"))
	write(t, filepath.Join(ct1, "var/lib/dpkg/status"), dpkgStatus("ct1pkg=1.0"))
	write(t, filepath.Join(ct1, "app/image.jar"), jarBytes(t, "org.example", "image", "3.0"))
	write(t, filepath.Join(ct1, "app/runtime.jar"), jarBytes(t, "org.example", "runtime", "0.1"))
	ct2 := filepath.Join(f.proc, strconv.Itoa(ct2PID), "root")
	write(t, filepath.Join(ct2, "etc/os-release"), osRelease("alpine", "3.20"))
	write(t, filepath.Join(ct2, "var/lib/dpkg/status"), dpkgStatus("ct2pkg=1.0"))
	for pid, target := range map[int]string{ct1PID: ct1, ct3PID: filepath.Join(dir, "missing")} {
		pd := filepath.Join(f.proc, strconv.Itoa(pid))
		if err := os.MkdirAll(pd, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(pd, "root")); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(f.proc, "stat"), []byte("cpu 0 0 0 0\nbtime 1700000000\n"))
	return f
}

var privileged = report.Privilege{Level: report.PrivilegePrivileged, UID: 0}

func (f *testFixture) run(t *testing.T, req report.Request) *report.Report {
	t.Helper()
	if reflect.DeepEqual(req.Policy, report.Policy{}) {
		req.Policy = report.DefaultPolicy()
	}
	p := privileged
	rep, err := Run(context.Background(), req, Options{Root: f.root, Proc: f.proc, Privilege: &p})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestFixtureSections(t *testing.T) {
	f := newFixture(t, true)
	rep := f.run(t, report.Request{})

	if rep.SchemaVersion != report.SchemaVersion || rep.Privilege.Level != report.PrivilegePrivileged {
		t.Errorf("report header = %d %+v", rep.SchemaVersion, rep.Privilege)
	}
	if rep.Host == nil || rep.Host.OS.ID != "debian" {
		t.Fatalf("host = %+v", rep.Host)
	}
	if rep.Packages == nil || len(rep.Packages.Packages) != 2 {
		t.Fatalf("packages = %+v", rep.Packages)
	}
	if rep.Processes == nil || rep.Artifacts == nil || rep.Containers == nil {
		t.Fatalf("missing sections: processes=%v artifacts=%v containers=%v", rep.Processes != nil, rep.Artifacts != nil, rep.Containers != nil)
	}
	for name, m := range sectionMetas(rep) {
		if m.Digest == "" {
			t.Errorf("%s has no digest", name)
		}
	}

	byPath := map[string]report.Artifact{}
	var gotool bool
	for _, a := range rep.Artifacts.Artifacts {
		if a.Nested == nil && a.Kind == report.ArtifactJar {
			byPath[a.Path] = a
		}
		if a.Kind == report.ArtifactGoBinary && a.Path == "/usr/local/bin/gotool" {
			gotool = a.GoVersion != ""
		}
	}
	if foo := byPath["/usr/share/java/foo.jar"]; foo.Version != "1.2.3" || foo.OwnerPackage != "libfoo-java" || foo.SHA256 == "" {
		t.Errorf("foo.jar = %+v", foo)
	}
	if bar := byPath["/opt/app/lib/bar.jar"]; bar.Version != "2.0.0" || bar.OwnerPackage != "" {
		t.Errorf("bar.jar = %+v", bar)
	}
	if !gotool {
		t.Errorf("Go binary not reported: %+v", rep.Artifacts.Artifacts)
	}
	for _, a := range rep.Artifacts.Artifacts {
		if strings.Contains(a.Path, "/var/lib/docker") {
			t.Errorf("container storage walked on the host: %s", a.Path)
		}
	}
}

func TestFixtureContainers(t *testing.T) {
	f := newFixture(t, false)
	rep := f.run(t, report.Request{Sections: []string{report.SectionContainers}})
	if rep.Host != nil || rep.Packages != nil || rep.Processes != nil || rep.Artifacts != nil {
		t.Errorf("sections that were not requested are present")
	}
	sec := rep.Containers
	if sec == nil {
		t.Fatal("no containers section")
	}
	if sec.InventoryCoverage != report.CoverageFull {
		t.Errorf("inventory coverage = %q", sec.InventoryCoverage)
	}
	if len(sec.ImageScopes) != 1 {
		t.Fatalf("image scopes = %+v", sec.ImageScopes)
	}
	scope := sec.ImageScopes[0]
	if scope.Digest != digestA || scope.FromContainer != ct1ID || scope.OS == nil || scope.OS.ID != "alpine" {
		t.Errorf("scope = %+v", scope)
	}
	if len(scope.Packages) != 1 || scope.Packages[0].Name != "ct1pkg" {
		t.Errorf("scope packages = %+v (the image must be read once, from the first container)", scope.Packages)
	}
	var image bool
	for _, a := range scope.Artifacts {
		switch {
		case a.Path == "/app/runtime.jar":
			t.Errorf("writable-layer file in the image scope: %+v", a)
		case a.Path == "/app/image.jar" && a.Nested == nil:
			image = a.Layer == report.LayerImage && a.Version == "3.0"
		}
	}
	if !image {
		t.Errorf("image.jar missing or not marked as image content: %+v", scope.Artifacts)
	}

	cts := map[string]report.Container{}
	for _, c := range sec.Containers {
		cts[c.ID] = c
		if c.InitPID != 0 || c.UpperDir != "" {
			t.Errorf("%s: probe hints not stripped: %+v", c.Name, c)
		}
	}
	c1 := cts[ct1ID]
	if c1.Coverage != report.CoverageFull {
		t.Errorf("ct1 coverage = %s (%s)", c1.Coverage, c1.Reason)
	}
	if len(c1.RuntimeArtifacts) != 1 || c1.RuntimeArtifacts[0].Path != "/app/runtime.jar" ||
		c1.RuntimeArtifacts[0].Layer != report.LayerRuntime || c1.RuntimeArtifacts[0].Version != "0.1" {
		t.Errorf("ct1 runtime artifacts = %+v", c1.RuntimeArtifacts)
	}
	if c2 := cts[ct2ID]; c2.Coverage != report.CoveragePartial || !strings.Contains(c2.Reason, "writable layer not found") {
		t.Errorf("ct2 = %s (%s)", c2.Coverage, c2.Reason)
	}
	if c3 := cts[ct3ID]; c3.Coverage != report.CoverageNone || !strings.Contains(c3.Reason, "unreadable") {
		t.Errorf("ct3 = %s (%s)", c3.Coverage, c3.Reason)
	}
	if c4 := cts[ct4ID]; c4.Coverage != report.CoverageNone || c4.Reason != "container is not running" {
		t.Errorf("ct4 = %s (%s)", c4.Coverage, c4.Reason)
	}

	// Without privileges the inventory stays and no content is read.
	p := report.Privilege{Level: report.PrivilegeNonRoot, UID: 1000}
	rep2, err := Run(context.Background(), report.Request{Sections: []string{report.SectionContainers}, Policy: report.DefaultPolicy()},
		Options{Root: f.root, Proc: f.proc, Privilege: &p})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Containers.ImageScopes) != 0 || len(rep2.Containers.Containers) != 4 {
		t.Errorf("unprivileged containers = %+v", rep2.Containers)
	}
	for _, c := range rep2.Containers.Containers {
		if c.Coverage != report.CoverageNone || c.Reason == "" {
			t.Errorf("unprivileged %s = %s (%s)", c.Name, c.Coverage, c.Reason)
		}
	}
}

// TestUnverifiedImageDigest checks a container whose image digest the
// inventory could not verify: only its writable layer is read, nothing is
// stored as image content, and the inventory's reason is kept.
func TestUnverifiedImageDigest(t *testing.T) {
	f := newFixture(t, false)
	env := &collect.Env{Root: f.root, Proc: f.proc, Policy: report.DefaultPolicy(), Cache: collect.NewHashCache(),
		Log: slog.New(slog.DiscardHandler), Privileged: true}
	r := &runner{env: env, log: env.Log, ctx: context.Background(), hardStop: time.Now().Add(time.Minute), limit: time.Minute}
	const note = "image digest could not be verified: test"
	sec := &report.ContainersSection{Containers: []report.Container{
		{ID: ct1ID, Name: "app-1", Running: true, InitPID: ct1PID, UpperDir: upperDir, Reason: note},
		{ID: ct4ID, Name: "stopped", Reason: note},
	}}
	if r.scanContainers(sec, nil, nil) {
		t.Fatal("interrupted")
	}
	if len(sec.ImageScopes) != 0 {
		t.Errorf("image scopes = %+v", sec.ImageScopes)
	}
	c1, c4 := sec.Containers[0], sec.Containers[1]
	if c1.Coverage != report.CoveragePartial || c1.Reason != note+"; image content not scanned" {
		t.Errorf("app-1 = %s (%s)", c1.Coverage, c1.Reason)
	}
	if len(c1.RuntimeArtifacts) != 1 || c1.RuntimeArtifacts[0].Path != "/app/runtime.jar" {
		t.Errorf("app-1 runtime artifacts = %+v", c1.RuntimeArtifacts)
	}
	if c4.Coverage != report.CoverageNone || c4.Reason != note+"; container is not running" {
		t.Errorf("stopped = %s (%s)", c4.Coverage, c4.Reason)
	}
}

func TestFixtureContainerLimit(t *testing.T) {
	f := newFixture(t, false)
	p := privileged
	rep, err := Run(context.Background(), report.Request{Sections: []string{report.SectionContainers}, Policy: report.DefaultPolicy()},
		Options{Root: f.root, Proc: f.proc, Privilege: &p, MaxContainers: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Containers.Containers {
		if c.ID == ct3ID && !strings.Contains(c.Reason, "limit of 1 scanned containers") {
			t.Errorf("ct3 = %s (%s)", c.Coverage, c.Reason)
		}
	}
}

func sectionMetas(rep *report.Report) map[string]*report.SectionMeta {
	m := map[string]*report.SectionMeta{}
	if rep.Host != nil {
		m[report.SectionHost] = &rep.Host.SectionMeta
	}
	if rep.Packages != nil {
		m[report.SectionPackages] = &rep.Packages.SectionMeta
	}
	if rep.Processes != nil {
		m[report.SectionProcesses] = &rep.Processes.SectionMeta
	}
	if rep.Artifacts != nil {
		m[report.SectionArtifacts] = &rep.Artifacts.SectionMeta
	}
	if rep.Containers != nil {
		m[report.SectionContainers] = &rep.Containers.SectionMeta
	}
	return m
}

func digests(rep *report.Report) map[string]string {
	out := map[string]string{}
	for name, m := range sectionMetas(rep) {
		out[name] = m.Digest
	}
	return out
}

func TestFixtureDigestsAndKnown(t *testing.T) {
	f := newFixture(t, false)
	first := f.run(t, report.Request{})
	second := f.run(t, report.Request{})
	d1, d2 := digests(first), digests(second)
	if len(d1) != len(report.AllSections) {
		t.Fatalf("digests = %v", d1)
	}
	for name, d := range d1 {
		if d2[name] != d {
			t.Errorf("%s digest changed between runs: %s → %s", name, d, d2[name])
		}
	}

	third := f.run(t, report.Request{KnownDigests: d1})
	for name, m := range sectionMetas(third) {
		if !m.Unchanged || m.Digest != d1[name] {
			t.Errorf("%s: unchanged=%v digest=%s", name, m.Unchanged, m.Digest)
		}
	}
	if len(third.Packages.Packages) != 0 || len(third.Artifacts.Artifacts) != 0 || len(third.Containers.Containers) != 0 ||
		len(third.Containers.ImageScopes) != 0 || third.Host.Hostname != "" {
		t.Errorf("unchanged sections carry items")
	}

	// A stale digest returns the full section.
	fourth := f.run(t, report.Request{KnownDigests: map[string]string{report.SectionPackages: "stale"}})
	if fourth.Packages.Unchanged || len(fourth.Packages.Packages) != 2 {
		t.Errorf("stale digest: %+v", fourth.Packages)
	}
}

// TestFixtureCacheRoundTrip shows that a cache passed back in the request
// is used instead of hashing again: the hash of the jar is replaced in the
// cache, and a later run reports the replaced value, also after a run of
// another section that did not look at the jar.
func TestFixtureCacheRoundTrip(t *testing.T) {
	f := newFixture(t, false)
	req := report.Request{Sections: []string{report.SectionArtifacts}}
	first := f.run(t, req)
	if len(first.Cache) == 0 {
		t.Fatal("no cache returned")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(f.fooJar, &st); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(first.Cache, &doc); err != nil {
		t.Fatalf("cache: %v", err)
	}
	if err := json.Unmarshal(doc["files"], &entries); err != nil {
		t.Fatalf("cache files: %v", err)
	}
	const fake = "f00df00df00df00df00df00df00df00df00df00df00df00df00df00df00df00d"
	replaced := false
	for _, e := range entries {
		var k struct {
			I uint64 `json:"i"`
		}
		if json.Unmarshal(e["k"], &k) == nil && k.I == st.Ino {
			e["h"] = json.RawMessage(`"` + fake + `"`)
			replaced = true
		}
	}
	if !replaced {
		t.Fatalf("jar not in cache: %s", first.Cache)
	}
	doc["files"], _ = json.Marshal(entries)
	cache, _ := json.Marshal(doc)

	// A run of another section in between must not discard the entry.
	between := f.run(t, report.Request{Sections: []string{report.SectionProcesses}, Cache: cache})

	req.Cache = between.Cache
	second := f.run(t, req)
	var got string
	for _, a := range second.Artifacts.Artifacts {
		if a.Path == "/usr/share/java/foo.jar" && a.Nested == nil {
			got = a.SHA256
		}
	}
	if got != fake {
		t.Errorf("jar hash = %s, want the cached value", got)
	}
}
