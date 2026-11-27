// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestWalkExclusions(t *testing.T) {
	root := t.TempDir()
	jar := buildZip(t, pomEntry("g", "a", "1"))
	for _, p := range []string{
		"opt/app/keep-1.0.jar",
		"opt/app/deep/a/b/c/keep2-1.0.jar",
		"proc/1/x-1.0.jar",
		"sys/x-1.0.jar",
		"dev/x-1.0.jar",
		"run/x-1.0.jar",
		"var/lib/docker/overlay2/abc/merged/x-1.0.jar",
		"var/lib/containerd/x-1.0.jar",
		"var/lib/containers/storage/x-1.0.jar",
		"var/lib/kubelet/pods/uid/volumes/x-1.0.jar",
		"var/lib/kubelet/keep3-1.0.jar",
		"data/skip/x-1.0.jar",
		"data/cache-1/x-1.0.jar",
		"data/keep4-1.0.jar",
		"srv/notes.txt",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, jar, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Symbolic links are not followed, to directories or to files.
	os.Symlink(filepath.Join(root, "opt", "app"), filepath.Join(root, "srv", "applink"))
	os.Symlink(filepath.Join(root, "opt", "app", "keep-1.0.jar"), filepath.Join(root, "srv", "link-1.0.jar"))
	// A FIFO with a jar name must not block the walk.
	if err := mkfifo(filepath.Join(root, "srv", "fifo-1.0.jar")); err != nil {
		t.Fatal(err)
	}

	env := testEnv(root)
	env.Policy.ExcludePaths = []string{"/data/skip", "/data/cache-*", "relative/ignored"}
	sec := testCollector(env, Inputs{}, "/").run(context.Background())
	var paths []string
	for _, a := range sec.Artifacts {
		paths = append(paths, a.Path)
	}
	want := []string{"/data/keep4-1.0.jar", "/opt/app/deep/a/b/c/keep2-1.0.jar", "/opt/app/keep-1.0.jar", "/var/lib/kubelet/keep3-1.0.jar"}
	if !slices.Equal(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if sec.Coverage != report.CoverageFull {
		t.Fatalf("coverage %s %q", sec.Coverage, sec.Reason)
	}
}

func TestWalkUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	for _, d := range []string{"a/locked", "b/locked"} {
		p := filepath.Join(root, d)
		os.MkdirAll(p, 0o755)
		os.WriteFile(filepath.Join(p, "x-1.jar"), buildZip(t, pomEntry("g", "x", "1")), 0o644)
		os.Chmod(p, 0)
		t.Cleanup(func() { os.Chmod(p, 0o755) })
	}
	sec := testCollector(testEnv(root), Inputs{}, "/").run(context.Background())
	if sec.Coverage != report.CoveragePartial || sec.Reason != "2 directories could not be read" {
		t.Fatalf("coverage %s %q", sec.Coverage, sec.Reason)
	}
}

// TestWalkSymlinkRoot walks a root given as a symbolic link, as a container
// root under /proc/<pid>/root is. Links below the root are still not
// followed.
func TestWalkSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.MkdirAll(filepath.Join(target, "app"), 0o755)
	os.WriteFile(filepath.Join(target, "app", "x-1.jar"), buildZip(t, pomEntry("g", "x", "1")), 0o644)
	outside := filepath.Join(dir, "outside")
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(outside, "y-1.jar"), buildZip(t, pomEntry("g", "y", "1")), 0o644)
	os.Symlink(outside, filepath.Join(target, "link"))
	root := filepath.Join(dir, "root")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	sec := testCollector(testEnv(root), Inputs{}, "/").run(context.Background())
	var paths []string
	for _, a := range sec.Artifacts {
		paths = append(paths, a.Path)
	}
	if !slices.Equal(paths, []string{"/app/x-1.jar"}) {
		t.Errorf("paths = %v", paths)
	}
	if sec.Coverage != report.CoverageFull {
		t.Errorf("coverage %s %q", sec.Coverage, sec.Reason)
	}
}

func TestWalkRootUnopenable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	sec := testCollector(testEnv(root), Inputs{}, "/").run(context.Background())
	if sec.Coverage != report.CoverageNone || !strings.Contains(sec.Reason, "cannot open the root directory") || len(sec.Artifacts) != 0 {
		t.Fatalf("coverage %s %q, %d artifacts", sec.Coverage, sec.Reason, len(sec.Artifacts))
	}
}

func TestWalkCancelled(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "x-1.jar"), buildZip(t, pomEntry("g", "x", "1")), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sec := testCollector(testEnv(root), Inputs{}, "/").run(ctx)
	if sec.Coverage != report.CoveragePartial || !strings.Contains(sec.Reason, "cancelled") {
		t.Fatalf("coverage %s %q", sec.Coverage, sec.Reason)
	}
}

func TestParseMountinfo(t *testing.T) {
	const info = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
30 22 0:40 / /mnt/nfs rw shared:20 - nfs4 srv:/export rw,vers=4.2
31 22 0:41 / /home/u/remote rw - fuse.sshfs u@h:/ rw
32 22 8:1 /srv/data /mnt/bind rw shared:1 - ext4 /dev/sda1 rw
33 22 8:2 /sub /a rw - xfs /dev/sdb1 rw
34 22 8:2 /sub /b rw - xfs /dev/sdb1 rw
35 22 8:3 / /media/with\040space rw - ext4 /dev/sdc1 rw
36 22 0:50 / /mnt/tmp rw - tmpfs tmpfs rw
`
	mt := parseMountinfo(strings.NewReader(info))
	if m, ok := mt.byPoint["/media/with space"]; !ok || m.fsType != "ext4" {
		t.Fatalf("escaped mount point not decoded: %+v", mt.byPoint)
	}
	skipped := func(p string) bool {
		m := mt.byPoint[p]
		return skipFSType(m.fsType) || mt.duplicates[p]
	}
	for p, want := range map[string]bool{
		"/":                 false,
		"/proc":             true,
		"/mnt/nfs":          true,
		"/home/u/remote":    true,
		"/mnt/bind":         true,  // the same file system is mounted whole at /
		"/a":                false, // first of two binds of the same subtree
		"/b":                true,
		"/media/with space": false,
		"/mnt/tmp":          false,
	} {
		if got := skipped(p); got != want {
			t.Errorf("%s skipped = %v, want %v", p, got, want)
		}
	}
}

func TestMarkHostDirs(t *testing.T) {
	const host = `22 1 8:1 / / rw - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw - proc proc rw
24 22 8:2 / /srv rw - xfs /dev/sdb1 rw
25 22 0:60 / /var/lib/kubelet/pods/u1/volumes/kubernetes.io~configmap/cfg rw - tmpfs tmpfs rw
26 22 0:70 / /run/containerd/io.containerd.runtime.v2.task/k8s.io/c1/rootfs rw - overlay overlay rw
27 22 8:3 / /mnt/hidden rw - ext4 /dev/sdc1 rw
28 27 8:4 / /mnt/hidden/inner rw - ext4 /dev/sdd1 rw
`
	const ctr = `40 39 0:70 / / rw - overlay overlay rw
41 40 0:80 / /proc rw - proc proc rw
42 40 8:1 / /host rw - ext4 /dev/sda1 rw
43 40 8:1 /var/lib/kubelet/pods/u1/volumes/kubernetes.io~empty-dir/data /data rw - ext4 /dev/sda1 rw
44 40 0:60 / /etc/cfg rw - tmpfs tmpfs rw
45 40 8:2 /app /opt/app rw - xfs /dev/sdb1 rw
46 40 8:1 /var/lib/docker/volumes/v/_data /vol rw - ext4 /dev/sda1 rw
47 40 8:5 / /pvc rw - ext4 /dev/sde1 rw
48 40 8:1 /etc/ssl /etc/ssl rw - ext4 /dev/sda1 rw
49 40 8:3 /inner /hidden rw - ext4 /dev/sdc1 rw
`
	h := parseMountinfo(strings.NewReader(host))
	c := parseMountinfo(strings.NewReader(ctr))
	excluded := func(p string) bool { return (&collector{excludes: buildExcludes([]string{"/etc/ssl"})}).excluded(p) }
	c.markHostDirs(h, excluded)
	for p, want := range map[string]bool{
		"/":        false,
		"/host":    true,  // the node root
		"/data":    false, // emptyDir in kubelet storage
		"/etc/cfg": false, // configMap tmpfs in kubelet storage
		"/opt/app": true,  // hostPath of another file system
		"/vol":     false, // docker volume
		"/pvc":     false, // not mounted on the host
		"/etc/ssl": false, // excluded from the host walk by policy
		"/hidden":  false, // hidden on the host by another mount
	} {
		if got := c.hostDirs[p]; got != want {
			t.Errorf("%s host dir = %v, want %v", p, got, want)
		}
	}
}

func TestExcluded(t *testing.T) {
	c := newCollector(testEnv("/"), Inputs{})
	c.excludes = buildExcludes([]string{"/opt/skip/", "/home/*/cache"})
	for p, want := range map[string]bool{
		"/proc":           true,
		"/proc/1":         true,
		"/processes":      false,
		"/opt/skip":       true,
		"/opt/skip/x":     true,
		"/opt/skipped":    false,
		"/home/u/cache":   true,
		"/home/u/cache2":  false,
		"/var/lib/docker": true,
		"/var/lib":        false,
	} {
		if got := c.excluded(p); got != want {
			t.Errorf("excluded(%s) = %v, want %v", p, got, want)
		}
	}
}

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o644) }

func TestCleanWalkPaths(t *testing.T) {
	got := cleanWalkPaths([]string{"/opt/app/", "relative", "/opt", "/srv/x/../y", "/optional", "", "/opt/app/lib"})
	if want := []string{"/opt", "/optional", "/srv/y"}; !slices.Equal(got, want) {
		t.Errorf("cleanWalkPaths = %v, want %v", got, want)
	}
	if got := cleanWalkPaths([]string{"/opt", "/"}); !slices.Equal(got, []string{"/"}) {
		t.Errorf("with / = %v", got)
	}
}

// TestWalkPaths walks only the walk paths. Missing paths, symbolic links and
// excluded paths are not walked and do not reduce coverage.
func TestWalkPaths(t *testing.T) {
	root := t.TempDir()
	jar := buildZip(t, pomEntry("g", "a", "1"))
	for _, p := range []string{"opt/app/a-1.jar", "opt/app/lib/b-1.jar", "srv/c-1.jar", "home/u/Downloads/d-1.jar", "data/skip/e-1.jar"} {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, jar, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.Symlink(filepath.Join(root, "srv"), filepath.Join(root, "srvlink"))
	env := testEnv(root)
	env.Policy.ExcludePaths = []string{"/data/skip"}
	in := Inputs{WalkPaths: []string{"/opt/app/lib", "/opt/app", "/missing", "/srvlink", "/data/skip", "/srv"}}
	sec := newCollector(env, in).run(context.Background())
	var paths []string
	for _, a := range sec.Artifacts {
		paths = append(paths, a.Path)
	}
	if want := []string{"/opt/app/a-1.jar", "/opt/app/lib/b-1.jar", "/srv/c-1.jar"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if want := []string{"/opt/app", "/srv"}; !slices.Equal(sec.WalkPaths, want) {
		t.Errorf("walked = %v, want %v", sec.WalkPaths, want)
	}
	if sec.Coverage != report.CoverageFull {
		t.Errorf("coverage %s %q", sec.Coverage, sec.Reason)
	}

	// No walk paths: nothing on disk is read.
	sec = newCollector(env, Inputs{}).run(context.Background())
	if len(sec.Artifacts) != 0 || sec.WalkPaths != nil || sec.Coverage != report.CoverageFull {
		t.Errorf("no walk: %+v", sec)
	}
}
