// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package container

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	alpineDigest  = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	busyboxDigest = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	corednsDigest = "sha256:1391544c978029fcddc65068f6ad67f396e55585b664ecccd7fefba029b9b706"
	pauseDigest   = "sha256:74c4244427b7312c5b901fe0f67cbc53683d06f4f24c6faee65d4182bf0fa893"
	// committedID is a locally committed image: it has no repo digest.
	committedID = "sha256:4c0c71d6db540ef542dd44038e2bf391429580c3e40d473124b3e45317920413"
)

func byName(t *testing.T, sec *report.ContainersSection) map[string]report.Container {
	t.Helper()
	m := map[string]report.Container{}
	for _, c := range sec.Containers {
		m[c.Name] = c
	}
	return m
}

func imagesByDigest(sec *report.ContainersSection) map[string]report.Image {
	m := map[string]report.Image{}
	for _, img := range sec.Images {
		m[img.Digest] = img
	}
	return m
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func checkCoverage(t *testing.T, sec *report.ContainersSection, want report.Coverage) {
	t.Helper()
	if sec.Coverage != want {
		t.Fatalf("coverage = %q (%s), want %q", sec.Coverage, sec.Reason, want)
	}
}

func checkImagesKnown(t *testing.T, sec *report.ContainersSection) {
	t.Helper()
	imgs := imagesByDigest(sec)
	for _, c := range sec.Containers {
		if c.ImageDigest == "" {
			continue
		}
		if _, ok := imgs[c.ImageDigest]; !ok {
			t.Errorf("container %s: image digest %s is not in the image list", c.Name, c.ImageDigest)
		}
	}
}

func TestDockerOverlay2(t *testing.T) {
	root, proc := fixture(t, "docker-overlay2")
	sec := Collect(context.Background(), testEnv(root, proc))
	if sec == nil {
		t.Fatal("nil section")
	}
	checkCoverage(t, sec, report.CoverageFull)
	if !reflect.DeepEqual(sec.Runtimes, []string{"docker"}) {
		t.Errorf("runtimes = %v", sec.Runtimes)
	}
	if sec.Digest == "" {
		t.Error("no digest")
	}

	got := byName(t, sec)
	want := map[string]report.Container{
		"web": {
			ID: "2966a90bc5a507ecac8e8640752d6262074e840c628b9ee2b4eaa6adca76176a", Name: "web", Runtime: "docker",
			ImageRef: "docker.io/library/alpine:3.20", ImageDigest: alpineDigest,
			Running: true, StartedAt: mustTime(t, "2026-11-20T15:11:21.244064138Z"), InitPID: 1578,
			UpperDir: "/var/lib/docker/overlay2/17f7444d9356fb3d8b1a0212ebd133a7f06e4de5ecc8e939e9efd7df4f1bb36e/diff",
		},
		"worker": {
			ID: "1b2efa9930ed6e7f2b24636898a510ee47484fd06aa89324eee3920ab9381334", Name: "worker", Runtime: "docker",
			ImageRef: "docker.io/library/busybox:1.36", ImageDigest: busyboxDigest,
			Running: true, StartedAt: mustTime(t, "2026-11-20T15:11:21.638801072Z"), InitPID: 1637,
			UpperDir: "/var/lib/docker/overlay2/d6c68e47ad77e11c45d36f53687f38e1def4c3fef5aefc5bc326a595ada61a51/diff",
		},
		"done": {
			ID: "7bcd69479b8d8b476e18b2c3a32cd0a4fbd66bae43bf675d86134171c892f05c", Name: "done", Runtime: "docker",
			ImageRef: "docker.io/library/alpine:3.20", ImageDigest: alpineDigest,
			StartedAt: mustTime(t, "2026-11-20T15:11:21.479909725Z"),
			UpperDir:  "/var/lib/docker/overlay2/352a0b55d5852f8f67e970940d1078fc167919509539fdd19f868b3239f49147/diff",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("containers:\n got %+v\nwant %+v", got, want)
	}

	wantImages := []report.Image{
		{Digest: committedID, RepoTags: []string{"docker.io/local/committed:1"}, OS: "linux", Arch: "amd64", Size: 7807585},
		{Digest: busyboxDigest, RepoTags: []string{"docker.io/library/busybox:1.36"}, OS: "linux", Arch: "amd64", Size: 4417166},
		{Digest: alpineDigest, RepoTags: []string{"docker.io/library/alpine:3.20", "docker.io/local/alpine:mine"}, OS: "linux", Arch: "amd64", Size: 7807582},
	}
	if !reflect.DeepEqual(sec.Images, wantImages) {
		t.Errorf("images:\n got %+v\nwant %+v", sec.Images, wantImages)
	}
}

func TestDockerStaleRunningState(t *testing.T) {
	root, proc := fixture(t, "docker-overlay2")
	// The process of "worker" is gone, as after a host crash.
	if err := os.RemoveAll(filepath.Join(proc, "1637")); err != nil {
		t.Fatal(err)
	}
	w := byName(t, Collect(context.Background(), testEnv(root, proc)))["worker"]
	if w.Running || w.InitPID != 0 {
		t.Errorf("worker: running=%v pid=%d, want stopped", w.Running, w.InitPID)
	}
}

func TestDockerContainerdStore(t *testing.T) {
	root, proc := fixture(t, "docker-snapshotter")
	sec := Collect(context.Background(), testEnv(root, proc))
	if sec == nil {
		t.Fatal("nil section")
	}
	checkCoverage(t, sec, report.CoverageFull)
	// The containerd that dockerd runs itself is part of Docker.
	if !reflect.DeepEqual(sec.Runtimes, []string{"docker"}) {
		t.Errorf("runtimes = %v", sec.Runtimes)
	}
	snap := "/srv/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/"
	got := byName(t, sec)
	want := map[string]struct {
		running bool
		pid     int
		digest  string
		upper   string
	}{
		"web":    {true, 1545, alpineDigest, snap + "4/fs"},
		"worker": {true, 1603, busyboxDigest, snap + "6/fs"},
		"done":   {false, 0, alpineDigest, snap + "8/fs"},
	}
	if len(got) != len(want) {
		t.Fatalf("containers = %+v", sec.Containers)
	}
	for name, w := range want {
		c := got[name]
		if c.Running != w.running || c.InitPID != w.pid || c.ImageDigest != w.digest || c.UpperDir != w.upper || c.Runtime != "docker" {
			t.Errorf("%s = %+v, want %+v", name, c, w)
		}
	}
	wantImages := []report.Image{
		{Digest: busyboxDigest, RepoTags: []string{"docker.io/library/busybox:1.36"}, OS: "linux", Arch: "amd64", Size: 2217006},
		{Digest: alpineDigest, RepoTags: []string{"docker.io/library/alpine:3.20", "docker.io/local/alpine:mine"}, OS: "linux", Arch: "amd64", Size: 3641182},
	}
	if !reflect.DeepEqual(sec.Images, wantImages) {
		t.Errorf("images:\n got %+v\nwant %+v", sec.Images, wantImages)
	}
}

func TestContainerdCRI(t *testing.T) {
	root, proc := fixture(t, "k3s")
	sec := Collect(context.Background(), testEnv(root, proc))
	if sec == nil {
		t.Fatal("nil section")
	}
	checkCoverage(t, sec, report.CoverageFull)
	if !reflect.DeepEqual(sec.Runtimes, []string{"containerd"}) {
		t.Errorf("runtimes = %v", sec.Runtimes)
	}

	snap := "/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/"
	got := byName(t, sec)
	want := map[string]report.Container{
		"default/demo/demo": {
			ID: "409e30b3c16a8b2fa979860a02041d9c5c92708e422cc8df037dd475bf03d09c", Name: "default/demo/demo", Runtime: "containerd",
			ImageRef: "docker.io/library/alpine:3.20", ImageDigest: alpineDigest,
			Running: true, StartedAt: time.Unix(0, 1795187584356708402).UTC(), InitPID: 798, UpperDir: snap + "20/fs",
		},
		"kube-system/coredns-7896679cc-bqqv5/coredns": {
			ID: "2a76ed4f1e98d1ab3b852d34ea92fdc192199425becf352f40131877d2f545fb", Name: "kube-system/coredns-7896679cc-bqqv5/coredns", Runtime: "containerd",
			ImageRef: "docker.io/rancher/mirrored-coredns-coredns:1.12.3", ImageDigest: corednsDigest,
			Running: true, StartedAt: time.Unix(0, 1795187473274127925).UTC(), InitPID: 517, UpperDir: snap + "17/fs",
		},
		"default/oneshot/oneshot": {
			ID: "c09d940cd58f26b761b3472cb93afbf074dcc86721d5f432176fc45454d626cf", Name: "default/oneshot/oneshot", Runtime: "containerd",
			ImageRef: "docker.io/library/busybox:1.36", ImageDigest: busyboxDigest,
			StartedAt: time.Unix(0, 1795188255655565987).UTC(), UpperDir: snap + "23/fs",
		},
	}
	plain, ok := got["plain"]
	if !ok {
		t.Fatalf("plain ctr container missing: %+v", sec.Containers)
	}
	delete(got, "plain")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("containers:\n got %+v\nwant %+v", got, want)
	}
	// Without CRI the start time comes from the task's init.pid.
	if !plain.Running || plain.InitPID != 1799 || plain.ImageDigest != alpineDigest || plain.UpperDir != snap+"25/fs" || plain.StartedAt.IsZero() {
		t.Errorf("plain = %+v", plain)
	}
	for _, c := range sec.Containers {
		if strings.HasPrefix(c.ImageRef, "docker.io/rancher/mirrored-pause") {
			t.Errorf("sandbox container listed: %+v", c)
		}
	}

	imgs := imagesByDigest(sec)
	wantImages := map[string]report.Image{
		alpineDigest:  {Digest: alpineDigest, RepoTags: []string{"docker.io/library/alpine:3.20"}, OS: "linux", Arch: "amd64", Size: 3641182},
		busyboxDigest: {Digest: busyboxDigest, RepoTags: []string{"docker.io/library/busybox:1.36"}, OS: "linux", Arch: "amd64", Size: 2217006},
		corednsDigest: {Digest: corednsDigest, RepoTags: []string{"docker.io/rancher/mirrored-coredns-coredns:1.12.3"}, OS: "linux", Arch: "amd64", Size: 22376752},
		pauseDigest:   {Digest: pauseDigest, RepoTags: []string{"docker.io/rancher/mirrored-pause:3.6"}, OS: "linux", Arch: "amd64", Size: 301463},
	}
	if !reflect.DeepEqual(imgs, wantImages) {
		t.Errorf("images:\n got %+v\nwant %+v", imgs, wantImages)
	}
}

func TestContainerdTaskFallback(t *testing.T) {
	root, proc := fixture(t, "k3s")
	meta := filepath.Join(root, "var/lib/rancher/k3s/agent/containerd", cdMetaDB)
	if err := os.WriteFile(meta, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec := Collect(context.Background(), testEnv(root, proc))
	checkCoverage(t, sec, report.CoveragePartial)
	if !strings.Contains(sec.Reason, "metadata database") {
		t.Errorf("reason = %q", sec.Reason)
	}
	if len(sec.Images) != 0 {
		t.Errorf("images without metadata: %+v", sec.Images)
	}
	snap := "/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/"
	got := byName(t, sec)
	if len(got) != 3 {
		t.Fatalf("containers = %+v", sec.Containers)
	}
	demo := got["default/demo/demo"]
	if !demo.Running || demo.InitPID != 798 || demo.ImageRef != "docker.io/library/alpine:3.20" ||
		demo.ImageDigest != "" || demo.UpperDir != snap+"20/fs" || demo.StartedAt.IsZero() {
		t.Errorf("demo = %+v", demo)
	}
	if c := got["kube-system/coredns-7896679cc-bqqv5/coredns"]; !c.Running || c.InitPID != 517 {
		t.Errorf("coredns = %+v", c)
	}
	if c := got["plain"]; !c.Running || c.InitPID != 1799 {
		t.Errorf("plain = %+v", c)
	}
}

func TestUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not apply to root")
	}
	t.Run("docker containers", func(t *testing.T) {
		root, proc := fixture(t, "docker-overlay2")
		dir := filepath.Join(root, "var/lib/docker/containers")
		chmod(t, dir, 0)
		sec := Collect(context.Background(), testEnv(root, proc))
		checkCoverage(t, sec, report.CoveragePartial)
		if !strings.Contains(sec.Reason, "/var/lib/docker/containers: permission denied") {
			t.Errorf("reason = %q", sec.Reason)
		}
		if len(sec.Containers) != 0 || len(sec.Images) != 3 {
			t.Errorf("containers=%d images=%d", len(sec.Containers), len(sec.Images))
		}
	})
	t.Run("docker data root", func(t *testing.T) {
		root, proc := fixture(t, "docker-overlay2")
		chmod(t, filepath.Join(root, "var/lib/docker"), 0)
		sec := Collect(context.Background(), testEnv(root, proc))
		checkCoverage(t, sec, report.CoverageNone)
		if !reflect.DeepEqual(sec.Runtimes, []string{"docker"}) || len(sec.Containers)+len(sec.Images) != 0 {
			t.Errorf("section = %+v", sec)
		}
	})
	t.Run("containerd", func(t *testing.T) {
		root, proc := fixture(t, "k3s")
		chmod(t, filepath.Join(root, "var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt"), 0)
		chmod(t, filepath.Join(root, "run/k3s/containerd", cdTasks), 0)
		sec := Collect(context.Background(), testEnv(root, proc))
		checkCoverage(t, sec, report.CoverageNone)
		if !strings.Contains(sec.Reason, "permission denied") {
			t.Errorf("reason = %q", sec.Reason)
		}
	})
	t.Run("one of two runtimes", func(t *testing.T) {
		root, proc := fixture(t, "docker-overlay2", "k3s")
		chmod(t, filepath.Join(root, "var/lib/docker"), 0)
		sec := Collect(context.Background(), testEnv(root, proc))
		checkCoverage(t, sec, report.CoveragePartial)
		if len(sec.Containers) != 4 {
			t.Errorf("containers = %+v", sec.Containers)
		}
	})
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o755) })
}

func TestNoRuntime(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if sec := Collect(context.Background(), testEnv(root, t.TempDir())); sec != nil {
		t.Errorf("section = %+v, want nil", sec)
	}
}

func TestEmptyDockerDataRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/docker"), 0o710); err != nil {
		t.Fatal(err)
	}
	sec := Collect(context.Background(), testEnv(root, t.TempDir()))
	if sec == nil {
		t.Fatal("nil section")
	}
	checkCoverage(t, sec, report.CoverageFull)
	if len(sec.Containers)+len(sec.Images) != 0 {
		t.Errorf("section = %+v", sec)
	}
}

func TestDeterministic(t *testing.T) {
	root, proc := fixture(t, "docker-overlay2", "k3s")
	first := Collect(context.Background(), testEnv(root, proc))
	checkCoverage(t, first, report.CoverageFull)
	checkImagesKnown(t, first)
	if !reflect.DeepEqual(first.Runtimes, []string{"containerd", "docker"}) {
		t.Errorf("runtimes = %v", first.Runtimes)
	}
	// The same image pulled by both runtimes is one entry.
	alpine := imagesByDigest(first)[alpineDigest]
	if !reflect.DeepEqual(alpine.RepoTags, []string{"docker.io/library/alpine:3.20", "docker.io/local/alpine:mine"}) {
		t.Errorf("alpine tags = %v", alpine.RepoTags)
	}
	for i := 0; i < 10; i++ {
		again := Collect(context.Background(), testEnv(root, proc))
		if again.Digest != first.Digest ||
			!reflect.DeepEqual(again.Containers, first.Containers) ||
			!reflect.DeepEqual(again.Images, first.Images) ||
			!reflect.DeepEqual(again.Runtimes, first.Runtimes) {
			t.Fatalf("run %d differs", i)
		}
	}
	for i := 1; i < len(first.Containers); i++ {
		a, b := first.Containers[i-1], first.Containers[i]
		if a.Runtime > b.Runtime || (a.Runtime == b.Runtime && a.Name > b.Name) {
			t.Errorf("containers out of order: %s/%s before %s/%s", a.Runtime, a.Name, b.Runtime, b.Name)
		}
	}
	for i := 1; i < len(first.Images); i++ {
		if first.Images[i-1].Digest >= first.Images[i].Digest {
			t.Errorf("images out of order at %d", i)
		}
	}
}

func TestDigestIgnoresProbeHints(t *testing.T) {
	root, proc := fixture(t, "docker-overlay2")
	a := Collect(context.Background(), testEnv(root, proc))
	sec := *a
	sec.Containers = append([]report.Container(nil), a.Containers...)
	for i := range sec.Containers {
		sec.Containers[i].InitPID += 1000
		sec.Containers[i].UpperDir = "/elsewhere"
	}
	d, err := sectionDigest(&sec)
	if err != nil {
		t.Fatal(err)
	}
	if d != a.Digest {
		t.Error("digest depends on InitPID or UpperDir")
	}
}

func TestCancelled(t *testing.T) {
	root, proc := fixture(t, "docker-overlay2")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sec := Collect(ctx, testEnv(root, proc))
	checkCoverage(t, sec, report.CoveragePartial)
	if !strings.Contains(sec.Reason, "interrupted") {
		t.Errorf("reason = %q", sec.Reason)
	}
}

func TestMountinfoUpper(t *testing.T) {
	proc := t.TempDir()
	line := `1185 1156 0:164 / / rw,relatime - overlay overlay rw,lowerdir=/a/1/fs:/a/2/fs,upperdir=/var/lib/my\040dir/3/fs,workdir=/var/lib/my\040dir/3/work` + "\n"
	other := "22 1 8:1 / /data rw - ext4 /dev/sda1 rw\n"
	if err := os.MkdirAll(filepath.Join(proc, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "42", "mountinfo"), []byte(other+line), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &collector{env: testEnv("/", proc)}
	if got := c.upperFromMountinfo(42); got != "/var/lib/my dir/3/fs" {
		t.Errorf("upper = %q", got)
	}
	if got := c.upperFromMountinfo(43); got != "" {
		t.Errorf("missing process: upper = %q", got)
	}
}

func TestChainIDs(t *testing.T) {
	got := chainIDs([]string{
		"sha256:08bc4e534116aa76b16015484b82eac51f9a593416feae9296c8a2d4bb7aa4a2",
		"sha256:2268e6c7a615410cbdb0c54c1f871ca48c2484c3c741c1781ffb76af3b32364c",
	})
	want := []string{
		"sha256:08bc4e534116aa76b16015484b82eac51f9a593416feae9296c8a2d4bb7aa4a2",
		"sha256:527c0674aeaf4b8f0aef9e87b5e168b681c76ec7716d83037dff78749f9a30b3",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chain ids = %v", got)
	}
}
