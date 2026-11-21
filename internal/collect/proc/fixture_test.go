// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package proc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// fakeProc builds a proc tree and a root file system under a temp directory.
type fakeProc struct {
	t    *testing.T
	proc string
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	base := t.TempDir()
	f := &fakeProc{t: t, proc: filepath.Join(base, "proc"), root: filepath.Join(base, "root")}
	f.write(filepath.Join(f.proc, "stat"), "cpu  1 2 3 4\nbtime 1700000000\nprocesses 10\n")
	f.write(filepath.Join(f.root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n")
	return f
}

func (f *fakeProc) write(path, content string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) link(path, target string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		f.t.Fatal(err)
	}
}

type fakeProcess struct {
	pid, ppid, uid int
	comm           string
	flags          uint64
	startTicks     uint64
	cmdline        []string
	exe            string // symlink target; empty for none
	cgroup         string
	maps           string
	netns          string
	fds            map[int]string // fd -> link target
}

func (f *fakeProc) add(p fakeProcess) string {
	dir := filepath.Join(f.proc, fmt.Sprint(p.pid))
	f.write(filepath.Join(dir, "stat"), fmt.Sprintf("%d (%s) S %d %d %d 0 -1 %d 0 0 0 0 0 0 0 0 20 0 1 0 %d 1000 10 18446744073709551615\n",
		p.pid, p.comm, p.ppid, p.pid, p.pid, p.flags, p.startTicks))
	f.write(filepath.Join(dir, "status"), fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n", p.comm, p.uid, p.uid, p.uid, p.uid))
	var cmd string
	for _, a := range p.cmdline {
		cmd += a + "\x00"
	}
	f.write(filepath.Join(dir, "cmdline"), cmd)
	f.write(filepath.Join(dir, "cgroup"), p.cgroup)
	f.write(filepath.Join(dir, "maps"), p.maps)
	if p.exe != "" {
		f.link(filepath.Join(dir, "exe"), p.exe)
	}
	f.link(filepath.Join(dir, "root"), f.root)
	if p.netns != "" {
		f.link(filepath.Join(dir, "ns", "net"), p.netns)
	}
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	for fd, target := range p.fds {
		f.link(filepath.Join(dir, "fd", fmt.Sprint(fd)), target)
	}
	return dir
}

func (f *fakeProc) env() *collect.Env {
	return &collect.Env{
		Root:   f.root,
		Proc:   f.proc,
		Policy: report.DefaultPolicy(),
		Cache:  collect.NewHashCache(),
		Log:    slog.New(slog.DiscardHandler),
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func sockLine(local, remote, state string, uid int, inode uint64) string {
	return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n",
		local, remote, state, uid, inode)
}

func buildFixture(t *testing.T) (*fakeProc, map[string]string) {
	f := newFakeProc(t)
	containerID := "3f4e2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f"

	// Files of the root file system.
	appContent := "app binary v2"
	f.write(filepath.Join(f.root, "usr", "bin", "app"), appContent)
	f.write(filepath.Join(f.root, "usr", "bin", "replaced"), "new version")
	f.write(filepath.Join(f.root, "usr", "lib", "libold.so"), "new lib")
	libContent := "deleted lib content"
	f.write(filepath.Join(f.root, "..", "libgone.bin"), libContent)

	hostNS := "net:[4026531840]"
	podNS := "net:[4026532999]"

	// pid 1: normal process, host namespace.
	f.add(fakeProcess{
		pid: 1, ppid: 0, uid: 0, comm: "init", startTicks: 1,
		cmdline: []string{"/sbin/init"},
		exe:     filepath.Join(f.root, "usr", "bin", "app"),
		cgroup:  "0::/init.scope\n",
		netns:   hostNS,
	})
	// pid 2: kernel thread.
	f.add(fakeProcess{pid: 2, comm: "kthreadd", flags: pfKthread, startTicks: 1})
	// pid 3: no exe, empty command line (exited or kernel worker).
	f.add(fakeProcess{pid: 3, ppid: 2, comm: "kworker/0:0", startTicks: 2})

	// pid 100: deleted executable with replaced and deleted libraries, two
	// listening sockets one of which is shared with pid 200.
	dir100 := f.add(fakeProcess{
		pid: 100, ppid: 1, uid: 1000, comm: "my (weird) proc", startTicks: 250,
		cmdline: []string{"/usr/bin/gone", "--password=hunter2", "--listen", ":3306"},
		exe:     "/usr/bin/gone (deleted)",
		cgroup:  "12:memory:/docker/" + containerID + "\n0::/system.slice/docker-" + containerID + ".scope\n",
		maps: "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/gone (deleted)\n" +
			"7f0000000000-7f0000100000 r-xp 00000000 08:02 999999999999 /usr/lib/libold.so (deleted)\n" +
			"7f0000200000-7f0000300000 r--p 00000000 08:02 6666 /usr/lib/libdata.so (deleted)\n" +
			"7f0000400000-7f0000500000 r-xp 00000000 08:02 7777 /usr/lib/libgone.so (deleted)\n" +
			"7f0000600000-7f0000700000 r-xp 00000000 00:01 8888 /memfd:jit (deleted)\n" +
			"7f0000800000-7f0000900000 r-xp 00001000 08:02 7777 /usr/lib/libgone.so (deleted)\n" +
			"7f0000a00000-7f0000b00000 r-xp 00000000 08:02 4242 /opt/my app/lib x.so (deleted)\n" +
			"7f0000c00000-7f0000d00000 r-xp 00000000 08:02 1234 /usr/lib/libc.so.6\n",
		netns: hostNS,
		fds:   map[int]string{0: "/dev/null", 3: "socket:[1001]", 4: "pipe:[55]", 5: "socket:[1009]"},
	})
	f.link(filepath.Join(dir100, "map_files", "7f0000400000-7f0000500000"), filepath.Join(f.root, "..", "libgone.bin"))
	f.write(filepath.Join(dir100, "net", "tcp"), tcpHeader+
		sockLine("0100007F:0CEA", "00000000:0000", "0A", 1000, 1001)+ // 127.0.0.1:3306, pids 100 and 200
		sockLine("0100007F:0CEA", "0100007F:D431", "01", 1000, 1009)+ // established, ignored
		sockLine("00000000:0050", "00000000:0000", "0A", 33, 1003)) // 0.0.0.0:80, unowned
	f.write(filepath.Join(dir100, "net", "tcp6"), tcpHeader+
		sockLine("0000000000000000FFFF00000100007F:1F90", "00000000000000000000000000000000:0000", "0A", 1000, 1002)+ // 127.0.0.1:8080, pid 200
		sockLine("00000000000000000000000001000000:1F91", "00000000000000000000000000000000:0000", "0A", 0, 1005)+ // ::1:8081, unowned
		sockLine("00000000000000000000000000000000:0016", "00000000000000000000000000000000:0000", "0A", 0, 1006)) // :::22, pid 1? no: unowned
	f.write(filepath.Join(dir100, "net", "udp"), tcpHeader+
		sockLine("00000000:0044", "00000000:0000", "07", 0, 1007)+ // 0.0.0.0:68, pid 200
		sockLine("0100007F:0035", "0100007F:1234", "01", 0, 1008)) // connected, ignored

	// pid 200: forked worker of 100 with a replaced executable.
	f.add(fakeProcess{
		pid: 200, ppid: 100, uid: 1000, comm: "worker", startTicks: 300,
		cmdline: []string{"/usr/bin/replaced", "--worker"},
		exe:     "/usr/bin/replaced (deleted)",
		netns:   hostNS,
		fds:     map[int]string{3: "socket:[1001]", 7: "socket:[1002]", 8: "socket:[1007]", 9: "socket:[1002]"},
	})

	// pid 300: memfd executable in a pod network namespace, cgroup v2 CRI.
	dir300 := f.add(fakeProcess{
		pid: 300, ppid: 1, uid: 33, comm: "x", startTicks: 400,
		cmdline: []string{"x"},
		exe:     "/memfd:payload (deleted)",
		cgroup:  "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b.slice/cri-containerd-" + containerID + ".scope\n",
		netns:   podNS,
		fds:     map[int]string{3: "socket:[2001]"},
	})
	f.write(filepath.Join(dir300, "net", "tcp"), tcpHeader+
		sockLine("00000000:2328", "00000000:0000", "0A", 33, 2001)) // 0.0.0.0:9000

	// pid 400: executable link unreadable (a regular file makes readlink
	// fail with EINVAL, standing in for EACCES).
	dir400 := f.add(fakeProcess{
		pid: 400, ppid: 1, uid: 0, comm: "sshd", startTicks: 500,
		cmdline: []string{"/usr/sbin/sshd", "-D"},
	})
	f.write(filepath.Join(dir400, "exe"), "")
	// pid 401: same, relative argv[0].
	dir401 := f.add(fakeProcess{
		pid: 401, ppid: 1, uid: 4242, comm: "nginx", startTicks: 501,
		cmdline: []string{"nginx: worker process"},
	})
	f.write(filepath.Join(dir401, "exe"), "")

	return f, map[string]string{
		"container": containerID,
		"app":       sha256Hex([]byte(appContent)),
		"lib":       sha256Hex([]byte(libContent)),
	}
}

func findProc(sec *report.ProcessesSection, pid int) *report.Process {
	for i := range sec.Processes {
		if sec.Processes[i].PID == pid {
			return &sec.Processes[i]
		}
	}
	return nil
}

func TestCollectFixture(t *testing.T) {
	f, want := buildFixture(t)
	sec := Collect(context.Background(), f.env())

	var pids []int
	for _, p := range sec.Processes {
		pids = append(pids, p.PID)
	}
	if !slices.Equal(pids, []int{1, 100, 200, 300, 400, 401}) {
		t.Fatalf("pids %v", pids)
	}
	boot := time.Unix(1700000000, 0).UTC()

	p1 := findProc(sec, 1)
	if p1.User != "root" || p1.ExeState != report.ExeNormal || p1.ExeSource != report.ExeFromProc ||
		p1.SHA256 != want["app"] || p1.ContainerID != "" || len(p1.Listen) != 0 {
		t.Errorf("pid 1: %+v", p1)
	}

	p100 := findProc(sec, 100)
	if p100.PPID != 1 || p100.User != "app" || p100.UID != 1000 {
		t.Errorf("pid 100 identity: %+v", p100)
	}
	if p100.Exe != "/usr/bin/gone" || p100.ExeState != report.ExeDeleted || p100.SHA256 != "" {
		t.Errorf("pid 100 exe: %q %q %q", p100.Exe, p100.ExeState, p100.SHA256)
	}
	if p100.Cmdline != "/usr/bin/gone --password=**** --listen :3306" {
		t.Errorf("pid 100 cmdline: %q", p100.Cmdline)
	}
	if !p100.StartedAt.Equal(boot.Add(2500 * time.Millisecond)) {
		t.Errorf("pid 100 started %v", p100.StartedAt)
	}
	if p100.ContainerID != want["container"] {
		t.Errorf("pid 100 container %q", p100.ContainerID)
	}
	wantLibs := []report.MappedLib{
		{Path: "/opt/my app/lib x.so", State: report.ExeDeleted},
		{Path: "/usr/lib/libgone.so", State: report.ExeDeleted, SHA256: want["lib"]},
		{Path: "/usr/lib/libold.so", State: report.ExeReplaced},
	}
	if !slices.Equal(p100.Libs, wantLibs) {
		t.Errorf("pid 100 libs:\n got %+v\nwant %+v", p100.Libs, wantLibs)
	}
	if !slices.Equal(p100.Listen, []report.Listen{{Proto: "tcp", Address: "127.0.0.1", Port: 3306}}) {
		t.Errorf("pid 100 listen %+v", p100.Listen)
	}

	p200 := findProc(sec, 200)
	if p200.ExeState != report.ExeReplaced || p200.Exe != "/usr/bin/replaced" {
		t.Errorf("pid 200 exe: %q %q", p200.Exe, p200.ExeState)
	}
	wantListen := []report.Listen{
		{Proto: "tcp", Address: "127.0.0.1", Port: 3306},
		{Proto: "tcp", Address: "127.0.0.1", Port: 8080},
		{Proto: "udp", Address: "0.0.0.0", Port: 68},
	}
	if !slices.Equal(p200.Listen, wantListen) {
		t.Errorf("pid 200 listen:\n got %+v\nwant %+v", p200.Listen, wantListen)
	}

	p300 := findProc(sec, 300)
	if p300.ExeState != report.ExeMemfd || p300.Exe != "/memfd:payload" || p300.User != "33" ||
		p300.ContainerID != want["container"] {
		t.Errorf("pid 300: %+v", p300)
	}
	if !slices.Equal(p300.Listen, []report.Listen{{Proto: "tcp", Address: "0.0.0.0", Port: 9000}}) {
		t.Errorf("pid 300 listen %+v", p300.Listen)
	}

	p400 := findProc(sec, 400)
	if p400.ExeSource != report.ExeFromCmdline || p400.Exe != "/usr/sbin/sshd" || p400.ExeState != report.ExeNormal || p400.SHA256 != "" {
		t.Errorf("pid 400: %+v", p400)
	}
	p401 := findProc(sec, 401)
	if p401.ExeSource != report.ExeFromCmdline || p401.Exe != "" || p401.Cmdline != "nginx: worker process" || p401.User != "4242" {
		t.Errorf("pid 401: %+v", p401)
	}

	wantUnowned := []report.UnownedPort{
		{Listen: report.Listen{Proto: "tcp", Address: "::", Port: 22}, UID: 0},
		{Listen: report.Listen{Proto: "tcp", Address: "0.0.0.0", Port: 80}, UID: 33},
		{Listen: report.Listen{Proto: "tcp", Address: "::1", Port: 8081}, UID: 0},
	}
	if !slices.Equal(sec.UnownedPorts, wantUnowned) {
		t.Errorf("unowned:\n got %+v\nwant %+v", sec.UnownedPorts, wantUnowned)
	}

	if sec.Coverage != report.CoveragePartial || !strings.Contains(sec.Reason, "executable unreadable for 2 of 6 processes") {
		t.Errorf("coverage %q reason %q", sec.Coverage, sec.Reason)
	}
	if sec.Digest == "" {
		t.Error("no digest")
	}
}

func TestCollectDigest(t *testing.T) {
	f, _ := buildFixture(t)
	first := Collect(context.Background(), f.env())

	// Same set of processes: same digest.
	if again := Collect(context.Background(), f.env()); again.Digest != first.Digest {
		t.Error("digest changed without a change")
	}

	// Boot time estimate moved by a second: same digest.
	f.write(filepath.Join(f.proc, "stat"), "btime 1700000001\n")
	moved := Collect(context.Background(), f.env())
	if moved.Digest != first.Digest {
		t.Error("digest depends on the boot time")
	}
	if findProc(moved, 100).StartedAt.Equal(findProc(first, 100).StartedAt) {
		t.Error("boot time change not applied")
	}

	// Rewritten process title: same digest.
	f.write(filepath.Join(f.proc, "200", "cmdline"), "worker: idle")
	if retitled := Collect(context.Background(), f.env()); retitled.Digest != first.Digest {
		t.Error("digest depends on the process title")
	}

	// Command lines switched off by policy: different digest, no command lines.
	env := f.env()
	env.Policy.CollectCmdline = false
	off := Collect(context.Background(), env)
	if off.Digest == first.Digest {
		t.Error("policy change did not change the digest")
	}
	for _, p := range off.Processes {
		if p.Cmdline != "" {
			t.Errorf("pid %d has a command line with collection off", p.PID)
		}
	}

	// A new listening socket: different digest.
	f.write(filepath.Join(f.proc, "300", "net", "tcp"), tcpHeader+
		sockLine("00000000:2328", "00000000:0000", "0A", 33, 2001)+
		sockLine("00000000:2329", "00000000:0000", "0A", 33, 2002))
	if more := Collect(context.Background(), f.env()); more.Digest == first.Digest {
		t.Error("new socket did not change the digest")
	}
}

func TestCollectCancelled(t *testing.T) {
	f, _ := buildFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sec := Collect(ctx, f.env())
	if sec.Coverage != report.CoveragePartial || !strings.Contains(sec.Reason, "interrupted") {
		t.Errorf("coverage %q reason %q", sec.Coverage, sec.Reason)
	}
}

func TestCollectNoProc(t *testing.T) {
	env := collect.NewEnv()
	env.Proc = filepath.Join(t.TempDir(), "missing")
	sec := Collect(context.Background(), env)
	if sec.Coverage != report.CoverageNone || sec.Reason == "" {
		t.Errorf("coverage %q reason %q", sec.Coverage, sec.Reason)
	}
}
