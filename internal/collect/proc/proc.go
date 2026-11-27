// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

// Package proc collects running processes from the proc file system: their
// executables (including replaced, deleted and memfd ones), replaced or
// deleted libraries, listening sockets and container membership. It only
// reads files below Env.Proc; it does not ptrace, run commands or enter
// namespaces.
package proc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Bounds on the work done per process.
const (
	maxSmallFile   = 64 << 10  // stat, status, cgroup, mountinfo
	maxCmdlineRead = 128 << 10 // bytes of /proc/<pid>/cmdline read
	maxCmdlineOut  = 32 << 10  // bytes of the masked command line kept
	maxMapsRead    = 8 << 20   // bytes of /proc/<pid>/maps read
	maxFDs         = 16384     // fd entries scanned per process
	maxSocketTable = 64 << 20  // bytes read per net/{tcp,udp}* file
)

// clockTicks is USER_HZ, the unit of the starttime field in
// /proc/<pid>/stat. It is 100 on every architecture Linux supports.
const clockTicks = 100

// pfKthread is the PF_KTHREAD bit of the flags field in /proc/<pid>/stat.
const pfKthread = 0x00200000

const deletedSuffix = " (deleted)"

// Collect reads the processes visible through env.Proc. It never fails: data
// it cannot read lowers the coverage and is explained in the reason.
func Collect(ctx context.Context, env *collect.Env) *report.ProcessesSection {
	start := time.Now()
	c := newCollector(env)
	sec := &report.ProcessesSection{SectionMeta: report.SectionMeta{
		Coverage:    report.CoverageFull,
		CollectedAt: start.UTC(),
	}}

	pids, err := listPIDs(c.proc)
	if err != nil {
		sec.Coverage = report.CoverageNone
		sec.Reason = fmt.Sprintf("cannot list processes: %v", err)
		sec.DurationMs = time.Since(start).Milliseconds()
		return sec
	}

	var infos []*procInfo
	for _, pid := range pids {
		if ctx.Err() != nil {
			c.interrupted = true
			break
		}
		if info, ok := c.process(pid); ok {
			infos = append(infos, info)
		}
	}

	unowned := c.listeners(ctx, infos)
	if ctx.Err() != nil {
		c.interrupted = true
	}

	sec.Processes = make([]report.Process, 0, len(infos))
	for _, info := range infos {
		sec.Processes = append(sec.Processes, info.p)
	}
	sec.UnownedPorts = unowned

	if digest, err := sectionDigest(env.Policy.CollectCmdline, infos, unowned); err == nil {
		sec.Digest = digest
	} else {
		c.log.Warn("process digest", "err", err)
	}

	if reasons := c.reasons(len(infos)); len(reasons) > 0 {
		sec.Coverage = report.CoveragePartial
		sec.Reason = strings.Join(reasons, "; ")
	}
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec
}

type collector struct {
	env      *collect.Env
	proc     string
	log      *slog.Logger
	bootTime time.Time
	users    map[int]string
	hidepid  bool
	// hostNetNS is the network namespace link of PID 1, empty when it
	// cannot be read.
	hostNetNS string

	exeDenied     int // executable link unreadable, path guessed from argv[0]
	mapsDenied    int // maps unreadable although the executable was readable
	mapsTruncated int // maps larger than maxMapsRead
	sockDenied    int // network namespace or fd table unreadable
	fdTruncated   int // more than maxFDs open files
	nsUnread      int // network namespaces whose socket tables could not be read
	interrupted   bool
}

// procInfo is a collected process plus the values that are needed later but
// are not part of the report.
type procInfo struct {
	p report.Process
	// startTicks is the raw starttime field. Unlike StartedAt it does not
	// depend on the boot time estimate, so the digest uses it.
	startTicks uint64
	netns      string
	dir        string
	// sockets is false when the fd table should not be scanned (counted
	// already as a degraded process).
	sockets bool
}

func newCollector(env *collect.Env) *collector {
	if env.Cache == nil {
		e := *env
		e.Cache = collect.NewHashCache()
		env = &e
	}
	c := &collector{env: env, proc: env.Proc, log: env.Log}
	if c.proc == "" {
		c.proc = "/proc"
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if bt, err := readBootTime(c.proc); err == nil {
		c.bootTime = bt
	} else {
		c.log.Debug("boot time", "err", err)
	}
	c.users = readPasswd(env.Path("/etc/passwd"))
	if !env.Privileged {
		c.hidepid = hidepidMounted(c.proc)
	}
	if ns, err := os.Readlink(filepath.Join(c.proc, "1", "ns", "net")); err == nil {
		c.hostNetNS = ns
	}
	return c
}

// process collects one process. It returns false for kernel threads, zombies
// and processes that exited during the scan.
func (c *collector) process(pid int) (*procInfo, bool) {
	dir := filepath.Join(c.proc, strconv.Itoa(pid))
	st, err := readStat(dir)
	if err != nil {
		return nil, false
	}
	if st.flags&pfKthread != 0 || st.state == 'Z' || st.state == 'X' {
		return nil, false
	}
	uid, err := readUID(dir)
	if err != nil {
		return nil, false
	}
	args, err := readCmdline(dir)
	if err != nil && gone(err) {
		return nil, false
	}

	info := &procInfo{startTicks: st.startTicks, dir: dir}
	p := &info.p
	p.PID = pid
	p.PPID = st.ppid
	p.UID = uid
	p.User = c.userName(uid)
	if !c.bootTime.IsZero() {
		p.StartedAt = c.bootTime.Add(time.Duration(st.startTicks) * (time.Second / clockTicks))
	}

	target, err := os.Readlink(filepath.Join(dir, "exe"))
	switch {
	case err == nil:
		c.fillExe(dir, target, p)
		libs, mapped, err := c.mappedLibs(dir, p.Exe)
		switch {
		case err == nil:
			p.Libs, p.Mapped = libs, mapped
		case gone(err):
			return nil, false
		case errors.Is(err, errMapsTruncated):
			p.Libs, p.Mapped = libs, mapped
			c.mapsTruncated++
		default:
			c.mapsDenied++
		}
		info.sockets = true
	case gone(err):
		// Kernel thread, zombie or a process that just exited.
		return nil, false
	default:
		if len(args) == 0 {
			return nil, false
		}
		c.exeDenied++
		p.ExeSource = report.ExeFromCmdline
		p.ExeState = report.ExeNormal
		p.Exe = argv0Path(args)
	}

	if c.env.Policy.CollectCmdline {
		p.Cmdline = maskCmdline(args)
	}
	if data, err := readLimited(filepath.Join(dir, "cgroup"), maxSmallFile); err == nil {
		p.ContainerID = containerIDFromCgroup(string(data))
	}
	if ns, err := os.Readlink(filepath.Join(dir, "ns", "mnt")); err == nil {
		p.MountNS = nsInode(ns)
	}
	if ns, err := os.Readlink(filepath.Join(dir, "ns", "net")); err == nil {
		info.netns = ns
		p.OtherNetNS = c.hostNetNS != "" && ns != c.hostNetNS
	} else if info.sockets {
		info.sockets = false
		if !gone(err) {
			c.sockDenied++
		}
	}
	return info, true
}

// nsInode returns the inode of a namespace link target such as
// "mnt:[4026531841]", or zero.
func nsInode(link string) uint64 {
	_, rest, ok := strings.Cut(link, ":[")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (c *collector) userName(uid int) string {
	if name, ok := c.users[uid]; ok {
		return name
	}
	return strconv.Itoa(uid)
}

func (c *collector) reasons(total int) []string {
	var r []string
	if c.interrupted {
		r = append(r, "collection was interrupted before all processes were read")
	}
	if c.hidepid {
		r = append(r, "proc is mounted with hidepid, other users' processes may be hidden")
	}
	if c.exeDenied > 0 {
		r = append(r, fmt.Sprintf("executable unreadable for %d of %d processes: path taken from the command line, "+
			"no hash, no replaced or deleted check, listening sockets without an owner", c.exeDenied, total))
	}
	if c.mapsDenied > 0 {
		r = append(r, fmt.Sprintf("memory mappings unreadable for %d more processes", c.mapsDenied))
	}
	if c.mapsTruncated > 0 {
		r = append(r, fmt.Sprintf("memory mappings of %d processes read only up to %d bytes", c.mapsTruncated, maxMapsRead))
	}
	if c.sockDenied > 0 {
		r = append(r, fmt.Sprintf("open sockets unreadable for %d more processes", c.sockDenied))
	}
	if c.fdTruncated > 0 {
		r = append(r, fmt.Sprintf("open files of %d processes scanned only up to %d entries", c.fdTruncated, maxFDs))
	}
	if c.nsUnread > 0 {
		r = append(r, fmt.Sprintf("socket tables of %d network namespaces unreadable", c.nsUnread))
	}
	return r
}

// digestVersion changes whenever the digest body or the masking rules change,
// so that a probe update re-sends the section.
const digestVersion = 3

// digestProcess is the part of a process that goes into the section digest.
//
// Left out on purpose, because they change between runs for an unchanged set
// of processes:
//   - StartedAt: derived from the boot time in /proc/stat, which moves by a
//     second or so when the clock is adjusted. The raw starttime ticks are
//     used instead; together with the pid they still identify the process.
//   - Cmdline: rewritten at run time by many daemons (postgres, sshd, nginx
//     workers set their titles). Only whether a command line is present is
//     kept, so switching CollectCmdline in the policy re-sends the section.
//
// An exec in the same process keeps pid and start time but changes the
// executable or its hash, so it still changes the digest.
type digestProcess struct {
	PID         int                `json:"pid"`
	PPID        int                `json:"ppid"`
	User        string             `json:"user"`
	UID         int                `json:"uid"`
	Exe         string             `json:"exe"`
	ExeSource   string             `json:"exe_source"`
	ExeState    string             `json:"exe_state"`
	SHA256      string             `json:"sha256"`
	StartTicks  uint64             `json:"start_ticks"`
	HasCmdline  bool               `json:"has_cmdline"`
	Libs        []report.MappedLib `json:"libs"`
	Listen      []report.Listen    `json:"listen"`
	ContainerID string             `json:"container_id"`
	MountNS     uint64             `json:"mount_ns"`
	OtherNetNS  bool               `json:"other_netns"`
}

type digestBody struct {
	Version        int                  `json:"v"`
	CollectCmdline bool                 `json:"collect_cmdline"`
	Processes      []digestProcess      `json:"processes"`
	Unowned        []report.UnownedPort `json:"unowned_ports"`
}

func sectionDigest(collectCmdline bool, infos []*procInfo, unowned []report.UnownedPort) (string, error) {
	body := digestBody{Version: digestVersion, CollectCmdline: collectCmdline, Unowned: unowned}
	body.Processes = make([]digestProcess, 0, len(infos))
	for _, info := range infos {
		p := &info.p
		body.Processes = append(body.Processes, digestProcess{
			PID: p.PID, PPID: p.PPID, User: p.User, UID: p.UID,
			Exe: p.Exe, ExeSource: p.ExeSource, ExeState: p.ExeState, SHA256: p.SHA256,
			StartTicks: info.startTicks, HasCmdline: p.Cmdline != "",
			Libs: p.Libs, Listen: p.Listen, ContainerID: p.ContainerID, MountNS: p.MountNS, OtherNetNS: p.OtherNetNS,
		})
	}
	return report.Digest(body)
}

// listPIDs returns the numeric entries of the proc directory in ascending
// order.
func listPIDs(proc string) ([]int, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	return pids, nil
}

// gone reports whether err means the process (or the entry) no longer exists.
func gone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
