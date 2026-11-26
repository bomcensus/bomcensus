// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

// Version command execution (SECURITY.md 6.6).
//
// A version command runs a file found on the target, which is not trusted.
// It is started through the exec helper (exechelper.go), a re-execution of
// the current binary that restricts itself and then executes the target
// from an inherited file descriptor:
//
//   - only native 64-bit ELF files on a mount of the probe's own mount
//     namespace are executed (not files of other mount namespaces that the
//     probe reaches through /proc/<pid>/exe, such as container processes)
//   - argv is fixed by the detector; the environment holds only the
//     detector's variables; stdin is /dev/null; cwd is /; no descriptor
//     but 0 to 2 survives
//   - its own session and process group, killed as a whole after the
//     timeout and after the command exits
//   - uid/gid nobody without supplementary groups when the probe is root,
//     and a new network namespace where that is permitted
//   - in the helper: rlimits, no_new_privs, ambient and bounding
//     capabilities cleared, all capabilities dropped, a Landlock domain
//     (read and execute only, no access to other processes) where the
//     kernel has Landlock, and a seccomp filter of its own
//     (internal/sandbox CommandRules) on top of the probe's
//   - stdout and stderr captured separately, each truncated at 64 KiB

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/bomcensus/bomcensus/internal/report"
)

// execLimits bound one version command.
type execLimits struct {
	Timeout      time.Duration
	CPUSeconds   uint64
	AddressSpace uint64 // bytes
	NoFile       uint64
	// NProcMargin is how many more tasks the command may create than its
	// user already runs (RLIMIT_NPROC counts all tasks of the user).
	NProcMargin uint64
	OutputLimit int // bytes per stream
}

var defaultExecLimits = execLimits{
	Timeout:      10 * time.Second,
	CPUSeconds:   10,
	AddressSpace: 2 << 30,
	NoFile:       64,
	NProcMargin:  64,
	OutputLimit:  64 << 10,
}

// nobodyID is the uid and gid commands run as when the probe is root.
const nobodyID = 65534

// execResult is cached per file and detector.
type execResult struct {
	// Ran is true when the command was executed and exited by itself.
	Ran    bool                  `json:"ran"`
	Output *report.VersionOutput `json:"out,omitempty"`
	Err    string                `json:"err,omitempty"`
}

// versionCommand runs the version command of d for the open file f, whose
// logical path is logical, or returns the cached result for this file.
func (c *collector) versionCommand(ctx context.Context, d *Detector, logical string, f *os.File, fi os.FileInfo) execResult {
	key := fmt.Sprintf("artifact.exec.v2.%s.u%d", d.ID, os.Geteuid())
	var res execResult
	if c.env.Cache.Extra(fi, key, &res) {
		return res
	}
	argv := append([]string{logical}, d.Exec...)
	env := make([]string, 0, len(d.Env))
	for _, e := range d.Env {
		env = append(env, e.Name+"="+parentDir(logical, e.Up))
	}
	lim := c.exec
	if d.AddressSpaceMB > 0 {
		lim.AddressSpace = uint64(d.AddressSpaceMB) << 20
	}
	if err := executable(f); err != nil {
		res = execResult{Err: "not executed: " + err.Error()}
		c.log.Debug("version command", "path", logical, "detector", d.ID, "err", res.Err)
		c.env.Cache.SetExtra(fi, key, res)
		return res
	}
	res = runVersion(ctx, f, argv, env, lim)
	if ctx.Err() != nil {
		// Cancelled from outside: not a property of the file.
		return res
	}
	if now, err := f.Stat(); err != nil || changedSince(fi, now) {
		// The output may not belong to the content that was hashed.
		return execResult{Err: "file changed while it was inspected"}
	}
	if !res.Ran {
		c.log.Debug("version command", "path", logical, "detector", d.ID, "err", res.Err)
	}
	c.env.Cache.SetExtra(fi, key, res)
	return res
}

// runVersion executes exe with argv and env under the limits.
func runVersion(ctx context.Context, exe *os.File, argv, env []string, lim execLimits) execResult {
	asNobody := os.Geteuid() == 0
	uid := os.Getuid()
	if asNobody {
		uid = nobodyID
	}
	margin := lim.NProcMargin
	if !initPIDNamespace("/proc") {
		// RLIMIT_NPROC counts the user's tasks in every PID namespace,
		// and /proc shows only those of its own.
		margin = max(margin, hiddenTasksMargin)
	}
	nproc := countTasks("/proc", uid) + margin
	res, err := startVersion(ctx, exe, argv, env, lim, nproc, asNobody, asNobody)
	if err != nil && asNobody && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL)) {
		// A new network namespace is not permitted here (for example in a
		// container without CAP_SYS_ADMIN).
		res, err = startVersion(ctx, exe, argv, env, lim, nproc, asNobody, false)
	}
	if err != nil {
		return execResult{Err: err.Error()}
	}
	return res
}

// startVersion returns an error only when the helper could not be started.
func startVersion(ctx context.Context, exe *os.File, argv, env []string, lim execLimits, nproc uint64, asNobody, newNet bool) (execResult, error) {
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	status, statusW, err := os.Pipe()
	if err != nil {
		return execResult{}, err
	}
	defer status.Close()

	args := []string{helperArg,
		strconv.FormatUint(lim.CPUSeconds, 10),
		strconv.FormatUint(lim.AddressSpace, 10),
		strconv.FormatUint(lim.NoFile, 10),
		strconv.FormatUint(nproc, 10),
		"--"}
	cmd := exec.CommandContext(ctx, "/proc/self/exe", append(args, argv...)...)
	cmd.Args[0] = "bomcensus-exec-helper"
	cmd.Env = append([]string{}, env...) // never nil: nil inherits ours
	cmd.Dir = "/"
	stdout := &capped{limit: lim.OutputLimit}
	stderr := &capped{limit: lim.OutputLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.ExtraFiles = []*os.File{exe, statusW} // fd 3 and 4 in the helper
	// A new session: its own process group, and no controlling terminal
	// that the command could open or inject input into.
	attr := &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if asNobody {
		attr.Credential = &syscall.Credential{Uid: nobodyID, Gid: nobodyID, Groups: []uint32{}}
	}
	if newNet {
		attr.Cloneflags = syscall.CLONE_NEWNET
	}
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second

	err = cmd.Start()
	statusW.Close()
	if err != nil {
		return execResult{}, err
	}
	pid := cmd.Process.Pid
	// The helper writes here only if it fails before the target runs; a
	// successful exec closes the descriptor.
	msg, _ := io.ReadAll(io.LimitReader(status, 4096))
	waitExited(pid)
	_ = syscall.Kill(-pid, syscall.SIGKILL) // anything the command left behind
	_ = cmd.Wait()

	switch {
	case len(msg) > 0:
		return execResult{Err: "exec helper: " + string(msg)}, nil
	case ctx.Err() != nil:
		return execResult{Err: "timed out after " + lim.Timeout.String()}, nil
	case cmd.ProcessState == nil:
		return execResult{Err: "no exit status"}, nil
	}
	return execResult{Ran: true, Output: &report.VersionOutput{
		Command:   argv,
		Stdout:    stdout.buf.String(),
		Stderr:    stderr.buf.String(),
		ExitCode:  exitCode(cmd.ProcessState),
		Truncated: stdout.truncated || stderr.truncated,
	}}, nil
}

// exitCode is the exit status, or 128 plus the signal number.
func exitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// waitExited blocks until pid has exited without reaping it, so that its
// process group id cannot be reused before the group is killed.
func waitExited(pid int) {
	const (
		pPID    = 1
		wEXITED = 0x4
		wNOWAIT = 0x1000000
	)
	var info [128]byte // siginfo_t
	for {
		_, _, e := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), wEXITED|wNOWAIT, 0, 0)
		if e != syscall.EINTR {
			return
		}
	}
}

// capped keeps the first limit bytes written and discards the rest.
type capped struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *capped) Write(p []byte) (int, error) {
	if room := w.limit - w.buf.Len(); room < len(p) {
		w.truncated = true
		if room > 0 {
			w.buf.Write(p[:room])
		}
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// countTasks returns the number of tasks whose real uid is uid.
func countTasks(proc string, uid int) uint64 {
	dirs, err := os.ReadDir(proc)
	if err != nil {
		return 0
	}
	want := strconv.Itoa(uid)
	var n uint64
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		f, err := os.Open(filepath.Join(proc, d.Name(), "status"))
		if err != nil {
			continue
		}
		var mine bool
		var threads uint64
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				fields := strings.Fields(v)
				mine = len(fields) > 0 && fields[0] == want
			} else if v, ok := strings.CutPrefix(line, "Threads:"); ok {
				threads, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			}
		}
		f.Close()
		if mine {
			n += max(threads, 1)
		}
	}
	return n
}

// nativeMachine is the ELF machine of the probe's architecture.
var nativeMachine = map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]

// executable checks that f may be executed as a version command: a 64-bit
// ELF file of the probe's architecture (anything else would fail in the
// seccomp architecture check, or run through an emulator registered with
// binfmt_misc), on a mount of the probe's own mount namespace. A file of
// a container process reached through /proc/<pid>/exe is on a mount of the
// container's namespace and is identified by static extraction only.
func executable(f *os.File) error {
	var hdr [20]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return fmt.Errorf("read ELF header: %w", err)
	}
	machine := elf.Machine(binary.LittleEndian.Uint16(hdr[18:]))
	if string(hdr[:4]) != elf.ELFMAG || elf.Class(hdr[elf.EI_CLASS]) != elf.ELFCLASS64 ||
		elf.Data(hdr[elf.EI_DATA]) != elf.ELFDATA2LSB || nativeMachine == 0 || machine != nativeMachine {
		return fmt.Errorf("not a native 64-bit ELF file (class %d, machine %v)", hdr[elf.EI_CLASS], machine)
	}
	id, err := mountID(f)
	if err != nil {
		return err
	}
	own, err := ownMounts()
	if err != nil {
		return err
	}
	if !own[id] {
		return fmt.Errorf("file is on mount %d, not in the probe's mount namespace", id)
	}
	return nil
}

// mountID returns the id of the mount that holds f.
func mountID(f *os.File) (int, error) {
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		return 0, err
	}
	if v := procField(string(b), "mnt_id"); v != "" {
		return strconv.Atoi(v)
	}
	return 0, errors.New("no mnt_id in fdinfo")
}

// ownMounts returns the ids of the mounts in the probe's mount namespace
// that are reachable from its root.
func ownMounts() (map[int]bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids := map[int]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		first, _, _ := strings.Cut(sc.Text(), " ")
		if id, err := strconv.Atoi(first); err == nil {
			ids[id] = true
		}
	}
	return ids, sc.Err()
}

// changedSince reports whether the file was written to or replaced in
// place between the two stats: size, modification or change time differ.
// The change time cannot be set by the file's owner.
func changedSince(before, after os.FileInfo) bool {
	a, ok1 := before.Sys().(*syscall.Stat_t)
	b, ok2 := after.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return true
	}
	return a.Size != b.Size || a.Mtim != b.Mtim || a.Ctim != b.Ctim || a.Ino != b.Ino || a.Dev != b.Dev
}

// hiddenTasksMargin is the process limit margin where /proc does not show
// every task of the user: tasks in other PID namespaces count against
// RLIMIT_NPROC but cannot be counted. A command cannot create processes
// (internal/sandbox CommandRules), so the limit only bounds its threads.
const hiddenTasksMargin = 4096

// initPIDNamespace reports whether the proc file system at proc belongs to
// the initial PID namespace, the only one in which kernel threads, such as
// kthreadd with pid 2, are visible.
func initPIDNamespace(proc string) bool {
	b, err := os.ReadFile(filepath.Join(proc, "2", "status"))
	return err == nil && procField(string(b), "Name") == "kthreadd"
}
