// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect/artifact"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Bounds of the open-jar detection.
const (
	maxJVMs           = 256
	maxFDsPerJVM      = 16384
	maxOpenJars       = 8192
	maxJVMExeNameSize = 32
)

// jvmNames are executable names of Java virtual machines.
var jvmNames = map[string]bool{"java": true, "javaw": true, "jsvc": true}

// dropSelf removes the probe's own process from the section. Its pid
// changes with every run and would change the digest every time. The
// digest is then recomputed over the remaining processes.
func dropSelf(sec *report.ProcessesSection, procDir string, log *slog.Logger) {
	if procDir != "/proc" {
		return
	}
	self := os.Getpid()
	idx := -1
	for i := range sec.Processes {
		if sec.Processes[i].PID == self {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	sec.Processes = append(sec.Processes[:idx:idx], sec.Processes[idx+1:]...)
	if sec.Digest == "" {
		return
	}
	if d, err := processDigest(sec, readBootTime(procDir)); err == nil {
		sec.Digest = d
	} else {
		log.Warn("process digest", "err", err)
	}
}

type digestProcess struct {
	PID         int                `json:"pid"`
	PPID        int                `json:"ppid"`
	User        string             `json:"user"`
	UID         int                `json:"uid"`
	Exe         string             `json:"exe"`
	ExeSource   string             `json:"exe_source"`
	ExeState    string             `json:"exe_state"`
	SHA256      string             `json:"sha256"`
	Start       int64              `json:"start"`
	HasCmdline  bool               `json:"has_cmdline"`
	Libs        []report.MappedLib `json:"libs"`
	Listen      []report.Listen    `json:"listen"`
	ContainerID string             `json:"container_id"`
}

type processDigestBody struct {
	Version   int                  `json:"v"`
	Processes []digestProcess      `json:"processes"`
	Unowned   []report.UnownedPort `json:"unowned_ports"`
}

// processDigest covers the same fields as the process collector's digest.
// Start times are taken relative to the boot time, in clock ticks, so that
// a drifting boot time estimate does not change the digest.
func processDigest(sec *report.ProcessesSection, boot time.Time) (string, error) {
	body := processDigestBody{Version: 1, Unowned: sec.UnownedPorts}
	body.Processes = make([]digestProcess, 0, len(sec.Processes))
	for i := range sec.Processes {
		p := &sec.Processes[i]
		start := p.StartedAt.Unix()
		if !boot.IsZero() {
			start = int64(p.StartedAt.Sub(boot) / (10 * time.Millisecond))
		}
		body.Processes = append(body.Processes, digestProcess{
			PID: p.PID, PPID: p.PPID, User: p.User, UID: p.UID,
			Exe: p.Exe, ExeSource: p.ExeSource, ExeState: p.ExeState, SHA256: p.SHA256,
			Start: start, HasCmdline: p.Cmdline != "",
			Libs: p.Libs, Listen: p.Listen, ContainerID: p.ContainerID,
		})
	}
	return report.Digest(body)
}

// readBootTime returns btime from <proc>/stat, or the zero time.
func readBootTime(procDir string) time.Time {
	data, err := readSmall(filepath.Join(procDir, "stat"), 1<<20)
	if err != nil {
		return time.Time{}
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return time.Unix(sec, 0).UTC()
			}
		}
	}
	return time.Time{}
}

func readSmall(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// runningExes lists the executables of the collected processes whose path
// was read from /proc.
func runningExes(sec *report.ProcessesSection) []artifact.RunningExe {
	if sec == nil {
		return nil
	}
	out := make([]artifact.RunningExe, 0, len(sec.Processes))
	for _, p := range sec.Processes {
		if p.ExeSource != report.ExeFromProc || p.Exe == "" {
			continue
		}
		out = append(out, artifact.RunningExe{PID: p.PID, Path: p.Exe, State: p.ExeState})
	}
	return out
}

// rootKey identifies the root directory of a process.
type rootKey struct{ dev, ino uint64 }

func rootKeyOf(p string) (rootKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return rootKey{}, false
	}
	return rootKey{dev: uint64(st.Dev), ino: st.Ino}, true
}

// openFileIndex maps a process root to the jars its JVMs hold open, by the
// path the process sees.
type openFileIndex map[rootKey]map[string][]int

// forRoot returns the open jars of processes whose root is the directory
// root (a path the probe can open).
func (ix openFileIndex) forRoot(root string) map[string][]int {
	if len(ix) == 0 {
		return nil
	}
	k, ok := rootKeyOf(root)
	if !ok {
		return nil
	}
	return ix[k]
}

// openJars lists the Java archives that running JVMs hold open. Paths are
// those the process sees, which inside a container are relative to the
// container root.
func openJars(procDir string, sec *report.ProcessesSection) openFileIndex {
	if sec == nil {
		return nil
	}
	ix := openFileIndex{}
	jvms, jars := 0, 0
	for _, p := range sec.Processes {
		if p.ExeSource != report.ExeFromProc || !isJVM(p.Exe) {
			continue
		}
		if jvms == maxJVMs || jars >= maxOpenJars {
			break
		}
		jvms++
		dir := filepath.Join(procDir, strconv.Itoa(p.PID))
		k, ok := rootKeyOf(filepath.Join(dir, "root"))
		if !ok {
			continue
		}
		for _, j := range processJars(filepath.Join(dir, "fd"), maxOpenJars-jars) {
			m := ix[k]
			if m == nil {
				m = map[string][]int{}
				ix[k] = m
			}
			if pids := m[j]; len(pids) == 0 || pids[len(pids)-1] != p.PID {
				m[j] = append(pids, p.PID)
				jars++
			}
		}
	}
	return ix
}

func isJVM(exe string) bool {
	base := path.Base(exe)
	return len(base) <= maxJVMExeNameSize && jvmNames[base]
}

// processJars returns the Java archives among the open files in fdDir.
func processJars(fdDir string, limit int) []string {
	d, err := os.Open(fdDir)
	if err != nil {
		return nil
	}
	defer d.Close()
	var out []string
	seen := 0
	for seen < maxFDsPerJVM && len(out) < limit {
		names, err := d.Readdirnames(256)
		for _, n := range names {
			seen++
			target, err := os.Readlink(filepath.Join(fdDir, n))
			if err != nil || !strings.HasPrefix(target, "/") || strings.HasSuffix(target, " (deleted)") {
				continue
			}
			switch strings.ToLower(path.Ext(target)) {
			case ".jar", ".war", ".ear":
				out = append(out, path.Clean(target))
			}
		}
		if err != nil {
			break
		}
	}
	return out
}
