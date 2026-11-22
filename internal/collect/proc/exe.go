// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package proc

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/bomcensus/bomcensus/internal/report"
)

var errMapsTruncated = errors.New("proc: maps truncated")

// fillExe sets the executable fields from the target of /proc/<pid>/exe.
func (c *collector) fillExe(dir, target string, p *report.Process) {
	p.ExeSource = report.ExeFromProc
	path, deleted := strings.CutSuffix(target, deletedSuffix)
	p.Exe = path
	switch {
	case strings.HasPrefix(path, "/memfd:"):
		p.ExeState = report.ExeMemfd
	case deleted:
		running, err := os.Stat(filepath.Join(dir, "exe"))
		p.ExeState = classifyUnlinked(dir, path, func(now os.FileInfo) bool {
			return err == nil && sameFile(running, now)
		})
	default:
		p.ExeState = report.ExeNormal
	}

	f, err := os.Open(filepath.Join(dir, "exe"))
	if err != nil {
		c.log.Debug("open exe", "pid", p.PID, "err", err)
		return
	}
	defer f.Close()
	if sum, err := c.env.Cache.SHA256File(f); err == nil {
		p.SHA256 = sum
	} else {
		c.log.Debug("hash exe", "pid", p.PID, "err", err)
	}
}

// classifyUnlinked decides what happened to a file that the kernel reports as
// deleted. path is looked up through /proc/<pid>/root, so processes in other
// mount namespaces (containers) are checked against their own file system.
//
// Only files with the " (deleted)" mark are classified. Without the mark the
// file is still linked at that path, and the path is not looked up: for a
// chrooted process the link shows the path from the reader's root, which
// does not resolve below /proc/<pid>/root.
//
// When the path cannot be inspected at all, the result is ExeDeleted: the
// original file is known to be unlinked and no replacement could be seen.
func classifyUnlinked(dir, path string, same func(now os.FileInfo) bool) string {
	// Lstat, so that a symbolic link placed at the path is not followed
	// outside the process root.
	now, err := os.Lstat(filepath.Join(dir, "root", path))
	if err != nil {
		return report.ExeDeleted
	}
	if same(now) {
		return report.ExeNormal
	}
	return report.ExeReplaced
}

func sameFile(a, b os.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

func inodeOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}

// mapping is one line of /proc/<pid>/maps.
type mapping struct {
	addr  string // "start-end", the name of the map_files entry
	exec  bool
	inode uint64
	path  string
}

// parseMapsLine splits "start-end perms offset dev inode   path". The path
// is everything after the inode and may contain spaces.
func parseMapsLine(line string) (mapping, bool) {
	var f [5]string
	rest := line
	for i := range f {
		rest = strings.TrimLeft(rest, " ")
		j := strings.IndexByte(rest, ' ')
		if j < 0 {
			if i != len(f)-1 {
				return mapping{}, false
			}
			f[i], rest = rest, ""
			break
		}
		f[i], rest = rest[:j], rest[j:]
	}
	if len(f[1]) < 3 || !strings.Contains(f[0], "-") {
		return mapping{}, false
	}
	ino, err := strconv.ParseUint(f[4], 10, 64)
	if err != nil {
		return mapping{}, false
	}
	return mapping{addr: f[0], exec: f[1][2] == 'x', inode: ino, path: strings.TrimLeft(rest, " ")}, true
}

// Mappings with the deleted mark that are not files someone installed:
// anonymous memory files (JIT code), System V shared memory and shared
// anonymous mappings.
var unlinkedNoise = []string{"/memfd:", "/SYSV", "/dev/zero", "/anon_hugepage"}

// mappedLibs returns the executable file mappings of a process whose file was
// replaced or deleted. The executable itself is reported on the process and
// left out here.
func (c *collector) mappedLibs(dir, exe string) ([]report.MappedLib, error) {
	f, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lr := &io.LimitedReader{R: f, N: maxMapsRead}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)

	var libs []report.MappedLib
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasSuffix(line, deletedSuffix) {
			continue
		}
		m, ok := parseMapsLine(line)
		if !ok || !m.exec {
			continue
		}
		path := strings.TrimSuffix(m.path, deletedSuffix)
		if !strings.HasPrefix(path, "/") || path == exe || seen[path] || hasAnyPrefix(path, unlinkedNoise) {
			continue
		}
		seen[path] = true
		state := classifyUnlinked(dir, path, func(now os.FileInfo) bool {
			ino, ok := inodeOf(now)
			return ok && ino == m.inode
		})
		if state == report.ExeNormal {
			continue
		}
		lib := report.MappedLib{Path: path, State: state}
		lib.SHA256 = c.hashMapFile(dir, m.addr)
		libs = append(libs, lib)
	}
	slices.SortFunc(libs, func(a, b report.MappedLib) int { return strings.Compare(a.Path, b.Path) })
	if err := sc.Err(); err != nil {
		return libs, err
	}
	if lr.N <= 0 {
		return libs, errMapsTruncated
	}
	return libs, nil
}

// hashMapFile hashes the file behind a mapping. Opening map_files entries
// needs CAP_CHECKPOINT_RESTORE or CAP_SYS_ADMIN, so this usually fails
// without them and the library is reported without a hash.
func (c *collector) hashMapFile(dir, addr string) string {
	f, err := os.Open(filepath.Join(dir, "map_files", addr))
	if err != nil {
		return ""
	}
	defer f.Close()
	sum, err := c.env.Cache.SHA256File(f)
	if err != nil {
		return ""
	}
	return sum
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
