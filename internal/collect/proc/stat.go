// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package proc

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type statInfo struct {
	state      byte
	ppid       int
	flags      uint64
	startTicks uint64
}

// readStat parses /proc/<pid>/stat.
func readStat(dir string) (statInfo, error) {
	data, err := readLimited(filepath.Join(dir, "stat"), maxSmallFile)
	if err != nil {
		return statInfo{}, err
	}
	return parseStat(string(data))
}

// parseStat parses the stat line. The command name is in parentheses and may
// itself contain spaces and parentheses, so the fields are taken after the
// last ')'.
func parseStat(line string) (statInfo, error) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return statInfo{}, fmt.Errorf("proc: malformed stat")
	}
	f := strings.Fields(line[i+1:])
	// f[0] is field 3 (state), so field n is f[n-3].
	if len(f) < 20 || len(f[0]) != 1 {
		return statInfo{}, fmt.Errorf("proc: short stat")
	}
	var st statInfo
	var err error
	st.state = f[0][0]
	if st.ppid, err = strconv.Atoi(f[1]); err != nil {
		return statInfo{}, fmt.Errorf("proc: stat ppid: %w", err)
	}
	if st.flags, err = strconv.ParseUint(f[6], 10, 64); err != nil {
		return statInfo{}, fmt.Errorf("proc: stat flags: %w", err)
	}
	if st.startTicks, err = strconv.ParseUint(f[19], 10, 64); err != nil {
		return statInfo{}, fmt.Errorf("proc: stat starttime: %w", err)
	}
	return st, nil
}

// readUID returns the effective uid from /proc/<pid>/status, the user a
// process acts as (what ps and top show).
func readUID(dir string) (int, error) {
	data, err := readLimited(filepath.Join(dir, "status"), maxSmallFile)
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			break
		}
		return strconv.Atoi(f[1])
	}
	return 0, fmt.Errorf("proc: no Uid line in status")
}

// readCmdline returns the arguments of a process. Processes that rewrite
// their title often leave a single argument with spaces; that case is split
// on white space so the masking rules see the words.
func readCmdline(dir string) ([]string, error) {
	data, err := readLimited(filepath.Join(dir, "cmdline"), maxCmdlineRead)
	if err != nil {
		return nil, err
	}
	return splitCmdline(data), nil
}

func splitCmdline(data []byte) []string {
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return nil
	}
	args := strings.Split(string(data), "\x00")
	if len(args) == 1 && strings.ContainsAny(args[0], " \t") {
		args = strings.Fields(args[0])
	}
	return args
}

// argv0Path returns argv[0] when it is an absolute path.
func argv0Path(args []string) string {
	if len(args) == 0 || !strings.HasPrefix(args[0], "/") {
		return ""
	}
	return args[0]
}

// readBootTime reads btime from /proc/stat.
func readBootTime(proc string) (time.Time, error) {
	data, err := readLimited(filepath.Join(proc, "stat"), 1<<20)
	if err != nil {
		return time.Time{}, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("proc: btime: %w", err)
			}
			return time.Unix(sec, 0).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("proc: no btime in stat")
}

// readPasswd maps uids to user names. A missing file yields an empty map.
func readPasswd(path string) map[int]string {
	users := map[int]string{}
	data, err := readLimited(path, 16<<20)
	if err != nil {
		return users
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), ":", 4)
		if len(f) < 3 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if _, dup := users[uid]; !dup {
			users[uid] = f[0]
		}
	}
	return users
}

// hidepidMounted reports whether the proc mount hides other users'
// processes, read from the mount table of the reading process.
func hidepidMounted(proc string) bool {
	data, err := readLimited(filepath.Join(proc, "self", "mountinfo"), 4<<20)
	if err != nil {
		return false
	}
	return hidepidInMountinfo(string(data), filepath.Clean(proc))
}

func hidepidInMountinfo(mountinfo, mountPoint string) bool {
	hidden := false
	for line := range strings.SplitSeq(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		g := strings.Fields(post)
		if len(f) < 5 || len(g) < 3 || f[4] != mountPoint || g[0] != "proc" {
			continue
		}
		// The last mount on a mount point wins.
		hidden = false
		for opt := range strings.SplitSeq(g[2], ",") {
			if v, ok := strings.CutPrefix(opt, "hidepid="); ok && v != "0" && v != "off" {
				hidden = true
			}
		}
	}
	return hidden
}
