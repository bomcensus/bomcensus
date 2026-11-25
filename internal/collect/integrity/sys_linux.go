// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package integrity

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func statKeyOf(fi os.FileInfo) (statKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return statKey{}, false
	}
	return statKey{Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size, Mtime: st.Mtim.Nano(), Ctime: st.Ctim.Nano()}, true
}

// dropCache asks the kernel to drop the file's pages from the page cache,
// so that the check does not evict what the host's services use.
func dropCache(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}

// packageLocks are the lock files that package managers hold with fcntl
// while they change the system.
var packageLocks = []string{
	"/var/lib/dpkg/lock-frontend",
	"/var/lib/dpkg/lock",
	"/var/lib/rpm/.rpm.lock",
	"/usr/lib/sysimage/rpm/.rpm.lock",
}

// packageManagerBusy reports whether a package manager holds its lock
// under root. A lock file that cannot be opened counts as free.
func packageManagerBusy(root string) bool {
	for _, p := range packageLocks {
		f, err := os.Open(filepath.Join(root, p))
		if err != nil {
			continue
		}
		lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
		err = unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lk)
		f.Close()
		if err == nil && lk.Type != unix.F_UNLCK {
			return true
		}
	}
	return false
}

// Pressure thresholds: the share of the last 10 seconds in which some task
// waited for CPU or I/O.
const (
	cpuPressureBusy = 60.0
	ioPressureBusy  = 40.0
)

// hostBusy reads the pressure stall information under the proc mount. It
// reports false when PSI is not available.
func hostBusy(proc string) bool {
	return someAvg10(filepath.Join(proc, "pressure", "cpu")) >= cpuPressureBusy ||
		someAvg10(filepath.Join(proc, "pressure", "io")) >= ioPressureBusy
}

func someAvg10(p string) float64 {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(field, "avg10="); ok {
				x, _ := strconv.ParseFloat(v, 64)
				return x
			}
		}
	}
	return 0
}
