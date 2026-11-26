// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// reexecMarker is set in the environment of a probe that re-executed itself
// from memory, so that it does not do so again. Its value is the path of
// the binary on disk.
const reexecMarker = "BOMCENSUS_PROBE_REEXEC"

// selfPath is the probe binary on disk, also after a re-execution from
// memory.
var selfPath = func() string {
	if p := os.Getenv(reexecMarker); p != "" {
		return p
	}
	p, _ := os.Readlink("/proc/self/exe")
	return strings.TrimSuffix(p, " (deleted)")
}()

// EnsureExecutableAfterDrop makes sure that a probe started as root can
// still execute its own binary after switching to uid 65534. The exec
// helper of the version commands is a re-execution of /proc/self/exe, and
// the probe binary is often left readable and executable by root only (for
// example when a scanner uploads it to /tmp with mode 0700). In that case
// the binary is copied into a sealed memory file and executed from there;
// the request on standard input is not read before. It returns only when
// nothing had to be done or the re-execution failed; failures are logged
// and leave version commands to fall back to static extraction.
func EnsureExecutableAfterDrop(log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if os.Getenv(reexecMarker) != "" {
		os.Unsetenv(reexecMarker)
		return
	}
	if os.Geteuid() != 0 {
		return
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/exe", &st); err != nil {
		log.Warn("cannot check own executable", "err", err)
		return
	}
	if executableBy(st, unprivilegedID, unprivilegedID) {
		return
	}
	if err := reexecFromMemory(); err != nil {
		log.Warn("binary is not executable by the unprivileged user and cannot be re-executed from memory; version commands will not run",
			"mode", fmt.Sprintf("%#o", st.Mode&0o7777), "err", err)
	}
}

func executableBy(st syscall.Stat_t, uid, gid uint32) bool {
	switch {
	case st.Uid == uid:
		return st.Mode&0o100 != 0
	case st.Gid == gid:
		return st.Mode&0o010 != 0
	}
	return st.Mode&0o001 != 0
}

func reexecFromMemory() error {
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer src.Close()
	// MFD_EXEC keeps the file executable where vm.memfd_noexec makes
	// memory files non-executable by default (kernel 6.3 and later);
	// older kernels reject the flag.
	fd, err := unix.MemfdCreate("bomcensus-probe", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err == unix.EINVAL {
		fd, err = unix.MemfdCreate("bomcensus-probe", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return fmt.Errorf("memfd_create: %w", err)
	}
	mem := os.NewFile(uintptr(fd), "memfd")
	defer mem.Close()
	if _, err := io.Copy(mem, src); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	// A file open for writing cannot be executed: reopen it read-only.
	ro, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return fmt.Errorf("reopen: %w", err)
	}
	defer ro.Close()
	mem.Close()
	env := append(os.Environ(), reexecMarker+"="+selfPath)
	// The descriptor is close-on-exec; the kernel opens the file before it
	// closes the descriptor.
	err = syscall.Exec("/proc/self/fd/"+strconv.Itoa(int(ro.Fd())), os.Args, env)
	return fmt.Errorf("exec: %w", err)
}
