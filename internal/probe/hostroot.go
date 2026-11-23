// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

// Host root mode (collect --host-root DIR), used by the node agent of the
// Kubernetes chart. The probe runs in a container that has the host's root
// file system mounted read-only at DIR. Before it reads anything it changes
// its root directory to DIR, so that the collectors see the host the way
// the probe of the systemd units does: the same paths, the host's /proc
// (the proc file system mounted on the host, reached through DIR/proc) and
// version commands that run host binaries with the host's libraries.
//
// The container starts the probe as root with the capabilities the
// privilege drop needs. In this mode the drop is not best effort: unless
// the probe ends up as uid 65534 with exactly CAP_DAC_READ_SEARCH and
// CAP_SYS_PTRACE, no_new_privs and the seccomp filter, it collects nothing.
// A root process with the host mounted could otherwise write to host files
// owned by root through submounts that are not read-only.

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// EnterHostRoot changes the root directory of the process to dir. It needs
// CAP_SYS_CHROOT and must run before ApplySandbox, whose seccomp filter
// denies chroot. dir must hold a proc file system at dir/proc.
func EnterHostRoot(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("host root %q is not an absolute path", dir)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(filepath.Join(dir, "proc"), &fs); err != nil {
		return fmt.Errorf("host root: %s/proc: %w", dir, err)
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return fmt.Errorf("host root: %s/proc is not a proc file system", dir)
	}
	// Go threads share one fs_struct (CLONE_FS), so this applies to the
	// whole process.
	if err := unix.Chroot(dir); err != nil {
		return fmt.Errorf("host root: chroot %s: %w", dir, err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("host root: chdir: %w", err)
	}
	// The probe binary lives in the container image, not on the host; a
	// host file at the same path must not be dropped from the artifacts.
	selfPath = ""
	return nil
}

// VerifyHostRootSandbox checks that the restrictions of ApplySandbox took
// full effect, as host root mode requires.
func VerifyHostRootSandbox(r *SandboxResult) error {
	var problems []string
	if r.UID != unprivilegedID || r.GID != unprivilegedID || len(r.Groups) != 0 {
		problems = append(problems, fmt.Sprintf("uid %d gid %d groups %v, want %d without groups", r.UID, r.GID, r.Groups, unprivilegedID))
	}
	want := make([]string, 0, len(keptCaps))
	for _, c := range keptCaps {
		want = append(want, capNames[c])
	}
	if !slices.Equal(r.Capabilities, want) {
		problems = append(problems, "effective capabilities "+listOrNone(r.Capabilities))
	}
	if !slices.Equal(r.Bounding, want) {
		problems = append(problems, "bounding set "+listOrNone(r.Bounding)+" (CAP_SETPCAP is needed to reduce it)")
	}
	if len(r.Ambient) != 0 {
		problems = append(problems, "ambient capabilities "+listOrNone(r.Ambient))
	}
	if !r.NoNewPrivs {
		problems = append(problems, "no_new_privs not set")
	}
	if r.Seccomp != 2 {
		problems = append(problems, "seccomp filter not installed")
	}
	if len(problems) > 0 {
		return errors.New("host root mode needs the full privilege drop: " + strings.Join(problems, "; "))
	}
	return nil
}
