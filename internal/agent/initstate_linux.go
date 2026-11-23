// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agent

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// InitStateDir hands dir to uid:gid with mode 0700. The node agent keeps
// its state in a host directory that the kubelet creates as root; an init
// container running as root with CAP_CHOWN and CAP_FOWNER calls this before
// the agent starts as an unprivileged user, which then creates its state
// directory inside. Only dir itself is changed, not its content, and a
// symbolic link is refused.
//
// The directory is opened with O_PATH, which needs no permission on it: on
// every later start it is already mode 0700 and owned by uid, and root
// without CAP_DAC_READ_SEARCH could not open it for reading.
func InitStateDir(dir string, uid, gid int) error {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("init-state: open %s: %w", dir, err)
	}
	defer unix.Close(fd)
	if err := unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("init-state: chown %s: %w", dir, err)
	}
	// fchmod does not take an O_PATH descriptor; its /proc link reaches the
	// same inode without resolving dir again.
	if err := unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), 0o700); err != nil {
		return fmt.Errorf("init-state: chmod %s: %w", dir, err)
	}
	return nil
}
