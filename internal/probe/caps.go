// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// capNames are the capability names by number (capability.h).
var capNames = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
	"CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
	"CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
	"CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// capSet is a capability bit mask.
type capSet uint64

func (s capSet) has(c int) bool { return s&(1<<uint(c)) != 0 }

// names returns the names of the capabilities in s.
func (s capSet) names() []string {
	var out []string
	for c := 0; c < 64; c++ {
		if !s.has(c) {
			continue
		}
		if c < len(capNames) {
			out = append(out, capNames[c])
		} else {
			out = append(out, "CAP_"+strconv.Itoa(c))
		}
	}
	return out
}

// capState is the capability state of the calling thread.
type capState struct {
	effective, permitted, inheritable capSet
	bounding, ambient                 capSet
}

// currentCaps reads the capability sets of the calling thread. The bounding
// and ambient sets come from /proc/thread-self/status.
func currentCaps() (capState, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return capState{}, err
	}
	st := capState{
		effective:   capSet(data[0].Effective) | capSet(data[1].Effective)<<32,
		permitted:   capSet(data[0].Permitted) | capSet(data[1].Permitted)<<32,
		inheritable: capSet(data[0].Inheritable) | capSet(data[1].Inheritable)<<32,
	}
	if b, err := os.ReadFile("/proc/thread-self/status"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				continue
			}
			switch k {
			case "CapBnd":
				st.bounding = capSet(n)
			case "CapAmb":
				st.ambient = capSet(n)
			}
		}
	}
	return st, nil
}

// lastCap is the highest capability number the kernel knows.
func lastCap() int {
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < 64 {
			return n
		}
	}
	return len(capNames) - 1
}
