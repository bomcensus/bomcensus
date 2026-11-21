// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package probe

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/psx"
)

// unprivilegedID is the uid and gid (nobody) a probe started as root runs as.
const unprivilegedID = 65534

// keptCaps are the capabilities a probe started as root keeps.
var keptCaps = []int{unix.CAP_DAC_READ_SEARCH, unix.CAP_SYS_PTRACE}

// allThreadsPrctl runs prctl on every thread of the process. Credentials,
// capabilities and no_new_privs are per thread in the kernel.
func allThreadsPrctl(option, arg2 uintptr) error {
	if _, _, e := psx.Syscall6(unix.SYS_PRCTL, option, arg2, 0, 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

// allThreadsCapset sets the effective, permitted and inheritable sets of
// every thread.
func allThreadsCapset(effective, permitted, inheritable capSet) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(effective), Permitted: uint32(permitted), Inheritable: uint32(inheritable)},
		{Effective: uint32(effective >> 32), Permitted: uint32(permitted >> 32), Inheritable: uint32(inheritable >> 32)},
	}
	if _, _, e := psx.Syscall3(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return nil
}

// restrictPrivileges drops root. A process that is not root keeps its
// capabilities (for example ambient ones granted by systemd).
func restrictPrivileges() SandboxStep {
	step := SandboxStep{Name: "privileges"}
	if os.Geteuid() != 0 {
		step.Status = StepSkipped
		caps, _ := currentCaps()
		step.Detail = fmt.Sprintf("not root (uid %d); capabilities kept as given: %s", os.Geteuid(), listOrNone(caps.effective.names()))
		return step
	}
	before, err := currentCaps()
	if err != nil {
		step.Status = StepFailed
		step.Detail = "capget: " + err.Error()
		return step
	}
	var keep capSet
	var missing []string
	for _, c := range keptCaps {
		if before.permitted.has(c) {
			keep |= 1 << uint(c)
		} else {
			missing = append(missing, capNames[c])
		}
	}
	if len(missing) > 0 {
		return keepRoot(before, missing)
	}

	var problems []string
	// Capabilities must survive the uid change.
	if err := allThreadsPrctl(unix.PR_SET_KEEPCAPS, 1); err != nil {
		problems = append(problems, "keepcaps: "+err.Error())
	}
	// The bounding set can only be reduced while CAP_SETPCAP is effective,
	// that is before the uid change.
	if before.effective.has(unix.CAP_SETPCAP) {
		var failed []string
		for c := 0; c <= lastCap(); c++ {
			if keep.has(c) || !before.bounding.has(c) {
				continue
			}
			if err := allThreadsPrctl(unix.PR_CAPBSET_DROP, uintptr(c)); err != nil {
				failed = append(failed, fmt.Sprintf("%d (%v)", c, err))
			}
		}
		if len(failed) > 0 {
			problems = append(problems, "bounding set: cannot drop "+strings.Join(failed, ", "))
		}
	} else {
		problems = append(problems, "bounding set not reduced: no CAP_SETPCAP")
	}

	// syscall.Setgroups, Setgid and Setuid apply to every thread.
	switched := true
	if err := syscall.Setgroups([]int{}); err != nil {
		problems = append(problems, "setgroups: "+err.Error())
		switched = false
	}
	if err := syscall.Setgid(unprivilegedID); err != nil {
		problems = append(problems, "setgid: "+err.Error())
		switched = false
	}
	if err := syscall.Setuid(unprivilegedID); err != nil {
		problems = append(problems, "setuid: "+err.Error())
		switched = false
	}

	// Whether or not the uid changed, nothing but the kept capabilities
	// remains. After a successful setuid the effective set is empty and is
	// raised again from the retained permitted set.
	if err := allThreadsCapset(keep, keep, 0); err != nil {
		problems = append(problems, "capset: "+err.Error())
	}
	if err := allThreadsPrctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL); err != nil && err != syscall.EINVAL {
		problems = append(problems, "clear ambient: "+err.Error())
	}
	_ = allThreadsPrctl(unix.PR_SET_KEEPCAPS, 0)

	after, _ := currentCaps()
	var detail []string
	if switched && os.Geteuid() == unprivilegedID {
		detail = append(detail, fmt.Sprintf("uid/gid %d, no supplementary groups", unprivilegedID))
	} else {
		detail = append(detail, fmt.Sprintf("still uid %d", os.Geteuid()))
	}
	detail = append(detail, "kept "+listOrNone(after.effective.names()))
	step.Status = StepApplied
	if len(problems) > 0 {
		step.Status = StepPartial
		if !switched && after.effective != keep {
			step.Status = StepFailed
		}
		detail = append(detail, problems...)
	}
	step.Detail = strings.Join(detail, "; ")
	return step
}

// keepRoot handles root without the two read capabilities, the normal case
// in a container with the default capability set. Switching to nobody would
// lose the read access root has. Reducing the capabilities would too: a
// process may read /proc/<pid>/exe of another process of its uid only when
// its permitted set includes the other's, and the container's processes
// usually hold this same set. The process therefore stays as it is; the
// seccomp filter and no_new_privs still apply.
func keepRoot(before capState, missing []string) SandboxStep {
	detail := fmt.Sprintf("uid 0 and capabilities kept (%s): %s not available, and switching to uid %d or reducing the set would hide what root can read",
		listOrNone(before.effective.names()), strings.Join(missing, " and "), unprivilegedID)
	if !before.effective.has(unix.CAP_SETUID) || !before.effective.has(unix.CAP_SETGID) {
		detail += fmt.Sprintf("; no CAP_SETUID/CAP_SETGID: version commands cannot switch to uid %d and fall back to static extraction", unprivilegedID)
	}
	return SandboxStep{Name: "privileges", Status: StepKept, Detail: detail}
}

func setNoNewPrivs() SandboxStep {
	step := SandboxStep{Name: "no_new_privs", Status: StepApplied}
	if err := allThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1); err != nil {
		step.Status = StepFailed
		step.Detail = err.Error()
	}
	return step
}
