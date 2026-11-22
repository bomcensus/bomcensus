// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package proc

import "strings"

// Prefixes container runtimes put in front of the container id in a cgroup
// path segment, in systemd ("docker-<id>.scope") and cgroupfs
// ("/libpod_parent/libpod-<id>") layouts. Plain cgroupfs layouts
// ("/docker/<id>", "/kubepods/burstable/pod<uid>/<id>") use the bare id.
var cgroupIDPrefixes = []string{
	"docker-",
	"cri-containerd-",
	"containerd-",
	"crio-",
	"libpod-",
	"nerdctl-",
}

// containerIDFromCgroup extracts the runtime container id from the contents
// of /proc/<pid>/cgroup. The cgroup v2 line is preferred; with cgroup v1 the
// first hierarchy that carries an id is used.
func containerIDFromCgroup(data string) string {
	lines := strings.Split(data, "\n")
	for _, unified := range []bool{true, false} {
		for _, line := range lines {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) != 3 || (parts[0] == "0" && parts[1] == "") != unified {
				continue
			}
			if id := containerIDFromPath(parts[2]); id != "" {
				return id
			}
		}
	}
	return ""
}

// containerIDFromPath returns the outermost 64-hex-digit container id in a
// cgroup path. Outermost, because with nested runtimes the host runtime knows
// only the outer container. Segments of the runtime monitors
// ("crio-conmon-<id>.scope", "libpod-conmon-<id>.scope") are not containers.
func containerIDFromPath(path string) string {
	for seg := range strings.SplitSeq(path, "/") {
		if strings.Contains(seg, "conmon") {
			continue
		}
		seg = strings.TrimSuffix(seg, ".scope")
		for _, p := range cgroupIDPrefixes {
			if s, ok := strings.CutPrefix(seg, p); ok {
				seg = s
				break
			}
		}
		if isContainerID(seg) {
			return seg
		}
	}
	return ""
}

func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
