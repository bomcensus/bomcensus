// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package hostinfo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

var (
	osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}
	machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
)

// legacyRelease are release files of systems without os-release, with the
// os-release ID they imply. An empty ID is taken from the file content.
var legacyRelease = []struct{ path, id string }{
	{"/etc/redhat-release", ""},
	{"/etc/system-release", ""},
	{"/etc/centos-release", "centos"},
	{"/etc/alpine-release", "alpine"},
	{"/etc/SuSE-release", ""},
	{"/etc/debian_version", "debian"},
}

const (
	maxReleaseFile = 64 << 10
	maxSymlinkHops = 40
)

// Collect reads the host identity. Kernel, hostname and architecture come
// from uname, so for a container root they describe the host the probe runs
// on.
func Collect(ctx context.Context, env *collect.Env) *report.HostSection {
	start := time.Now()
	sec := &report.HostSection{OS: report.OS{Family: "linux"}}
	var problems []string

	if rel, from, err := readOSRelease(env); err == nil {
		sec.OS = rel
		if from != "" {
			problems = append(problems, "os-release not found; identified from "+from)
		}
	} else {
		problems = append(problems, err.Error())
	}

	sec.MachineID = readMachineID(env)

	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		sec.Hostname = clean(unix.ByteSliceToString(u.Nodename[:]))
		sec.Kernel = clean(unix.ByteSliceToString(u.Release[:]))
		sec.Arch = clean(unix.ByteSliceToString(u.Machine[:]))
	} else {
		problems = append(problems, "uname: "+err.Error())
	}
	if err := ctx.Err(); err != nil {
		problems = append(problems, "collection cancelled: "+err.Error())
	}

	sec.Coverage = report.CoverageFull
	if len(problems) > 0 {
		sec.Coverage = report.CoveragePartial
		sec.Reason = strings.Join(problems, "; ")
	}
	if d, err := report.Digest(digestBody{
		Hostname: sec.Hostname, MachineID: sec.MachineID, OS: sec.OS, Kernel: sec.Kernel, Arch: sec.Arch,
	}); err == nil {
		sec.Digest = d
	}
	sec.CollectedAt = start.UTC()
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec
}

// readOSRelease returns the parsed os-release. from names the legacy file
// used when there is no os-release.
func readOSRelease(env *collect.Env) (rel report.OS, from string, err error) {
	for _, p := range osReleasePaths {
		b, err := readSmall(env, p)
		if err != nil {
			continue
		}
		return parseOSRelease(b), "", nil
	}
	for _, l := range legacyRelease {
		b, err := readSmall(env, l.path)
		if err != nil {
			continue
		}
		line, _, _ := bytes.Cut(b, []byte("\n"))
		if r, ok := parseLegacyRelease(clean(string(line)), l.id); ok {
			return r, l.path, nil
		}
	}
	return report.OS{Family: "linux"}, "", errors.New("os-release not found")
}

// parseOSRelease parses the os-release format (systemd os-release(5)):
// KEY=value lines with shell-like quoting.
func parseOSRelease(b []byte) report.OS {
	vars := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxReleaseFile)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vars[strings.TrimSpace(k)] = clean(unquote(strings.TrimSpace(v)))
	}
	rel := report.OS{
		Family:     "linux",
		ID:         vars["ID"],
		IDLike:     vars["ID_LIKE"],
		Name:       vars["NAME"],
		Version:    vars["VERSION"],
		VersionID:  vars["VERSION_ID"],
		Codename:   vars["VERSION_CODENAME"],
		PrettyName: vars["PRETTY_NAME"],
	}
	if rel.Codename == "" {
		rel.Codename = vars["UBUNTU_CODENAME"]
	}
	return rel
}

// unquote removes double or single quotes. Inside double quotes a backslash
// escapes the next character.
func unquote(v string) string {
	if len(v) == 0 {
		return v
	}
	switch v[0] {
	case '\'':
		if end := strings.IndexByte(v[1:], '\''); end >= 0 {
			return v[1 : 1+end]
		}
		return v[1:]
	case '"':
		var sb strings.Builder
		for i := 1; i < len(v); i++ {
			c := v[i]
			if c == '\\' && i+1 < len(v) {
				i++
				sb.WriteByte(v[i])
				continue
			}
			if c == '"' {
				break
			}
			sb.WriteByte(c)
		}
		return sb.String()
	}
	return v
}

var (
	legacyVersion = regexp.MustCompile(`\d+(\.\d+)*`)
	legacyIDs     = []struct{ prefix, id string }{
		{"Red Hat Enterprise Linux", "rhel"},
		{"CentOS", "centos"},
		{"Fedora", "fedora"},
		{"Amazon Linux", "amzn"},
		{"Oracle Linux", "ol"},
		{"Rocky Linux", "rocky"},
		{"AlmaLinux", "almalinux"},
		{"Scientific Linux", "scientific"},
		{"SUSE Linux Enterprise Server", "sles"},
		{"openSUSE", "opensuse"},
	}
)

// parseLegacyRelease reads the first line of a pre-os-release file such as
// "CentOS release 6.10 (Final)" or the bare version in /etc/alpine-release.
func parseLegacyRelease(line, id string) (report.OS, bool) {
	if line == "" {
		return report.OS{}, false
	}
	rel := report.OS{Family: "linux", ID: id, VersionID: legacyVersion.FindString(line)}
	if id == "" {
		for _, l := range legacyIDs {
			if strings.HasPrefix(line, l.prefix) {
				rel.ID = l.id
				break
			}
		}
		rel.PrettyName = line
		rel.Name = strings.TrimSpace(strings.Split(line, " release ")[0])
	}
	return rel, true
}

// machineID returns a valid machine-id (32 lowercase hex digits) or "".
func readMachineID(env *collect.Env) string {
	for _, p := range machineIDPaths {
		b, err := readSmall(env, p)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(b))
		if isMachineID(id) {
			return id
		}
	}
	return ""
}

func isMachineID(s string) bool {
	if len(s) != 32 {
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

// readSmall reads a regular file of at most maxReleaseFile bytes.
func readSmall(env *collect.Env, logical string) ([]byte, error) {
	f, err := env.Open(resolve(env, logical))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, maxReleaseFile))
}

// resolve follows symlinks component by component inside env.Root, so that
// an absolute link target in a container root does not lead to the host.
func resolve(env *collect.Env, p string) string {
	hops := 0
	var walk func(string) string
	walk = func(p string) string {
		if p == "/" || p == "." || p == "" {
			return "/"
		}
		parent := walk(path.Dir(p))
		cand := path.Join(parent, path.Base(p))
		fi, err := os.Lstat(env.Path(cand))
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 || hops >= maxSymlinkHops {
			return cand
		}
		hops++
		target, err := os.Readlink(env.Path(cand))
		if err != nil || target == "" {
			return cand
		}
		if !path.IsAbs(target) {
			target = path.Join(parent, target)
		}
		return walk(path.Clean(target))
	}
	return walk(path.Clean(p))
}
