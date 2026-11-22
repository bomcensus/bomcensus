// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package hostinfo

import (
	"context"
	"debug/pe"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	cryptographyKey   = `SOFTWARE\Microsoft\Cryptography`
	// firstWindows11Build is the first build number of Windows 11. Its
	// ProductName value still says "Windows 10".
	firstWindows11Build = 22000
)

// Collect reads the host identity of a Windows system. env.Root is not used:
// there is no file system root to redirect on Windows.
//
// OS fields:
//
//	family       "windows"
//	id           "windows"
//	name         ProductName, e.g. "Windows 11 Pro", "Windows Server 2022 Datacenter"
//	version      DisplayVersion (ReleaseId on older builds), e.g. "24H2"
//	version_id   major.minor.build, e.g. "10.0.26100"
//	pretty_name  name, version and full build, e.g. "Windows 11 Pro 24H2 (10.0.26100.2314)"
//
// The kernel is major.minor.build.UBR and the machine id is the MachineGuid
// without dashes.
func Collect(ctx context.Context, _ *collect.Env) *report.HostSection {
	start := time.Now()
	sec := &report.HostSection{OS: report.OS{Family: "windows", ID: "windows"}}
	var problems []string

	v := windows.RtlGetVersion()
	build := v.BuildNumber
	cv, err := readCurrentVersion()
	if err != nil {
		problems = append(problems, "registry "+currentVersionKey+": "+err.Error())
	}
	sec.OS, sec.Kernel = describe(v.MajorVersion, v.MinorVersion, build, cv)

	if name, err := os.Hostname(); err == nil {
		sec.Hostname = clean(name)
	} else {
		problems = append(problems, "hostname: "+err.Error())
	}
	if id, err := machineGUID(); err == nil {
		sec.MachineID = id
	} else {
		problems = append(problems, "machine guid: "+err.Error())
	}
	sec.Arch = nativeArch()
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

// currentVersion holds the values read from the CurrentVersion key.
type currentVersion struct {
	ProductName, DisplayVersion, ReleaseID, EditionID, InstallationType string
	UBR                                                                 uint64
}

func readCurrentVersion() (currentVersion, error) {
	var cv currentVersion
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return cv, err
	}
	defer k.Close()
	str := func(name string) string {
		s, _, _ := k.GetStringValue(name)
		return clean(s)
	}
	cv.ProductName = str("ProductName")
	cv.DisplayVersion = str("DisplayVersion")
	cv.ReleaseID = str("ReleaseId")
	cv.EditionID = str("EditionID")
	cv.InstallationType = str("InstallationType")
	cv.UBR, _, _ = k.GetIntegerValue("UBR")
	return cv, nil
}

// describe builds the OS fields and the kernel string. It is separate from
// Collect so that it can be tested with fixed values.
func describe(major, minor, build uint32, cv currentVersion) (report.OS, string) {
	o := report.OS{Family: "windows", ID: "windows"}
	o.Name = cv.ProductName
	if build >= firstWindows11Build && strings.HasPrefix(o.Name, "Windows 10") {
		o.Name = "Windows 11" + strings.TrimPrefix(o.Name, "Windows 10")
	}
	if o.Name == "" {
		o.Name = "Windows"
	}
	o.Version = cv.DisplayVersion
	if o.Version == "" {
		o.Version = cv.ReleaseID
	}
	if major > 0 {
		o.VersionID = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}
	kernel := o.VersionID
	if kernel != "" && cv.UBR > 0 {
		kernel += fmt.Sprintf(".%d", cv.UBR)
	}
	// The pretty name carries the full version so that the console, which
	// shows the name and appends the version only when the name lacks it,
	// does not repeat it.
	pretty := []string{o.Name}
	if o.Version != "" {
		pretty = append(pretty, o.Version)
	}
	if kernel != "" {
		pretty = append(pretty, "("+kernel+")")
	}
	o.PrettyName = strings.Join(pretty, " ")
	return o, kernel
}

// machineGUID returns HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid in
// the 32 lower-case hex digit form of a Linux machine-id.
func machineGUID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, cryptographyKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	s, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	id := strings.ToLower(strings.NewReplacer("-", "", "{", "", "}", "").Replace(strings.TrimSpace(s)))
	if !isMachineID(id) {
		return "", fmt.Errorf("unexpected value %q", s)
	}
	return id, nil
}

func isMachineID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return s != strings.Repeat("0", 32)
}

// nativeArch names the machine architecture as uname does on Linux, so that
// assets of both systems compare. It asks for the native machine, which
// differs from runtime.GOARCH for an x86-64 binary emulated on ARM64.
func nativeArch() string {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err == nil {
		switch native {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			return "x86_64"
		case pe.IMAGE_FILE_MACHINE_ARM64:
			return "aarch64"
		case pe.IMAGE_FILE_MACHINE_I386:
			return "i686"
		case pe.IMAGE_FILE_MACHINE_ARMNT:
			return "armv7l"
		}
	}
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return runtime.GOARCH
}
