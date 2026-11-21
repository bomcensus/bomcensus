// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Distro is the operating system that OS packages are normalized against.
type Distro struct {
	// ID is the os-release ID ("ubuntu", "rocky"), lowercased.
	ID string
	// VersionID is the os-release VERSION_ID ("24.04", "9.3").
	VersionID string
	// IDLike is the os-release ID_LIKE list, lowercased.
	IDLike []string
}

// DistroFromOS builds a Distro from the host section or an image scope.
// A nil os gives the zero Distro (unknown).
func DistroFromOS(os *report.OS) Distro {
	if os == nil {
		return Distro{}
	}
	return Distro{
		ID:        strings.ToLower(strings.TrimSpace(os.ID)),
		VersionID: strings.TrimSpace(os.VersionID),
		IDLike:    strings.Fields(strings.ToLower(os.IDLike)),
	}
}

// Known reports whether the distribution is known.
func (d Distro) Known() bool { return d.ID != "" }

// Qualifier is the purl distro qualifier and the component's Distro value:
// "<id>-<version_id>", or just the id when the version is unknown. Empty
// when the distribution is unknown.
func (d Distro) Qualifier() string {
	switch {
	case d.ID == "":
		return ""
	case d.VersionID == "":
		return d.ID
	}
	return d.ID + "-" + d.VersionID
}

// unknownNamespace is the purl namespace of OS packages from a system whose
// os-release could not be read. The purl spec requires a namespace for deb,
// rpm and apk.
const unknownNamespace = "unknown"

// namespace is the purl namespace (vendor) of OS packages.
func (d Distro) namespace() string {
	if d.ID == "" {
		return unknownNamespace
	}
	return d.ID
}

// distroFamilies maps os-release IDs (and ID_LIKE entries) to the native
// package format.
var distroFamilies = map[string]string{
	"debian": report.PackageDeb, "ubuntu": report.PackageDeb, "linuxmint": report.PackageDeb,
	"raspbian": report.PackageDeb, "pop": report.PackageDeb, "kali": report.PackageDeb,

	"rhel": report.PackageRPM, "centos": report.PackageRPM, "fedora": report.PackageRPM,
	"rocky": report.PackageRPM, "almalinux": report.PackageRPM, "ol": report.PackageRPM,
	"amzn": report.PackageRPM, "sles": report.PackageRPM, "sled": report.PackageRPM,
	"opensuse": report.PackageRPM, "opensuse-leap": report.PackageRPM,
	"opensuse-tumbleweed": report.PackageRPM, "suse": report.PackageRPM,
	"mariner": report.PackageRPM, "azurelinux": report.PackageRPM, "photon": report.PackageRPM,

	"alpine": report.PackageAPK, "wolfi": report.PackageAPK, "chainguard": report.PackageAPK,
	"postmarketos": report.PackageAPK,
}

// PackageFormat is the native package format of the distribution ("deb",
// "rpm", "apk"), or "" when unknown.
func (d Distro) PackageFormat() string {
	if f, ok := distroFamilies[d.ID]; ok {
		return f
	}
	for _, like := range d.IDLike {
		if f, ok := distroFamilies[like]; ok {
			return f
		}
	}
	return ""
}

// is reports whether the distribution is one of ids, directly or through
// ID_LIKE.
func (d Distro) is(ids ...string) bool {
	for _, id := range ids {
		if d.ID == id {
			return true
		}
		for _, like := range d.IDLike {
			if like == id {
				return true
			}
		}
	}
	return false
}
