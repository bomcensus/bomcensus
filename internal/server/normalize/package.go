// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Package returns the component of an OS package installed on d. Version
// keeps the native string (with the epoch) because version comparison uses
// it; the purl follows the purl type definitions:
//
//	pkg:deb/<id>/<name>@<version>?arch=<arch>&distro=<id>-<version_id>
//	pkg:rpm/<id>/<name>@<version-release>?arch=<arch>&distro=<id>-<version_id>&epoch=<epoch>
//	pkg:apk/<id>/<name>@<version>?arch=<arch>&distro=<id>-<version_id>
//
// Unknown package types get a pkg:generic purl. When the distribution is
// unknown the namespace is "unknown" and the distro qualifier is left out.
func Package(p report.Package, d Distro) store.Component {
	origin, _ := ClassifyOrigin(p, d)
	c := store.Component{
		Type:          p.Type,
		Name:          p.Name,
		Version:       p.Version,
		Arch:          p.Arch,
		Distro:        d.Qualifier(),
		SourceName:    p.SourceName,
		SourceVersion: p.SourceVersion,
		Vendor:        p.Vendor,
		Origin:        origin,
	}
	if c.Vendor == "" {
		c.Vendor = p.Maintainer
	}
	// dpkg and apk leave the source out when it equals the binary package.
	if (p.Type == report.PackageDeb || p.Type == report.PackageAPK) && c.SourceName == "" {
		c.SourceName = p.Name
	}
	if (p.Type == report.PackageDeb || p.Type == report.PackageAPK) && c.SourceVersion == "" {
		c.SourceVersion = p.Version
	}
	c.PURL = PackagePURL(p, d).String()
	return c
}

// PackagePURL builds the purl of an OS package.
func PackagePURL(p report.Package, d Distro) PURL {
	q := map[string]string{"arch": p.Arch, "distro": d.Qualifier()}
	switch p.Type {
	case report.PackageDeb, report.PackageAPK:
		return PURL{Type: p.Type, Namespace: d.namespace(), Name: strings.ToLower(p.Name),
			Version: p.Version, Qualifiers: q}
	case report.PackageRPM:
		epoch, rest := SplitEpoch(p.Version)
		q["epoch"] = epoch
		return PURL{Type: p.Type, Namespace: d.namespace(), Name: p.Name, Version: rest, Qualifiers: q}
	}
	return PURL{Type: "generic", Name: p.Name, Version: p.Version, Qualifiers: map[string]string{"arch": p.Arch}}
}

// SplitEpoch splits "[epoch:]rest". The epoch is returned only when it is
// all digits.
func SplitEpoch(v string) (epoch, rest string) {
	i := strings.IndexByte(v, ':')
	if i <= 0 {
		return "", v
	}
	for _, c := range v[:i] {
		if c < '0' || c > '9' {
			return "", v
		}
	}
	return v[:i], v[i+1:]
}
