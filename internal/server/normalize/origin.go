// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"regexp"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Fields an origin rule looks at.
const (
	FieldVendor   = "vendor"   // rpm Vendor
	FieldSupplier = "supplier" // vendor and maintainer together
	FieldVersion  = "version"  // full native version (release tags)
)

// OriginRule decides the origin of an OS package. Rules are evaluated in
// order and the first match wins.
type OriginRule struct {
	Name string
	// Format limits the rule to one package format; empty means any.
	Format string
	// Distros limits the rule to these os-release IDs (compared with ID
	// only, not ID_LIKE: a vendor that is native on one distribution is a
	// third-party repository on its relatives, e.g. Fedora Project (EPEL)
	// packages on Rocky). Empty means any.
	Distros []string
	Field   string
	Match   *regexp.Regexp
	Origin  store.ComponentOrigin
}

// elDistros are the rpm distributions with vendor rules below. On these, an
// rpm whose vendor is set but matches none of them comes from a third-party
// repository.
var elDistros = []string{"rhel", "centos", "rocky", "almalinux", "ol", "amzn", "fedora",
	"sles", "sled", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse",
	"mariner", "azurelinux", "photon"}

var re = regexp.MustCompile

// OriginRules is the origin rule table (ARCH 5.2 item 4). When no rule
// matches, DefaultOrigin applies.
var OriginRules = []OriginRule{
	// 1. rpm vendors of the distribution itself.
	{Name: "rhel-vendor", Format: report.PackageRPM, Distros: []string{"rhel"}, Field: FieldVendor,
		Match: re(`(?i)^red hat\b`), Origin: store.OriginDistro},
	{Name: "centos-vendor", Format: report.PackageRPM, Distros: []string{"centos"}, Field: FieldVendor,
		Match: re(`(?i)^(centos|red hat)\b`), Origin: store.OriginDistro},
	{Name: "rocky-vendor", Format: report.PackageRPM, Distros: []string{"rocky"}, Field: FieldVendor,
		Match: re(`(?i)^(rocky|red hat)\b`), Origin: store.OriginDistro},
	{Name: "alma-vendor", Format: report.PackageRPM, Distros: []string{"almalinux"}, Field: FieldVendor,
		Match: re(`(?i)^(almalinux|red hat)\b`), Origin: store.OriginDistro},
	{Name: "oracle-vendor", Format: report.PackageRPM, Distros: []string{"ol"}, Field: FieldVendor,
		Match: re(`(?i)^oracle\b`), Origin: store.OriginDistro},
	{Name: "amazon-vendor", Format: report.PackageRPM, Distros: []string{"amzn"}, Field: FieldVendor,
		Match: re(`(?i)^amazon\b`), Origin: store.OriginDistro},
	{Name: "fedora-vendor", Format: report.PackageRPM, Distros: []string{"fedora"}, Field: FieldVendor,
		Match: re(`(?i)^fedora project\b`), Origin: store.OriginDistro},
	{Name: "suse-vendor", Format: report.PackageRPM,
		Distros: []string{"sles", "sled", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse"},
		Field:   FieldVendor, Match: re(`(?i)suse`), Origin: store.OriginDistro},
	{Name: "azure-linux-vendor", Format: report.PackageRPM, Distros: []string{"mariner", "azurelinux"},
		Field: FieldVendor, Match: re(`(?i)^microsoft\b`), Origin: store.OriginDistro},
	{Name: "photon-vendor", Format: report.PackageRPM, Distros: []string{"photon"}, Field: FieldVendor,
		Match: re(`(?i)^(vmware|broadcom)\b`), Origin: store.OriginDistro},

	// 2. Well-known third-party repositories, by vendor or maintainer.
	{Name: "nginx-org", Field: FieldSupplier,
		Match: re(`(?i)nginx\.(com|org)|nginx packaging|nginx,? inc|@f5\.com`), Origin: store.OriginThirdParty},
	{Name: "docker", Field: FieldSupplier,
		Match: re(`(?i)@docker\.com|^docker(,? inc\.?)?\s*(<|$)`), Origin: store.OriginThirdParty},
	{Name: "elastic", Field: FieldSupplier,
		Match: re(`(?i)@elastic\.co\b|^elastic(search)?\b`), Origin: store.OriginThirdParty},
	{Name: "mongodb", Field: FieldSupplier, Match: re(`(?i)@mongodb\.(com|org)|mongodb,? inc`),
		Origin: store.OriginThirdParty},
	{Name: "pgdg-vendor", Field: FieldSupplier,
		Match: re(`(?i)postgresql global development group`), Origin: store.OriginThirdParty},
	{Name: "grafana", Field: FieldSupplier, Match: re(`(?i)grafana`), Origin: store.OriginThirdParty},
	{Name: "hashicorp", Field: FieldSupplier, Match: re(`(?i)hashicorp`), Origin: store.OriginThirdParty},
	{Name: "nodesource", Field: FieldSupplier, Match: re(`(?i)nodesource`), Origin: store.OriginThirdParty},
	{Name: "gitlab", Field: FieldSupplier, Match: re(`(?i)@gitlab\.com|gitlab,? inc`), Origin: store.OriginThirdParty},
	{Name: "chrome", Field: FieldSupplier, Match: re(`(?i)chromium-dev@chromium\.org|google (inc|llc)`),
		Origin: store.OriginThirdParty},
	{Name: "microsoft", Field: FieldSupplier, Match: re(`(?i)microsoft`), Origin: store.OriginThirdParty},

	// 3. Release tags of third-party repositories.
	{Name: "ppa", Format: report.PackageDeb, Field: FieldVersion, Match: re(`(?i)[~+.]ppa`),
		Origin: store.OriginThirdParty},
	{Name: "pgdg-release", Field: FieldVersion, Match: re(`(?i)pgdg`), Origin: store.OriginThirdParty},
	{Name: "nginx-rpm-release", Format: report.PackageRPM, Field: FieldVersion, Match: re(`\.ngx$`),
		Origin: store.OriginThirdParty},
	// nginx.org and Docker build one package per release and append the
	// codename after the Debian revision: 1.25.3-1~jammy,
	// 5:24.0.7-1~ubuntu.22.04~jammy. Distribution revisions end in a digit
	// (1.2-1~deb12u1, 2.0-1~bpo12+1, 1.2-0ubuntu1~22.04.1).
	{Name: "deb-codename-suffix", Format: report.PackageDeb, Field: FieldVersion,
		Match: re(`-[0-9][^-]*~[a-z]+$`), Origin: store.OriginThirdParty},

	// 4. Maintainers and release tags of the distribution itself.
	{Name: "ubuntu-maintainer", Format: report.PackageDeb, Distros: []string{"ubuntu"}, Field: FieldSupplier,
		Match: re(`(?i)ubuntu|canonical`), Origin: store.OriginDistro},
	{Name: "debian-maintainer", Format: report.PackageDeb, Distros: []string{"debian", "ubuntu"},
		Field: FieldSupplier, Match: re(`(?i)debian\.(org|net)|lists\.debian|alioth`), Origin: store.OriginDistro},
	{Name: "ubuntu-release", Format: report.PackageDeb, Distros: []string{"ubuntu"}, Field: FieldVersion,
		Match: re(`ubuntu[0-9]`), Origin: store.OriginDistro},
	{Name: "debian-release", Format: report.PackageDeb, Distros: []string{"debian"}, Field: FieldVersion,
		Match: re(`[+~](deb[0-9]+u[0-9]+|bpo[0-9]+)`), Origin: store.OriginDistro},
	{Name: "alpine-maintainer", Format: report.PackageAPK, Distros: []string{"alpine"}, Field: FieldSupplier,
		Match: re(`(?i)@alpinelinux\.org`), Origin: store.OriginDistro},

	// 5. An rpm with a vendor that is not the distribution's.
	{Name: "rpm-foreign-vendor", Format: report.PackageRPM, Distros: elDistros, Field: FieldVendor,
		Match: re(`\S`), Origin: store.OriginThirdParty},
}

// DefaultRule is the name ClassifyOrigin returns when no rule matched.
const DefaultRule = "default"

// DefaultOrigin applies when no rule matches: a package whose format is the
// distribution's native one, or any package of an unknown distribution, is
// treated as a distribution package (distro); a package of another format
// (an rpm on Debian) is third_party. Treating unknown packages as distro
// keeps them under the distribution's advisories, which are keyed by source
// package and know about backports.
func DefaultOrigin(format string, d Distro) store.ComponentOrigin {
	native := d.PackageFormat()
	if native == "" || native == format {
		return store.OriginDistro
	}
	return store.OriginThirdParty
}

// ClassifyOrigin returns the origin of p on d and the name of the rule that
// decided it.
func ClassifyOrigin(p report.Package, d Distro) (store.ComponentOrigin, string) {
	for _, r := range OriginRules {
		if r.Format != "" && r.Format != p.Type {
			continue
		}
		if len(r.Distros) > 0 && !containsString(r.Distros, d.ID) {
			continue
		}
		var v string
		switch r.Field {
		case FieldVendor:
			v = p.Vendor
		case FieldSupplier:
			v = p.Vendor
			if p.Maintainer != "" {
				if v != "" {
					v += " "
				}
				v += p.Maintainer
			}
		case FieldVersion:
			v = p.Version
		}
		if v != "" && r.Match.MatchString(v) {
			return r.Origin, r.Name
		}
	}
	return DefaultOrigin(p.Type, d), DefaultRule
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
