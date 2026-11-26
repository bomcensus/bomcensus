// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"path"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Component types of artifacts.
const (
	TypeMaven  = "maven"
	TypeGolang = "golang"
	TypeBinary = "binary"
)

// GoStdlib is the module name of the Go standard library (the toolchain a
// binary was built with).
const GoStdlib = "stdlib"

// Artifact returns the components an artifact stands for. A Go binary
// yields its main module and the standard library of its toolchain; other
// artifacts yield one component. All of them have origin upstream.
//
//	jar        pkg:maven/<group>/<artifact>@<version>, or pkg:generic/<name>@<version>
//	           when the coordinates are missing
//	go_binary  pkg:golang/<module>@<version> and pkg:golang/stdlib@<go version>
//	go_module  pkg:golang/<module>@<version>
//	software   the detector's purl and CPE, or pkg:generic/<name>@<version>;
//	           the build, when the detector found one, is kept
func Artifact(a report.Artifact) []store.Component {
	switch a.Kind {
	case report.ArtifactJar:
		return []store.Component{jarComponent(a)}
	case report.ArtifactGoBinary:
		out := []store.Component{goModule(firstNonEmpty(a.Module, a.Name), a.Version)}
		if v := GoVersion(a.GoVersion); v != "" {
			out = append(out, goModule(GoStdlib, v))
		}
		return out
	case report.ArtifactGoModule:
		return []store.Component{goModule(firstNonEmpty(a.Module, a.Name), a.Version)}
	}
	return []store.Component{softwareComponent(a)}
}

func jarComponent(a report.Artifact) store.Component {
	c := store.Component{Type: TypeMaven, Version: a.Version, Origin: store.OriginUpstream, CPE: a.CPE}
	if a.GroupID != "" && a.ArtifactID != "" {
		c.Name = a.GroupID + ":" + a.ArtifactID
		c.PURL = PURL{Type: "maven", Namespace: a.GroupID, Name: a.ArtifactID, Version: a.Version}.String()
		return c
	}
	c.Name = firstNonEmpty(a.ArtifactID, a.Name)
	c.PURL = PURL{Type: "generic", Name: c.Name, Version: a.Version}.String()
	return c
}

// goModule builds a golang component. The module path keeps its case: Go
// module paths are case-sensitive and advisories (OSV) use them verbatim.
// A "(devel)" version, which the toolchain writes for local builds, is left
// out of the purl.
func goModule(module, version string) store.Component {
	c := store.Component{Type: TypeGolang, Name: module, Version: version, Origin: store.OriginUpstream}
	pv := version
	if pv == "(devel)" {
		pv = ""
	}
	dir, base := path.Split(strings.Trim(module, "/"))
	c.PURL = PURL{Type: "golang", Namespace: dir, Name: base, Version: pv}.String()
	return c
}

func softwareComponent(a report.Artifact) store.Component {
	c := store.Component{Type: TypeBinary, Name: a.Name, Version: a.Version, Build: a.Build, CPE: a.CPE,
		Origin: store.OriginUpstream}
	if p := strings.TrimSuffix(strings.TrimSpace(a.PURL), "@"); strings.HasPrefix(p, "pkg:") {
		c.PURL = p
	} else {
		c.PURL = PURL{Type: "generic", Name: a.Name, Version: a.Version}.String()
	}
	return c
}

// GoVersion returns the toolchain version without the "go" prefix:
// "go1.22.1" and "go1.22.1 X:boringcrypto" give "1.22.1". It returns "" when
// s holds no release version.
func GoVersion(s string) string {
	for _, f := range strings.Fields(s) {
		if len(f) > 2 && strings.HasPrefix(f, "go") && f[2] >= '0' && f[2] <= '9' {
			return f[2:]
		}
	}
	return ""
}

// Location is where an artifact was found: its path, followed by "!/" and
// each nested archive entry.
func Location(a report.Artifact) string {
	if len(a.Nested) == 0 {
		return a.Path
	}
	return a.Path + "!/" + strings.Join(a.Nested, "!/")
}

// Method maps a report detection method to the stored one.
func Method(m string) string {
	switch m {
	case report.MethodExec:
		return store.DetectExec
	case report.MethodStatic:
		return store.DetectStatic
	case report.MethodManifest:
		return store.DetectManifest
	case report.MethodBuildInfo:
		return store.DetectBuildInfo
	}
	return m
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// GoBinaries returns the Go executables among arts: files with Go build
// info and a hash, not entries of archives.
func GoBinaries(arts []report.Artifact) []store.GoBinary {
	var out []store.GoBinary
	for _, a := range arts {
		if a.Kind != report.ArtifactGoBinary || a.SHA256 == "" || len(a.Nested) > 0 {
			continue
		}
		out = append(out, store.GoBinary{Path: a.Path, SHA256: strings.ToLower(a.SHA256), GOOS: a.GOOS, GOARCH: a.GOARCH})
	}
	return out
}
