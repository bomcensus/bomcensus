// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"sort"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Owned is what the artifacts owned by one OS package add to it.
type Owned struct {
	Locations []string
	InUse     bool
}

// FileHash is a file hash with the identity of its component (the ID is
// resolved by the caller).
type FileHash struct {
	SHA256    string
	Path      string
	Component store.Component
}

// Content is the normalized software of one scope.
type Content struct {
	Packages  []store.ComponentObservation
	Artifacts []store.ComponentObservation
	// Owned maps the name of an OS package to the artifacts it owns.
	Owned map[string]Owned
	// Hashes are the file hashes of the artifacts, for RecordFileHashes.
	Hashes []FileHash
}

// BuildContent normalizes the packages and artifacts of one scope: it
// builds package observations, artifact observations for artifacts that no
// package owns, links owned artifacts to their package (as locations) and
// collects file hashes.
func BuildContent(pkgs []report.Package, arts []report.Artifact, d Distro) Content {
	c := Content{Packages: Packages(pkgs, d)}
	c.Artifacts, c.Owned = Artifacts(arts)
	LinkOwned(c.Packages, c.Owned)
	c.Hashes = FileHashes(arts, c.Packages)
	return c
}

// Packages returns one observation per package.
func Packages(pkgs []report.Package, d Distro) []store.ComponentObservation {
	out := make([]store.ComponentObservation, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		out = append(out, store.ComponentObservation{Component: Package(p, d), Method: store.DetectPackageDB})
	}
	return out
}

// Artifacts returns observations for the artifacts that no OS package owns
// and, by package name, what the owned ones add to their package.
func Artifacts(arts []report.Artifact) ([]store.ComponentObservation, map[string]Owned) {
	var out []store.ComponentObservation
	owned := map[string]Owned{}
	for _, a := range arts {
		loc := Location(a)
		if a.OwnerPackage != "" {
			o := owned[a.OwnerPackage]
			if loc != "" {
				o.Locations = append(o.Locations, loc)
			}
			o.InUse = o.InUse || a.InUse
			owned[a.OwnerPackage] = o
			continue
		}
		obs := store.ComponentObservation{InUse: a.InUse, Method: Method(a.Method)}
		if loc != "" {
			obs.Locations = []string{loc}
		}
		if a.VersionOutput != nil {
			obs.VersionCommand = strings.Join(a.VersionOutput.Command, " ")
			obs.VersionRaw = a.VersionOutput.Stdout + a.VersionOutput.Stderr
		}
		for _, c := range Artifact(a) {
			o := obs
			o.Component = c
			out = append(out, o)
		}
	}
	for k, o := range owned {
		o.Locations = sortedUnique(o.Locations)
		owned[k] = o
	}
	return out, owned
}

// LinkOwned sets the locations and in-use flag of each package observation
// from owned, replacing what it had. It returns the owner names that match
// no package.
func LinkOwned(pkgs []store.ComponentObservation, owned map[string]Owned) []string {
	matched := map[string]bool{}
	for i := range pkgs {
		c := pkgs[i].Component
		pkgs[i].Locations = nil
		pkgs[i].InUse = false
		for _, key := range OwnerKeys(c) {
			o, ok := owned[key]
			if !ok {
				continue
			}
			matched[key] = true
			pkgs[i].Locations = append(pkgs[i].Locations, o.Locations...)
			pkgs[i].InUse = pkgs[i].InUse || o.InUse
		}
		pkgs[i].Locations = sortedUnique(pkgs[i].Locations)
	}
	var unmatched []string
	for k := range owned {
		if !matched[k] {
			unmatched = append(unmatched, k)
		}
	}
	sort.Strings(unmatched)
	return unmatched
}

// OwnerKeys are the names an artifact's OwnerPackage may use for c: the
// package name, and "name:arch" as dpkg prints multi-arch packages.
func OwnerKeys(c store.Component) []string {
	if c.Arch == "" {
		return []string{c.Name}
	}
	return []string{c.Name, c.Name + ":" + c.Arch}
}

// FileHashes returns the hashes of artifact files with the component they
// belong to: the owning package's component, or the artifact's own (the
// main module of a Go binary). Go modules have no file of their own and are
// skipped.
func FileHashes(arts []report.Artifact, pkgs []store.ComponentObservation) []FileHash {
	byOwner := map[string]store.Component{}
	for _, p := range pkgs {
		for _, k := range OwnerKeys(p.Component) {
			if _, ok := byOwner[k]; !ok {
				byOwner[k] = p.Component
			}
		}
	}
	var out []FileHash
	for _, a := range arts {
		if a.SHA256 == "" || a.Kind == report.ArtifactGoModule || len(a.Nested) > 0 {
			continue
		}
		var c store.Component
		if a.OwnerPackage != "" {
			pc, ok := byOwner[a.OwnerPackage]
			if !ok {
				continue
			}
			c = pc
		} else {
			c = Artifact(a)[0]
		}
		out = append(out, FileHash{SHA256: a.SHA256, Path: a.Path, Component: c})
	}
	return out
}

// Identity is the identity key of a component (see store.Component).
func Identity(c store.Component) string {
	return strings.Join([]string{c.Type, c.Name, c.Version, c.Arch, c.Distro, c.PURL}, "\x00")
}

func sortedUnique(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	s = append([]string(nil), s...)
	sort.Strings(s)
	out := s[:1]
	for _, x := range s[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}
