// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"cmp"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Digest algorithms of expected files.
const (
	AlgoMD5    = "md5"
	AlgoSHA1   = "sha1"
	AlgoSHA256 = "sha256"
	AlgoSHA384 = "sha384"
	AlgoSHA512 = "sha512"
)

// maxExpectedFiles bounds the files kept in memory for rpm and apk, whose
// databases are read whole. dpkg file lists are read per package.
const maxExpectedFiles = 2_000_000

// ExpectedFile is a package file whose content the database records.
type ExpectedFile struct {
	// Path is the logical path where the content is, after dpkg diversions.
	Path   string
	Algo   string
	Digest string // lower-case hex
	// MissingOK is set for files the package allows to be absent (rpm
	// %missingok).
	MissingOK bool
	// MaySymlink is set when the database cannot tell a symlink from a
	// regular file (apk records the checksum of a symlink's target name).
	// A symlink at Path is then not checked.
	MaySymlink bool
}

// ExpectedPackage is one installed package and how to get its files.
type ExpectedPackage struct {
	Type, Name, Version, Arch string

	files    []ExpectedFile // rpm, apk
	excluded int            // rpm, apk
	dpkg     *dpkgFileSource
}

// Key orders packages for resumable passes. It is stable across runs as long
// as the package is installed in the same version.
func (p *ExpectedPackage) Key() string {
	return p.Type + "/" + p.Name + "/" + p.Arch + "/" + p.Version
}

// Expected lists the packages of every database under an inspected root,
// ordered by Key.
type Expected struct {
	Packages  []*ExpectedPackage
	Databases []report.PackageDB
	// Problems describe databases or entries that could not be read.
	Problems []string

	env  *collect.Env
	res  *resolver
	dpkg *dpkgState
}

// ReadExpected reads the package databases for an integrity check. File
// lists of dpkg packages are read later, by Files.
func ReadExpected(ctx context.Context, env *collect.Env) *Expected {
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	e := &Expected{env: env, res: newResolver(env)}
	e.readDpkg(ctx)
	e.readRPM(ctx)
	e.readAPK(ctx)
	slices.SortFunc(e.Packages, func(a, b *ExpectedPackage) int {
		return cmp.Compare(a.Key(), b.Key())
	})
	e.Packages = slices.CompactFunc(e.Packages, func(a, b *ExpectedPackage) bool { return a.Key() == b.Key() })
	if len(e.Problems) > 0 {
		log.Debug("package databases incomplete for the integrity check", "problems", strings.Join(e.Problems, "; "))
	}
	return e
}

// Files returns the files of p whose content can be checked, and the number
// left out because the database marks them as changeable (conffiles,
// %config, %ghost, no digest). An error means the file list could not be
// read; files is then empty.
func (e *Expected) Files(p *ExpectedPackage) (files []ExpectedFile, excluded int, err error) {
	if p.dpkg != nil {
		return e.dpkgFiles(p)
	}
	return p.files, p.excluded, nil
}

// Find returns the package with the same type, name and arch, whatever its
// version.
func (e *Expected) Find(typ, name, arch string) *ExpectedPackage {
	for _, p := range e.Packages {
		if p.Type == typ && p.Name == name && p.Arch == arch {
			return p
		}
	}
	return nil
}

func (e *Expected) problem(msg string) {
	if len(e.Problems) < 64 {
		e.Problems = append(e.Problems, cleanReason(msg))
	}
}

// Resolve returns the path to open for the logical path p. Symlinked
// directories and a symlink in the last component are followed inside the
// inspected root. link reports whether p itself is a symlink. Resolve is
// not safe for concurrent use.
func (e *Expected) Resolve(p string) (real string, link bool) {
	p = path.Clean(p)
	dir, base := path.Split(p)
	cand := path.Join(e.res.dir(path.Clean(dir)), base)
	fi, err := os.Lstat(e.env.Path(cand))
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return e.env.Path(e.res.file(cand)), true
	}
	return e.env.Path(cand), false
}

// exists stats a canonical path; a missing path is not a problem.
func (e *Expected) exists(p string) bool {
	_, err := e.res.stat(p)
	if err == nil {
		return true
	}
	if !notExist(err) {
		e.problem(p + ": " + errMsg(err))
	}
	return false
}
