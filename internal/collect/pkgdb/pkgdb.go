// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package pkgdb reads the OS package databases (dpkg, rpm, apk) directly,
// without running the package managers, and maps files to the packages that
// own them.
package pkgdb

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// maxPackages bounds the number of packages in one section.
const maxPackages = 200_000

// maxReason bounds the coverage reason.
const maxReason = 2048

// Collect reads every package database found under env.Root. It never
// returns nil: a system without any package database yields full coverage,
// no packages and no databases. The Index is built lazily on first use.
func Collect(ctx context.Context, env *collect.Env) (*report.PackagesSection, *Index) {
	start := time.Now()
	c := &collector{
		ctx: ctx,
		env: env,
		res: newResolver(env),
		log: env.Log,
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	c.ix = newIndex(ctx, env)

	c.collectDpkg()
	c.collectRPM()
	c.collectAPK()
	if err := ctx.Err(); err != nil {
		c.problem("collection cancelled: " + err.Error())
	}

	sec := &report.PackagesSection{
		Databases: c.dbs,
		Packages:  sortPackages(c.pkgs),
	}
	if len(sec.Packages) > maxPackages {
		sec.Packages = sec.Packages[:maxPackages]
		c.problem(fmt.Sprintf("more than %d packages, rest dropped", maxPackages))
	}
	sec.Coverage = report.CoverageFull
	if len(c.problems) > 0 {
		sec.Coverage = report.CoveragePartial
		if c.readable == 0 {
			sec.Coverage = report.CoverageNone
		}
		sec.Reason = strings.Join(c.problems, "; ")
		if len(sec.Reason) > maxReason {
			sec.Reason = cleanReason(sec.Reason[:maxReason])
		}
		c.log.Debug("package databases incomplete", "reason", sec.Reason)
	}
	if d, err := report.Digest(digestBody{Databases: sec.Databases, Packages: sec.Packages}); err == nil {
		sec.Digest = d
	}
	sec.CollectedAt = start.UTC()
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec, c.ix
}

// digestBody is PackagesSection without SectionMeta.
type digestBody struct {
	Databases []report.PackageDB `json:"databases,omitempty"`
	Packages  []report.Package   `json:"packages,omitempty"`
}

// sortPackages orders by type, name, arch and version, then by the remaining
// fields so that the order is total, and drops exact duplicates.
func sortPackages(p []report.Package) []report.Package {
	slices.SortFunc(p, func(a, b report.Package) int {
		return cmp.Or(
			cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Arch, b.Arch),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.SourceName, b.SourceName),
			cmp.Compare(a.SourceVersion, b.SourceVersion),
			cmp.Compare(a.Vendor, b.Vendor),
			cmp.Compare(a.Maintainer, b.Maintainer),
			cmp.Compare(a.ModularityLabel, b.ModularityLabel),
			cmp.Compare(a.Status, b.Status),
		)
	})
	return slices.Compact(p)
}

func cleanReason(s string) string { return strings.ToValidUTF8(s, "") }

// collector accumulates the results of all databases.
type collector struct {
	ctx context.Context
	env *collect.Env
	res *resolver
	log *slog.Logger
	ix  *Index

	dbs      []report.PackageDB
	pkgs     []report.Package
	problems []string
	// readable counts databases from which something usable was read.
	readable int
	cur      *dbState
}

// dbState tracks one database while it is read.
type dbState struct {
	db report.PackageDB
	// produced counts packages read from it.
	produced int
	// bad is set when it was read incompletely.
	bad bool
	// unreadable is set when nothing could be read from it.
	unreadable bool
}

func (c *collector) startDB(typ, p string) *dbState {
	d := &dbState{db: report.PackageDB{Type: typ, Path: p}}
	c.cur = d
	return d
}

func (c *collector) endDB(d *dbState) {
	if c.cur == d {
		c.cur = nil
	}
	if d.unreadable {
		return
	}
	c.dbs = append(c.dbs, d.db)
	if d.produced > 0 || !d.bad {
		c.readable++
	}
}

// markBad flags the database being read as incomplete.
func (c *collector) markBad() {
	if c.cur != nil {
		c.cur.bad = true
	}
}

func (c *collector) add(p []report.Package) {
	if c.cur != nil {
		c.cur.produced += len(p)
	}
	if room := maxPackages + 1 - len(c.pkgs); room < len(p) {
		if room < 0 {
			room = 0
		}
		p = p[:room]
	}
	c.pkgs = append(c.pkgs, p...)
}

func (c *collector) problem(msg string) {
	c.problems = append(c.problems, cleanReason(msg))
}

// fail records a database that exists but cannot be read at all.
func (c *collector) fail(p, msg string) {
	c.problem(p + ": " + msg)
}

// exists stats a canonical path. A missing path is not a problem; any other
// error is recorded and reported as absent.
func (c *collector) exists(p string) (fs.FileInfo, bool) {
	fi, err := c.res.stat(p)
	if err == nil {
		return fi, true
	}
	if !notExist(err) {
		c.fail(p, errMsg(err))
	}
	return nil, false
}

// errMsg describes an error without the host path of the file, which differs
// from the logical path when a container root is read.
func errMsg(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

func notExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// fileSize returns the size of an open file.
func fileSize(f *os.File) (int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
