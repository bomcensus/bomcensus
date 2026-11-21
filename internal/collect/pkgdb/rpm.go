// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// rpmDirs are the rpm database directories. On many systems one is a
// symlink to the other; each real directory is read once.
var rpmDirs = []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"}

// rpmDBFiles names the database files of one directory, newest backend first.
// Only the first one present is read: an older file next to a newer one is
// a leftover of a backend conversion.
var rpmDBFiles = []string{"rpmdb.sqlite", "Packages.db", "Packages"}

const (
	rpmSQLite = "sqlite"
	rpmNDB    = "ndb"
	rpmBDB    = "bdb"
)

func (c *collector) collectRPM() {
	seen := map[string]bool{}
	for _, d := range rpmDirs {
		dir := c.res.file(d)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		for _, name := range rpmDBFiles {
			p := c.res.file(path.Join(dir, name))
			fi, ok := c.exists(p)
			if !ok {
				continue
			}
			if !fi.Mode().IsRegular() {
				c.fail(p, "not a regular file")
				break
			}
			c.readRPM(p)
			break
		}
	}
}

func (c *collector) readRPM(p string) {
	db := c.startDB(report.PackageRPM, p)
	defer c.endDB(db)
	var (
		pkgs []report.Package
		bad  int
	)
	format, skipped, err := eachRPMBlob(c.ctx, c.env, p, func(blob []byte) bool {
		h, err := parseRPMHeader(blob, pkgTags)
		if err != nil {
			bad++
			return true
		}
		pk, ok, err := rpmPackage(h)
		if err != nil {
			bad++
			return true
		}
		if ok {
			pkgs = append(pkgs, pk)
		}
		return len(pkgs) <= maxPackages
	})
	if format == "" {
		c.fail(p, errMsg(err))
		db.unreadable = true
		return
	}
	bad += skipped
	var issues []string
	if err != nil {
		issues = append(issues, errMsg(err))
	}
	if bad > 0 {
		issues = append(issues, fmt.Sprintf("unreadable entries: %d", bad))
	}
	if format == rpmSQLite && walPending(c.env.Path(p)) {
		issues = append(issues, "changes in the write-ahead log were not read")
	}
	if len(issues) > 0 {
		c.problem(p + ": " + strings.Join(issues, ", "))
		c.markBad()
	}
	if err != nil && len(pkgs) == 0 {
		db.unreadable = true
	}
	c.add(pkgs)
	c.ix.addSource(indexSource{kind: srcRPM, path: p})
}

var errUnknownRPMDB = errors.New("unknown rpm database format")

// eachRPMBlob detects the format of an rpm database and calls fn for every
// stored header. format is empty when the file could not be opened as any
// known format; err then says why.
func eachRPMBlob(ctx context.Context, env *collect.Env, p string, fn func([]byte) bool) (format string, skipped int, err error) {
	real := env.Path(p)
	f, err := os.Open(real)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	size, err := fileSize(f)
	if err != nil {
		return "", 0, err
	}
	if isSQLite(f) {
		skipped, err = eachSQLite(ctx, real, fn)
		return rpmSQLite, skipped, err
	}
	if n, err := openNDB(f, size); err == nil {
		skipped, err = n.each(ctx, fn)
		return rpmNDB, skipped, err
	} else if !errors.Is(err, errNotNDB) {
		return "", 0, err
	}
	if b, err := openBDB(f, size); err == nil {
		skipped, err = b.each(ctx, fn)
		return rpmBDB, skipped, err
	} else if !errors.Is(err, errNotBDB) {
		return "", 0, err
	}
	return "", 0, errUnknownRPMDB
}
