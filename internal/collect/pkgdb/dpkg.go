// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

const (
	dpkgStatus  = "/var/lib/dpkg/status"
	dpkgStatusD = "/var/lib/dpkg/status.d"
	dpkgInfo    = "/var/lib/dpkg/info"

	// maxStatusDFiles bounds the number of files read from status.d.
	maxStatusDFiles = 100_000
)

// dpkgPresent lists the dpkg states in which the package files are on disk.
// "not-installed" and "config-files" are left out: only conffiles remain.
var dpkgPresent = map[string]bool{
	"installed":        true,
	"half-installed":   true,
	"unpacked":         true,
	"half-configured":  true,
	"triggers-awaited": true,
	"triggers-pending": true,
}

const dpkgNormalStatus = "install ok installed"

// dpkgParse is the result of parsing one status file.
type dpkgParse struct {
	pkgs []report.Package
	// bad counts stanzas that could not be used.
	bad          int
	long         bool
	unterminated bool
}

// parseDpkgStatus parses dpkg control stanzas. requireStatus is false for
// distroless status.d files, which carry no Status field.
func parseDpkgStatus(ctx context.Context, r io.Reader, requireStatus bool) (dpkgParse, error) {
	var (
		res dpkgParse
		st  dpkgStanza
		lr  = newLineReader(r)
		n   int
	)
	for {
		line, ok := lr.next()
		if !ok {
			break
		}
		if n++; n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return res, err
			}
		}
		if len(bytes.TrimSpace(line)) == 0 {
			st.emit(&res, requireStatus)
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of a multi-line field
		}
		st.seen = true
		i := bytes.IndexByte(line, ':')
		if i <= 0 {
			st.malformed = true
			continue
		}
		val := line[i+1:]
		switch strings.ToLower(string(bytes.TrimSpace(line[:i]))) {
		case "package":
			st.name = clean(val)
		case "status":
			st.status = clean(val)
			st.hasStatus = true
		case "version":
			st.version = clean(val)
		case "architecture":
			st.arch = clean(val)
		case "source":
			st.source = clean(val)
		case "maintainer":
			st.maintainer = clean(val)
		}
	}
	st.emit(&res, requireStatus)
	res.long = lr.long
	res.unterminated = lr.unterminated
	return res, lr.err
}

type dpkgStanza struct {
	seen, malformed, hasStatus                      bool
	name, status, version, arch, source, maintainer string
}

func (st *dpkgStanza) emit(res *dpkgParse, requireStatus bool) {
	defer func() { *st = dpkgStanza{} }()
	if !st.seen {
		return
	}
	if st.malformed || st.name == "" || (requireStatus && !st.hasStatus) {
		res.bad++
		return
	}
	status := ""
	if st.hasStatus {
		f := strings.Fields(st.status)
		if len(f) != 3 {
			res.bad++
			return
		}
		if !dpkgPresent[f[2]] {
			return
		}
		if norm := strings.Join(f, " "); norm != dpkgNormalStatus {
			status = norm
		}
	}
	if st.version == "" {
		res.bad++
		return
	}
	p := report.Package{
		Type:       report.PackageDeb,
		Name:       st.name,
		Version:    st.version,
		Arch:       st.arch,
		Maintainer: st.maintainer,
		Status:     status,
	}
	p.SourceName, p.SourceVersion = parseDpkgSource(st.source)
	if p.SourceName == "" {
		p.SourceName = p.Name
	}
	if p.SourceVersion == "" {
		p.SourceVersion = p.Version
	}
	res.pkgs = append(res.pkgs, p)
}

// parseDpkgSource splits a Source field: "name" or "name (version)".
func parseDpkgSource(v string) (name, version string) {
	v = strings.TrimSpace(v)
	i := strings.IndexAny(v, " \t(")
	if i < 0 {
		return v, ""
	}
	name = v[:i]
	rest := strings.TrimSpace(v[i:])
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		version = strings.TrimSpace(rest[1 : len(rest)-1])
	}
	return name, version
}

// collectDpkg reads /var/lib/dpkg/status and the distroless status.d layout.
func (c *collector) collectDpkg() {
	statusPath := c.res.file(dpkgStatus)
	if fi, ok := c.exists(statusPath); ok {
		if !fi.Mode().IsRegular() {
			c.fail(statusPath, "not a regular file")
		} else {
			c.readDpkgFile(statusPath, true, "")
		}
	}

	dir := c.res.file(dpkgStatusD)
	fi, ok := c.exists(dir)
	if !ok {
		return
	}
	if !fi.IsDir() {
		c.fail(dir, "not a directory")
		return
	}
	ents, err := os.ReadDir(c.env.Path(dir))
	if err != nil {
		c.fail(dir, errMsg(err))
		return
	}
	db := c.startDB(report.PackageDeb, dir)
	files := 0
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".md5sums") {
			continue
		}
		if files++; files > maxStatusDFiles {
			c.problem(fmt.Sprintf("%s: more than %d files, rest skipped", dir, maxStatusDFiles))
			db.bad = true
			break
		}
		p := path.Join(dir, name)
		if fi, err := os.Stat(c.env.Path(p)); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		c.readDpkgFile(p, false, name)
		if c.ctx.Err() != nil {
			break
		}
	}
	c.endDB(db)
	c.ix.addSource(indexSource{kind: srcDpkgStatusD, path: dir})
}

// readDpkgFile parses one status file. statusDName is the file name inside
// status.d, empty for the main status file.
func (c *collector) readDpkgFile(p string, requireStatus bool, statusDName string) {
	var db *dbState
	if statusDName == "" {
		db = c.startDB(report.PackageDeb, p)
		defer c.endDB(db)
	}
	f, err := os.Open(c.env.Path(p))
	if err != nil {
		c.fail(p, errMsg(err))
		if db != nil {
			db.unreadable = true
		} else {
			c.markBad()
		}
		return
	}
	defer f.Close()
	res, err := parseDpkgStatus(c.ctx, f, requireStatus)
	var issues []string
	if err != nil {
		issues = append(issues, errMsg(err))
	}
	if res.bad > 0 {
		issues = append(issues, fmt.Sprintf("malformed entries: %d", res.bad))
	}
	if res.long {
		issues = append(issues, "line too long")
	}
	if res.unterminated && requireStatus {
		issues = append(issues, "file ends without a newline")
	}
	if len(issues) > 0 {
		c.problem(p + ": " + strings.Join(issues, ", "))
		c.markBad()
	}
	c.add(res.pkgs)
	for _, pk := range res.pkgs {
		c.ix.addInstalled(pk.Name)
	}
	if statusDName != "" && len(res.pkgs) > 0 {
		c.ix.addStatusDName(statusDName, res.pkgs[0].Name)
	}
	if statusDName == "" {
		c.ix.addSource(indexSource{kind: srcDpkgInfo, path: c.res.file(dpkgInfo)})
	}
}
