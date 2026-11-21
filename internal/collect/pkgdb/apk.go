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
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// apkLocations are the installed databases of apk, in order of preference.
var apkLocations = []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"}

type apkParse struct {
	pkgs         []report.Package
	bad          int
	long         bool
	unterminated bool
}

// parseAPKInstalled parses the apk installed database: blank-line separated
// records of "K:value" lines.
func parseAPKInstalled(ctx context.Context, r io.Reader) (apkParse, error) {
	var (
		res apkParse
		st  apkStanza
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
			st.emit(&res)
			continue
		}
		st.seen = true
		if len(line) < 2 || line[1] != ':' {
			st.malformed = true
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'P':
			st.name = clean(val)
		case 'V':
			st.version = clean(val)
		case 'A':
			st.arch = clean(val)
		case 'o':
			st.origin = clean(val)
		case 'm':
			st.maintainer = clean(val)
		}
	}
	st.emit(&res)
	res.long = lr.long
	res.unterminated = lr.unterminated
	return res, lr.err
}

type apkStanza struct {
	seen, malformed                         bool
	name, version, arch, origin, maintainer string
}

func (st *apkStanza) emit(res *apkParse) {
	defer func() { *st = apkStanza{} }()
	if !st.seen {
		return
	}
	if st.malformed || st.name == "" || st.version == "" {
		res.bad++
		return
	}
	p := report.Package{
		Type:          report.PackageAPK,
		Name:          st.name,
		Version:       st.version,
		Arch:          st.arch,
		SourceName:    st.origin,
		SourceVersion: st.version,
		Maintainer:    st.maintainer,
	}
	if p.SourceName == "" {
		p.SourceName = p.Name
	}
	res.pkgs = append(res.pkgs, p)
}

// parseAPKFiles calls fn for every file record (F: directory, R: file).
func parseAPKFiles(ctx context.Context, r io.Reader, fn func(pkg, file string) bool) error {
	lr := newLineReader(r)
	var pkg, dir string
	n := 0
	for {
		line, ok := lr.next()
		if !ok {
			return lr.err
		}
		if n++; n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if len(bytes.TrimSpace(line)) == 0 {
			pkg, dir = "", ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		val := string(line[2:])
		switch line[0] {
		case 'P':
			pkg = cleanString(val)
		case 'F':
			dir = strings.Trim(val, "/")
		case 'R':
			if pkg == "" || val == "" {
				continue
			}
			p := "/" + val
			if dir != "" {
				p = "/" + dir + "/" + val
			}
			if !fn(pkg, p) {
				return nil
			}
		}
	}
}

func (c *collector) collectAPK() {
	seen := map[string]bool{}
	for _, loc := range apkLocations {
		p := c.res.file(loc)
		if seen[p] {
			continue
		}
		seen[p] = true
		fi, ok := c.exists(p)
		if !ok {
			continue
		}
		if !fi.Mode().IsRegular() {
			c.fail(p, "not a regular file")
			continue
		}
		c.readAPK(p)
	}
}

func (c *collector) readAPK(p string) {
	db := c.startDB(report.PackageAPK, p)
	defer c.endDB(db)
	f, err := os.Open(c.env.Path(p))
	if err != nil {
		c.fail(p, errMsg(err))
		db.unreadable = true
		return
	}
	defer f.Close()
	res, err := parseAPKInstalled(c.ctx, f)
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
	if res.unterminated {
		issues = append(issues, "file ends without a newline")
	}
	if len(issues) > 0 {
		c.problem(p + ": " + strings.Join(issues, ", "))
		c.markBad()
	}
	c.add(res.pkgs)
	c.ix.addSource(indexSource{kind: srcAPK, path: p})
}
