// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

func (e *Expected) readAPK(ctx context.Context) {
	seen := map[string]bool{}
	for _, loc := range apkLocations {
		p := e.res.file(loc)
		if seen[p] {
			continue
		}
		seen[p] = true
		if !e.exists(p) {
			continue
		}
		e.readAPKFile(ctx, p)
	}
}

// readAPKFile reads the installed database with the checksum (Z:) of each
// file record (R:). apk has no conffile marker, so /etc is left out. A
// symlink's checksum is that of its target name, so symlinks are skipped by
// the check (MaySymlink).
func (e *Expected) readAPKFile(ctx context.Context, p string) {
	f, err := os.Open(e.env.Path(p))
	if err != nil {
		e.problem(p + ": " + errMsg(err))
		return
	}
	defer f.Close()
	e.Databases = append(e.Databases, report.PackageDB{Type: report.PackageAPK, Path: p})

	var (
		cur      *ExpectedPackage
		dir      string
		file     string // last R: record, until its Z: line
		total    int
		bad      int
		lr       = newLineReader(f)
		n        int
		inStanza bool
	)
	flush := func() {
		if cur != nil && cur.Name != "" && cur.Version != "" {
			e.Packages = append(e.Packages, cur)
		} else if inStanza {
			bad++
		}
		cur, dir, file, inStanza = nil, "", "", false
	}
	for {
		line, ok := lr.next()
		if !ok {
			break
		}
		if n++; n%4096 == 0 && ctx.Err() != nil {
			e.problem(p + ": " + ctx.Err().Error())
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		inStanza = true
		if cur == nil {
			cur = &ExpectedPackage{Type: report.PackageAPK}
		}
		val := string(line[2:])
		switch line[0] {
		case 'P':
			cur.Name = cleanString(val)
		case 'V':
			cur.Version = cleanString(val)
		case 'A':
			cur.Arch = cleanString(val)
		case 'F':
			dir, file = strings.Trim(val, "/"), ""
		case 'R':
			if val == "" {
				file = ""
				continue
			}
			file = "/" + val
			if dir != "" {
				file = "/" + dir + "/" + val
			}
		case 'Z':
			if file == "" {
				continue
			}
			fp := file
			file = ""
			if fp == "/etc" || strings.HasPrefix(fp, "/etc/") {
				cur.excluded++
				continue
			}
			algo, digest, ok := apkChecksum(val)
			if !ok {
				cur.excluded++
				continue
			}
			if total++; total > maxExpectedFiles {
				e.problem(fmt.Sprintf("%s: more than %d files, rest not checked", p, maxExpectedFiles))
				return
			}
			cur.files = append(cur.files, ExpectedFile{Path: fp, Algo: algo, Digest: digest, MaySymlink: true})
		}
	}
	flush()
	if lr.err != nil {
		e.problem(p + ": " + errMsg(lr.err))
	}
	if bad > 0 {
		e.problem(fmt.Sprintf("%s: malformed entries: %d", p, bad))
	}
}

// apkChecksum decodes a Z: value: "Q1" + base64 SHA-1, "Q2" + base64
// SHA-256, or a hex MD5 in old databases.
func apkChecksum(v string) (algo, digest string, ok bool) {
	decode := func(s string, n int) (string, bool) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) != n {
			return "", false
		}
		return hex.EncodeToString(b), true
	}
	switch {
	case strings.HasPrefix(v, "Q1"):
		d, ok := decode(v[2:], 20)
		return AlgoSHA1, d, ok
	case strings.HasPrefix(v, "Q2"):
		d, ok := decode(v[2:], 32)
		return AlgoSHA256, d, ok
	case validHex([]byte(v), 16):
		return AlgoMD5, strings.ToLower(v), true
	}
	return "", "", false
}
