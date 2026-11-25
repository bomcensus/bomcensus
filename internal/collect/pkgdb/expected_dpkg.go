// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

const dpkgDiversions = "/var/lib/dpkg/diversions"

// dpkgVerified lists the dpkg states in which the files of a package are
// all in place. half-installed and unpacked packages are in the middle of
// an operation and are skipped.
var dpkgVerified = map[string]bool{
	"installed":        true,
	"triggers-awaited": true,
	"triggers-pending": true,
}

type dpkgState struct {
	info      string
	conffiles map[string]bool
	// diversions maps a diverted path to where the file of every package
	// other than the diverting one is.
	diversions map[string]dpkgDiversion
}

type dpkgDiversion struct {
	to, pkg string
}

type dpkgFileSource struct {
	name, arch string
}

type dpkgVerifyStanza struct {
	name, arch, version, state string
	conffiles                  []string
	inConffiles, malformed     bool
}

// readDpkg reads /var/lib/dpkg/status with the Conffiles of each package,
// and the diversions. Distroless status.d layouts carry no file lists and
// are not checked.
func (e *Expected) readDpkg(ctx context.Context) {
	statusPath := e.res.file(dpkgStatus)
	if !e.exists(statusPath) {
		return
	}
	f, err := os.Open(e.env.Path(statusPath))
	if err != nil {
		e.problem(statusPath + ": " + errMsg(err))
		return
	}
	defer f.Close()
	e.Databases = append(e.Databases, report.PackageDB{Type: report.PackageDeb, Path: statusPath})
	st := &dpkgState{info: e.res.file(dpkgInfo), conffiles: map[string]bool{}}
	e.dpkg = st

	var cur dpkgVerifyStanza
	bad := 0
	emit := func() {
		s := cur
		cur = dpkgVerifyStanza{}
		if s.name == "" && s.version == "" && s.state == "" {
			return
		}
		for _, c := range s.conffiles {
			st.conffiles[c] = true
		}
		if s.malformed || s.name == "" {
			bad++
			return
		}
		if !dpkgVerified[s.state] {
			return
		}
		if s.version == "" {
			bad++
			return
		}
		e.Packages = append(e.Packages, &ExpectedPackage{
			Type: report.PackageDeb, Name: s.name, Version: s.version, Arch: s.arch,
			dpkg: &dpkgFileSource{name: s.name, arch: s.arch},
		})
	}
	lr := newLineReader(f)
	n := 0
	for {
		line, ok := lr.next()
		if !ok {
			break
		}
		if n++; n%4096 == 0 && ctx.Err() != nil {
			e.problem(statusPath + ": " + ctx.Err().Error())
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			emit()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur.inConffiles {
				// " /etc/foo <md5> [obsolete|remove-on-upgrade]"
				if fs := strings.Fields(string(line)); len(fs) >= 2 && path.IsAbs(fs[0]) {
					cur.conffiles = append(cur.conffiles, path.Clean(fs[0]))
				}
			}
			continue
		}
		cur.inConffiles = false
		i := bytes.IndexByte(line, ':')
		if i <= 0 {
			cur.malformed = true
			continue
		}
		val := line[i+1:]
		switch strings.ToLower(string(bytes.TrimSpace(line[:i]))) {
		case "package":
			cur.name = clean(val)
		case "version":
			cur.version = clean(val)
		case "architecture":
			cur.arch = clean(val)
		case "status":
			if fs := strings.Fields(string(val)); len(fs) == 3 {
				cur.state = fs[2]
			} else {
				cur.malformed = true
			}
		case "conffiles":
			cur.inConffiles = true
		}
	}
	emit()
	if lr.err != nil {
		e.problem(statusPath + ": " + errMsg(lr.err))
	}
	if lr.long {
		e.problem(statusPath + ": line too long")
	}
	if bad > 0 {
		e.problem(fmt.Sprintf("%s: malformed entries: %d", statusPath, bad))
	}
	e.readDiversions()
}

// readDiversions reads the diversions database: groups of three lines,
// the diverted path, where it was moved and the diverting package (":" for
// a local diversion).
func (e *Expected) readDiversions() {
	p := e.res.file(dpkgDiversions)
	f, err := os.Open(e.env.Path(p))
	if err != nil {
		if !notExist(err) {
			e.problem(p + ": " + errMsg(err))
		}
		return
	}
	defer f.Close()
	lr := newLineReader(f)
	var group []string
	for {
		line, ok := lr.next()
		if !ok {
			break
		}
		group = append(group, string(line))
		if len(group) < 3 {
			continue
		}
		from, to, pkg := path.Clean(group[0]), path.Clean(group[1]), group[2]
		group = group[:0]
		if !path.IsAbs(from) || !path.IsAbs(to) {
			continue
		}
		if e.dpkg.diversions == nil {
			e.dpkg.diversions = map[string]dpkgDiversion{}
		}
		e.dpkg.diversions[from] = dpkgDiversion{to: to, pkg: pkg}
	}
	if lr.err != nil || len(group) != 0 {
		e.problem(p + ": malformed")
	}
}

// dpkgFiles reads <pkg>[:<arch>].md5sums. Only paths still in the
// package's .list are checked: a file taken over by another package stays
// in the old package's md5sums but leaves its list.
func (e *Expected) dpkgFiles(p *ExpectedPackage) ([]ExpectedFile, int, error) {
	st := e.dpkg
	src := p.dpkg
	base := ""
	for _, cand := range []string{src.name + ":" + src.arch, src.name} {
		if src.arch == "" && cand != src.name {
			continue
		}
		if _, err := e.res.stat(path.Join(st.info, cand+".list")); err == nil {
			base = cand
			break
		}
	}
	if base == "" {
		return nil, 0, nil
	}
	listed, err := readDpkgList(e.env.Path(path.Join(st.info, base+".list")))
	if err != nil {
		return nil, 0, fmt.Errorf("%s.list: %s", base, errMsg(err))
	}
	f, err := os.Open(e.env.Path(path.Join(st.info, base+".md5sums")))
	if err != nil {
		if notExist(err) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("%s.md5sums: %s", base, errMsg(err))
	}
	defer f.Close()
	var (
		files    []ExpectedFile
		excluded int
	)
	lr := newLineReader(f)
	for {
		line, ok := lr.next()
		if !ok {
			break
		}
		sum, rel, found := bytes.Cut(line, []byte("  "))
		if !found || len(rel) == 0 || !validHex(sum, 16) {
			continue
		}
		fp := path.Clean("/" + strings.TrimPrefix(string(rel), "/"))
		if !listed[fp] {
			continue
		}
		if st.conffiles[fp] {
			excluded++
			continue
		}
		if d, ok := st.diversions[fp]; ok && d.pkg != src.name {
			fp = d.to
		}
		files = append(files, ExpectedFile{Path: fp, Algo: AlgoMD5, Digest: strings.ToLower(string(sum))})
	}
	if lr.err != nil {
		return nil, 0, fmt.Errorf("%s.md5sums: %s", base, errMsg(lr.err))
	}
	return files, excluded, nil
}

func readDpkgList(real string) (map[string]bool, error) {
	f, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	lr := newLineReader(f)
	for {
		line, ok := lr.next()
		if !ok {
			break
		}
		if len(line) > 0 && line[0] == '/' {
			out[path.Clean(string(line))] = true
		}
	}
	return out, lr.err
}

// validHex reports whether b is the hex encoding of n bytes.
func validHex(b []byte, n int) bool {
	if len(b) != 2*n {
		return false
	}
	_, err := hex.DecodeString(string(b))
	return err == nil
}
