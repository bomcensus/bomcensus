// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// rpm header tags of the file verification data (rpmtag.h).
const (
	tagFileStates      = 1029
	tagFileDigests     = 1035
	tagFileFlags       = 1037
	tagFileVerifyFlags = 1045
	tagFileDigestAlgo  = 5011
)

// rpm file flags (rpmfiles.h).
const (
	rpmFileConfig    = 1 << 0
	rpmFileMissingOK = 1 << 3
	rpmFileGhost     = 1 << 6
)

// rpmVerifyDigest is RPMVERIFY_FILEDIGEST: the content is verified.
const rpmVerifyDigest = 1 << 0

// rpmFileStateNormal is RPMFILE_STATE_NORMAL. Files in other states were
// not installed (--excludedocs, another arch's colour) or were replaced.
const rpmFileStateNormal = 0

// rpmDigestAlgos maps PGPHASHALGO values. Packages without the tag use MD5.
var rpmDigestAlgos = map[uint32]string{1: AlgoMD5, 2: AlgoSHA1, 8: AlgoSHA256, 9: AlgoSHA384, 10: AlgoSHA512}

var verifyTags = append([]int32{tagOldFilenames, tagFileModes, tagDirIndexes, tagBasenames, tagDirNames,
	tagFileStates, tagFileDigests, tagFileFlags, tagFileVerifyFlags, tagFileDigestAlgo}, pkgTags...)

func (e *Expected) readRPM(ctx context.Context) {
	seen := map[string]bool{}
	for _, d := range rpmDirs {
		dir := e.res.file(d)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		for _, name := range rpmDBFiles {
			p := e.res.file(path.Join(dir, name))
			if !e.exists(p) {
				continue
			}
			e.readRPMFile(ctx, p)
			break
		}
	}
}

func (e *Expected) readRPMFile(ctx context.Context, p string) {
	total := 0
	bad := 0
	format, skipped, err := eachRPMBlob(ctx, e.env, p, func(blob []byte) bool {
		h, err := parseRPMHeader(blob, verifyTags)
		if err != nil {
			bad++
			return true
		}
		pk, ok, err := rpmPackage(h)
		if err != nil {
			bad++
			return true
		}
		if !ok {
			return true
		}
		files, excluded, err := rpmExpectedFiles(h)
		if err != nil {
			bad++
			return true
		}
		total += len(files)
		if total > maxExpectedFiles {
			e.problem(fmt.Sprintf("%s: more than %d files, rest not checked", p, maxExpectedFiles))
			return false
		}
		e.Packages = append(e.Packages, &ExpectedPackage{
			Type: report.PackageRPM, Name: pk.Name, Version: pk.Version, Arch: pk.Arch,
			files: files, excluded: excluded,
		})
		return true
	})
	if format == "" {
		e.problem(p + ": " + errMsg(err))
		return
	}
	e.Databases = append(e.Databases, report.PackageDB{Type: report.PackageRPM, Path: p})
	var issues []string
	if err != nil {
		issues = append(issues, errMsg(err))
	}
	if bad += skipped; bad > 0 {
		issues = append(issues, fmt.Sprintf("unreadable entries: %d", bad))
	}
	if len(issues) > 0 {
		e.problem(p + ": " + strings.Join(issues, ", "))
	}
}

// rpmExpectedFiles returns the regular files with a digest that rpm would
// verify, and the number of regular files it leaves out.
func rpmExpectedFiles(h *rpmHeader) (files []ExpectedFile, excluded int, err error) {
	_, paths, err := rpmAllFiles(h)
	if err != nil {
		return nil, 0, err
	}
	modes, err := h.ints(tagFileModes)
	if err != nil {
		return nil, 0, err
	}
	digests, err := h.strs(tagFileDigests)
	if err != nil {
		return nil, 0, err
	}
	flags, err := h.ints(tagFileFlags)
	if err != nil {
		return nil, 0, err
	}
	verify, err := h.ints(tagFileVerifyFlags)
	if err != nil {
		return nil, 0, err
	}
	states, err := h.ints(tagFileStates)
	if err != nil {
		return nil, 0, err
	}
	algos, err := h.ints(tagFileDigestAlgo)
	if err != nil {
		return nil, 0, err
	}
	algo := AlgoMD5
	if len(algos) > 0 {
		a, ok := rpmDigestAlgos[algos[0]]
		if !ok {
			return nil, len(paths), nil
		}
		algo = a
	}
	at := func(v []uint32, i int, def uint32) uint32 {
		if i < len(v) {
			return v[i]
		}
		return def
	}
	for i, p := range paths {
		if i >= len(modes) || modes[i]&0o170000 != 0o100000 {
			continue // not a regular file
		}
		fl := at(flags, i, 0)
		d := ""
		if i < len(digests) {
			d = strings.ToLower(digests[i])
		}
		switch {
		case at(states, i, rpmFileStateNormal) != rpmFileStateNormal:
			continue
		case fl&(rpmFileConfig|rpmFileGhost) != 0,
			at(verify, i, ^uint32(0))&rpmVerifyDigest == 0,
			d == "" || !validHex([]byte(d), len(d)/2):
			excluded++
			continue
		}
		files = append(files, ExpectedFile{Path: p, Algo: algo, Digest: d, MissingOK: fl&rpmFileMissingOK != 0})
	}
	return files, excluded, nil
}

// rpmAllFiles returns the name and every path of a header, in header order,
// directories included, so that the indexes match the per-file tags.
func rpmAllFiles(h *rpmHeader) (name string, files []string, err error) {
	name, err = h.str(tagName)
	if err != nil {
		return "", nil, err
	}
	base, err := h.strs(tagBasenames)
	if err != nil {
		return name, nil, err
	}
	if len(base) == 0 {
		old, err := h.strs(tagOldFilenames)
		return name, old, err
	}
	dirs, err := h.strs(tagDirNames)
	if err != nil {
		return name, nil, err
	}
	idx, err := h.ints(tagDirIndexes)
	if err != nil {
		return name, nil, err
	}
	if len(idx) != len(base) {
		return name, nil, fmt.Errorf("%w: file list sizes differ", errHeader)
	}
	files = make([]string, len(base))
	for i, b := range base {
		if int(idx[i]) >= len(dirs) {
			return name, nil, fmt.Errorf("%w: directory index out of range", errHeader)
		}
		files[i] = dirs[idx[i]] + b
	}
	return name, files, nil
}
