// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package artifact

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// archiveLimits bound the work spent on one Java archive. Exceeding a limit
// leaves the rest of that archive unread and makes the section partial.
type archiveLimits struct {
	// MaxDepth is the number of nesting levels below the file on disk.
	MaxDepth int
	// MaxEntries is the largest entry count of one archive.
	MaxEntries int
	// MaxTotalBytes bounds the bytes read from entries of one file on disk,
	// all nesting levels together.
	MaxTotalBytes int64
	// MaxRatio is the largest uncompressed/compressed ratio of an entry
	// larger than ratioFloor.
	MaxRatio uint64
	// MaxNestedSize is the largest compressed nested archive that is
	// inflated into memory. Stored nested archives are read in place.
	MaxNestedSize int64
	// MaxMetaSize bounds pom.properties and MANIFEST.MF.
	MaxMetaSize int64
}

var defaultArchiveLimits = archiveLimits{
	MaxDepth:      3,
	MaxEntries:    100_000,
	MaxTotalBytes: 1 << 30,
	MaxRatio:      100,
	MaxNestedSize: 64 << 20,
	MaxMetaSize:   1 << 20,
}

// ratioFloor exempts small entries from the ratio check: they cannot be
// bombs and text compresses well.
const ratioFloor = 1 << 20

// Limit kinds, as reported in the section reason.
const (
	limitDepth   = "depth"
	limitEntries = "entry count"
	limitSize    = "size"
	limitRatio   = "compression ratio"
)

var errEntryTooLarge = errors.New("artifact: archive entry too large")

// jarResult is what one file on disk yields. It is cached per file.
type jarResult struct {
	// Artifacts have no Path, hashes of the outer file or usage flags.
	Artifacts []report.Artifact `json:"a,omitempty"`
	Limits    []string          `json:"l,omitempty"`
	Corrupt   int               `json:"c,omitempty"`
}

type jarScan struct {
	ctx     context.Context
	lim     archiveLimits
	budget  int64
	limits  map[string]bool
	corrupt int
	out     []report.Artifact
}

// scanJar reads the archive in ra. name is the file name on disk.
func scanJar(ctx context.Context, ra io.ReaderAt, size int64, name string, lim archiveLimits) jarResult {
	s := &jarScan{ctx: ctx, lim: lim, budget: lim.MaxTotalBytes, limits: map[string]bool{}}
	s.archive(ra, size, name, nil, 0, "")
	res := jarResult{Artifacts: s.out, Corrupt: s.corrupt}
	for k := range s.limits {
		res.Limits = append(res.Limits, k)
	}
	slices.Sort(res.Limits)
	return res
}

func (s *jarScan) hit(kind string) { s.limits[kind] = true }

func isArchiveName(n string) bool {
	l := strings.ToLower(n)
	return strings.HasSuffix(l, ".jar") || strings.HasSuffix(l, ".war") || strings.HasSuffix(l, ".ear")
}

func isPomProperties(n string) bool {
	return strings.HasPrefix(n, "META-INF/maven/") && strings.HasSuffix(n, "/pom.properties")
}

// archive identifies one archive and descends into its nested archives.
// nested is the entry path of this archive (nil for the file on disk).
func (s *jarScan) archive(ra io.ReaderAt, size int64, name string, nested []string, depth int, sum string) {
	art := report.Artifact{Kind: report.ArtifactJar, Nested: nested, Size: size, SHA1: sum}
	base := path.Base(name)

	zr, err := zip.NewReader(ra, size)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		s.corrupt++
		identifyByName(&art, base)
		s.out = append(s.out, art)
		return
	}
	if len(zr.File) > s.lim.MaxEntries {
		s.hit(limitEntries)
		identifyByName(&art, base)
		s.out = append(s.out, art)
		return
	}

	var poms []pom
	var manifest map[string]string
	var children []*zip.File
	for _, f := range zr.File {
		switch {
		case f.FileInfo().IsDir():
		case isPomProperties(f.Name):
			if b, ok := s.readMeta(f); ok {
				p := parsePom(b)
				p.entry = f.Name
				if p.artifactID != "" {
					poms = append(poms, p)
				}
			}
		case strings.EqualFold(f.Name, "META-INF/MANIFEST.MF"):
			if b, ok := s.readMeta(f); ok {
				manifest = parseManifest(b)
			}
		case isArchiveName(f.Name):
			children = append(children, f)
		}
	}

	embedded := identify(&art, base, poms, manifest)
	s.out = append(s.out, art)
	for _, p := range embedded {
		e := report.Artifact{Kind: report.ArtifactJar, Nested: append(slices.Clone(nested), p.entry)}
		p.apply(&e)
		s.out = append(s.out, e)
	}

	for _, f := range children {
		if s.ctx.Err() != nil {
			return
		}
		s.child(ra, f, nested, depth)
	}
}

// readMeta reads a small metadata entry within the limits.
func (s *jarScan) readMeta(f *zip.File) ([]byte, bool) {
	if !s.entryAllowed(f) {
		return nil, false
	}
	b, err := readSmallEntry(f, s.lim.MaxMetaSize)
	if errors.Is(err, errEntryTooLarge) {
		s.hit(limitSize)
		return nil, false
	}
	if err != nil {
		s.corrupt++
		return nil, false
	}
	s.budget -= int64(len(b))
	return b, true
}

// entryAllowed checks the ratio and budget limits before an entry is read.
func (s *jarScan) entryAllowed(f *zip.File) bool {
	if f.UncompressedSize64 > ratioFloor &&
		(f.CompressedSize64 == 0 || f.UncompressedSize64/f.CompressedSize64 > s.lim.MaxRatio) {
		s.hit(limitRatio)
		return false
	}
	if f.UncompressedSize64 > uint64(max(s.budget, 0)) {
		s.hit(limitSize)
		return false
	}
	return true
}

// child handles a nested archive entry.
func (s *jarScan) child(ra io.ReaderAt, f *zip.File, nested []string, depth int) {
	entryPath := append(slices.Clone(nested), f.Name)
	byName := func() {
		art := report.Artifact{Kind: report.ArtifactJar, Nested: entryPath, Size: int64(f.UncompressedSize64)}
		identifyByName(&art, f.Name)
		s.out = append(s.out, art)
	}
	if depth+1 > s.lim.MaxDepth {
		s.hit(limitDepth)
		byName()
		return
	}
	if f.Flags&0x1 != 0 { // encrypted
		s.corrupt++
		byName()
		return
	}
	if !s.entryAllowed(f) {
		byName()
		return
	}
	size := int64(f.UncompressedSize64)

	if f.Method == zip.Store && f.CompressedSize64 == f.UncompressedSize64 {
		// Stored, as Spring Boot requires for BOOT-INF/lib: read in place.
		off, err := f.DataOffset()
		if err != nil {
			s.corrupt++
			byName()
			return
		}
		sr := io.NewSectionReader(ra, off, size)
		h := sha1.New()
		n, err := io.Copy(h, sr)
		s.budget -= n
		if err != nil || n != size {
			s.corrupt++
			byName()
			return
		}
		s.archive(sr, size, f.Name, entryPath, depth+1, hex.EncodeToString(h.Sum(nil)))
		return
	}

	if size > s.lim.MaxNestedSize {
		s.hit(limitSize)
		byName()
		return
	}
	rc, err := f.Open()
	if err != nil {
		s.corrupt++
		byName()
		return
	}
	var buf bytes.Buffer
	buf.Grow(int(size))
	n, err := io.Copy(&buf, io.LimitReader(rc, size+1))
	rc.Close()
	s.budget -= n
	if err != nil || n != size {
		s.corrupt++
		byName()
		return
	}
	sum := sha1.Sum(buf.Bytes())
	s.archive(bytes.NewReader(buf.Bytes()), size, f.Name, entryPath, depth+1, hex.EncodeToString(sum[:]))
}

// pom is one META-INF/maven/<group>/<artifact>/pom.properties.
type pom struct {
	entry      string
	groupID    string
	artifactID string
	version    string
}

func (p pom) apply(a *report.Artifact) {
	a.Name = p.artifactID
	a.GroupID = p.groupID
	a.ArtifactID = p.artifactID
	a.Version = p.version
	a.Method = report.MethodManifest
	if p.groupID != "" && p.version != "" {
		a.PURL = "pkg:maven/" + p.groupID + "/" + p.artifactID + "@" + purlEscape(p.version)
	}
}

func parsePom(b []byte) pom {
	props := parseProperties(b)
	return pom{groupID: props["groupId"], artifactID: props["artifactId"], version: props["version"]}
}

// parseProperties reads the subset of the Java properties format that Maven
// writes: one key=value per line, # and ! comments.
func parseProperties(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1024), len(b)+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			continue
		}
		out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
	}
	return out
}

// parseManifest returns the main section of a MANIFEST.MF with lower-case
// attribute names.
func parseManifest(b []byte) map[string]string {
	out := map[string]string{}
	var key string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1024), len(b)+1)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			break
		}
		if line[0] == ' ' {
			if key != "" {
				out[key] += line[1:]
			}
			continue
		}
		i := strings.Index(line, ":")
		if i <= 0 {
			key = ""
			continue
		}
		key = strings.ToLower(strings.TrimSpace(line[:i]))
		out[key] = strings.TrimSpace(line[i+1:])
	}
	return out
}

// identify fills name and version from, in order, pom.properties, the
// manifest and the file name. It returns the coordinates of other projects
// embedded in a shaded archive.
func identify(a *report.Artifact, base string, poms []pom, mf map[string]string) []pom {
	fnName, fnVersion := splitArchiveName(base)
	switch len(poms) {
	case 0:
	case 1:
		poms[0].apply(a)
		return nil
	default:
		// A shaded archive: the outer project is the one named like the
		// file, if any.
		best := -1
		for i, p := range poms {
			if p.artifactID != fnName {
				continue
			}
			if best < 0 || p.version == fnVersion {
				best = i
			}
		}
		if best >= 0 {
			poms[best].apply(a)
			return slices.Delete(slices.Clone(poms), best, best+1)
		}
	}

	title := mf["implementation-title"]
	if title == "" {
		title, _, _ = strings.Cut(mf["bundle-symbolicname"], ";")
		title = strings.TrimSpace(title)
	}
	if title == "" {
		title = mf["bundle-name"]
	}
	version := mf["implementation-version"]
	if version == "" {
		version = mf["bundle-version"]
	}
	if title != "" || version != "" {
		a.Name = cmpOr(title, fnName)
		a.Version = cmpOr(version, fnVersion)
		a.Method = report.MethodManifest
	} else {
		a.Name, a.Version = fnName, fnVersion
		a.Method = report.MethodStatic
	}
	if len(poms) > 1 {
		return poms
	}
	return nil
}

func identifyByName(a *report.Artifact, name string) {
	a.Name, a.Version = splitArchiveName(path.Base(name))
	a.Method = report.MethodStatic
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// splitArchiveName splits "commons-lang3-3.12.0.jar" into name and version.
// The version starts at the first "-<digit>" after which the rest is a
// version: dot-separated parts, then "-qualifier" parts that start with a
// letter ("31.1-jre", "2.0.61.Final-linux-x86_64").
func splitArchiveName(base string) (string, string) {
	stem := base
	if isArchiveName(stem) {
		stem = stem[:len(stem)-4]
	}
	for i := 0; i+1 < len(stem); i++ {
		if stem[i] == '-' && i > 0 && stem[i+1] >= '0' && stem[i+1] <= '9' && isVersion(stem[i+1:]) {
			return stem[:i], stem[i+1:]
		}
	}
	return stem, ""
}

func isVersion(s string) bool {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p == "" {
			return false
		}
		if i > 0 && !(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') {
			return false
		}
		for _, r := range p {
			if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '.' || r == '_' || r == '+') {
				return false
			}
		}
	}
	return true
}
