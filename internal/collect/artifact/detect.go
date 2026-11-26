// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package artifact

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/bomcensus/bomcensus/internal/detectors"
)

// Detector recognizes one piece of known software by file name and finds its
// version. Detectors are built from a table (detectors.go, Load).
type Detector struct {
	// ID is stable; it is reported in Artifact.Detector and keys the cache.
	ID string
	// Name is the reported software name unless a matching Rule overrides it.
	Name string
	// Names are path.Match patterns for the base name of the file.
	Names []string
	// Paths, when set, are path.Match patterns for the trailing components
	// of the logical path ("bin/java"); one of them must match.
	Paths []string
	// Archive makes the detector match Java archives instead of ELF
	// executables.
	Archive bool

	// Exec is the argument list passed after the program name. Empty means
	// the file is never executed.
	Exec []string
	// Env lists environment variables for the version command. The child
	// gets these and nothing else.
	Env []EnvVar
	// Parse extracts the version from the command output: stdout, then
	// stderr.
	Parse []Rule
	// AddressSpaceMB overrides the address space limit of the version
	// command.
	AddressSpaceMB int

	// Static rules are tried in order; the first that yields a version wins.
	Static []StaticRule

	// PURL and CPE are templates; {version} is replaced.
	PURL string
	CPE  string

	// constrained is set for detectors that are not in the built-in
	// table (detectors.Entry.Builtin): their side files are opened with
	// openSideConstrained and what they capture must be
	// detectors.ValidCaptured.
	constrained bool
	// cacheTag tells the cached static results of a detector that is not
	// built in apart from those of another detector with the same id.
	cacheTag string
}

// EnvVar is an environment variable derived from the install path.
type EnvVar struct {
	Name string
	// Up is the number of directories above the file: 2 turns
	// /opt/jdk/bin/java into /opt/jdk.
	Up int
}

// Rule extracts a version with a regular expression: the group named
// "version" if there is one, else the first group. A group named "build"
// captures the vendor build or revision number (Artifact.Build).
type Rule struct {
	Pattern *regexp.Regexp
	// Name, PURL and CPE override the detector's values when set.
	Name string
	PURL string
	CPE  string
}

// StaticRule reads a version without running anything.
type StaticRule struct {
	// File is a path relative to the directory of the matched file and may
	// contain glob characters ("../lib/libruby.so*"). Empty means the
	// matched file itself.
	File string
	// Entry reads one entry of a zip archive (File, or the matched file).
	Entry string
	// BuildSetting matches Rules against one Go build setting ("-ldflags")
	// of the matched file.
	BuildSetting string
	// GoMain takes the main module version of a Go binary.
	GoMain bool
	Rules  []Rule
	// Limit bounds the bytes scanned. Zero means the default for the kind
	// of source.
	Limit int64
}

const (
	defaultSideFileLimit = detectors.SideFileLimit
	defaultBinaryLimit   = detectors.BinaryLimit
	scanChunk            = 1 << 20
	scanOverlap          = 4 << 10
)

// matches reports whether d applies to the logical path p.
func (d *Detector) matches(p string) bool {
	base := path.Base(p)
	if !slices.ContainsFunc(d.Names, func(pat string) bool {
		ok, _ := path.Match(pat, base)
		return ok
	}) {
		return false
	}
	if len(d.Paths) == 0 {
		return true
	}
	return slices.ContainsFunc(d.Paths, func(pat string) bool {
		n := strings.Count(pat, "/") + 1
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		if len(parts) < n {
			return false
		}
		ok, _ := path.Match(pat, strings.Join(parts[len(parts)-n:], "/"))
		return ok
	})
}

// match is a version found by a rule, with the overrides of that rule.
type match struct {
	Version string `json:"v,omitempty"`
	Build   string `json:"b,omitempty"`
	Name    string `json:"n,omitempty"`
	PURL    string `json:"p,omitempty"`
	CPE     string `json:"c,omitempty"`
}

func (r *Rule) find(b []byte) (match, bool) {
	sub := r.Pattern.FindSubmatch(b)
	if sub == nil {
		return match{}, false
	}
	idx := 1
	if i := r.Pattern.SubexpIndex("version"); i > 0 {
		idx = i
	}
	if idx >= len(sub) || len(sub[idx]) == 0 {
		return match{}, false
	}
	m := match{Version: string(sub[idx]), Name: r.Name, PURL: r.PURL, CPE: r.CPE}
	if i := r.Pattern.SubexpIndex("build"); i > 0 && i < len(sub) {
		m.Build = string(sub[i])
	}
	return m, true
}

// firstMatch applies rules in order to one buffer.
func firstMatch(rules []Rule, b []byte) (match, bool) {
	for i := range rules {
		if m, ok := rules[i].find(b); ok {
			return m, true
		}
	}
	return match{}, false
}

// scanReader streams r in overlapping chunks and returns the match of the
// rule with the lowest index found anywhere in the first limit bytes.
func scanReader(r io.Reader, rules []Rule, limit int64) (match, bool) {
	best, bestIdx := match{}, len(rules)
	buf := make([]byte, scanChunk+scanOverlap)
	keep := 0
	lr := io.LimitReader(r, limit)
	for {
		n, err := io.ReadFull(lr, buf[keep:])
		data := buf[:keep+n]
		for i := 0; i < bestIdx; i++ {
			if m, ok := rules[i].find(data); ok {
				best, bestIdx = m, i
				break
			}
		}
		if bestIdx == 0 || err != nil {
			break
		}
		keep = min(scanOverlap, len(data))
		copy(buf, data[len(data)-keep:])
	}
	return best, bestIdx < len(rules)
}

// staticSource is the matched file as the static rules see it.
type staticSource struct {
	logical string
	file    *os.File // the matched file, open
	size    int64
	goInfo  *goInfo
}

// static runs the static rules of d. Results of scanning the matched file
// itself are cached with the file.
func (c *collector) static(d *Detector, src staticSource, fi os.FileInfo) (match, bool) {
	for i := range d.Static {
		r := &d.Static[i]
		var m match
		var ok bool
		switch {
		case r.GoMain:
			if src.goInfo != nil && src.goInfo.Main.Version != "" && src.goInfo.Main.Version != "(devel)" {
				m, ok = match{Version: strings.TrimPrefix(src.goInfo.Main.Version, "v")}, true
			}
		case r.BuildSetting != "":
			if src.goInfo != nil {
				if v, found := src.goInfo.Settings[r.BuildSetting]; found {
					m, ok = firstMatch(r.Rules, []byte(v))
				}
			}
		case r.File == "" && r.Entry == "":
			key := "artifact.static.v1." + d.ID + "." + strconv.Itoa(i)
			if d.cacheTag != "" {
				key = "artifact.static.t1." + d.ID + "." + d.cacheTag + "." + strconv.Itoa(i)
			}
			var cached struct {
				M  match `json:"m"`
				OK bool  `json:"ok"`
			}
			if fi != nil && c.env.Cache.Extra(fi, key, &cached) {
				m, ok = cached.M, cached.OK
				break
			}
			if _, err := src.file.Seek(0, io.SeekStart); err != nil {
				break
			}
			m, ok = scanReader(src.file, r.Rules, limitOr(r.Limit, defaultBinaryLimit))
			if fi != nil {
				cached.M, cached.OK = m, ok
				c.env.Cache.SetExtra(fi, key, cached)
			}
		case r.File == "":
			m, ok = c.zipEntryMatch(src.file, src.size, r)
		default:
			m, ok = c.sideFileMatch(src.logical, r, d.constrained)
		}
		if ok && d.accepts(m) {
			return m, true
		}
	}
	return match{}, false
}

// limitOr returns v, at most def, or def when v is zero.
func limitOr(v, def int64) int64 {
	if v > 0 {
		return min(v, def)
	}
	return def
}

// accepts reports whether a match may be reported: always for built-in
// detectors, only with a version and build of the strict grammar for the
// others.
func (d *Detector) accepts(m match) bool {
	if !d.constrained {
		return true
	}
	return detectors.ValidCaptured(m.Version) && (m.Build == "" || detectors.ValidCaptured(m.Build))
}

// sideFileMatch applies a rule to a file next to the matched one.
// Detectors that are not built in open it with openSideConstrained.
func (c *collector) sideFileMatch(logical string, r *StaticRule, constrained bool) (match, bool) {
	rel := path.Clean(path.Join(path.Dir(logical), r.File))
	candidates := []string{rel}
	if strings.ContainsAny(rel, "*?[") {
		real, err := filepath.Glob(c.env.Path(rel))
		if err != nil {
			return match{}, false
		}
		candidates = candidates[:0]
		for _, p := range real {
			candidates = append(candidates, c.env.Logical(p))
		}
		slices.Sort(candidates)
	}
	open := c.openSide
	if constrained {
		open = c.openSideConstrained
		// A pattern of a table that is not built in reads a few files,
		// not a directory.
		candidates = candidates[:min(len(candidates), detectors.MaxSideFileMatches)]
	}
	for _, p := range candidates {
		f, err := open(p)
		if err != nil {
			continue
		}
		var m match
		var ok bool
		if r.Entry != "" {
			if fi, err := f.Stat(); err == nil {
				m, ok = c.zipEntryMatch(f, fi.Size(), r)
			}
		} else {
			m, ok = scanReader(f, r.Rules, limitOr(r.Limit, defaultSideFileLimit))
		}
		f.Close()
		if ok {
			return m, true
		}
	}
	return match{}, false
}

// openSide opens a regular file for a static rule. Symbolic links are
// followed only on the real root: inside a container root an absolute link
// would resolve against the host.
func (c *collector) openSide(logical string) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if c.env.Root != "/" && c.env.Root != "" {
		flags |= syscall.O_NOFOLLOW
	}
	fd, err := syscall.Open(c.env.Path(logical), flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), logical)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, os.ErrInvalid
	}
	return f, nil
}

// zipEntryMatch applies a rule to one entry of a zip file.
func (c *collector) zipEntryMatch(ra io.ReaderAt, size int64, r *StaticRule) (match, bool) {
	zr, err := zip.NewReader(ra, size)
	if err != nil && zr == nil {
		return match{}, false
	}
	if len(zr.File) > c.limits.MaxEntries {
		return match{}, false
	}
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, r.Entry) {
			continue
		}
		b, err := readSmallEntry(f, limitOr(r.Limit, defaultSideFileLimit))
		if err != nil {
			return match{}, false
		}
		return firstMatch(r.Rules, b)
	}
	return match{}, false
}

// readSmallEntry reads a zip entry that must not exceed max bytes.
func readSmallEntry(f *zip.File, max int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(max) {
		return nil, errEntryTooLarge
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(rc, max+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > max {
		return nil, errEntryTooLarge
	}
	return buf.Bytes(), nil
}

// expand fills a PURL or CPE template.
func expand(tmpl, version string, escape func(string) string) string {
	if tmpl == "" || version == "" {
		return ""
	}
	return strings.ReplaceAll(tmpl, "{version}", escape(version))
}

// purlEscape percent-encodes a purl version.
func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '.', ch == '-', ch == '_', ch == '~':
			b.WriteByte(ch)
		default:
			b.WriteString("%" + strings.ToUpper(string("0123456789abcdef"[ch>>4])+string("0123456789abcdef"[ch&15])))
		}
	}
	return b.String()
}

// cpeEscape quotes the characters that are special in a CPE 2.3 component.
func cpeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '_' || r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}
