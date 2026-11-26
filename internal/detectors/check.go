// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package detectors

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Limits of one table. They apply to every table a probe receives; the
// built-in table is well inside them.
const (
	MaxDetectors    = 256
	MaxNames        = 32 // names and paths of one detector
	MaxRules        = 16 // parse rules, static rules, and rules of one static rule
	MaxPatternLen   = 1024
	MaxGroups       = 8
	MaxExecArgs     = 16
	MaxEnv          = 4
	MaxEnvUp        = 8
	MaxAddressSpace = 16 << 10 // MiB
	MaxIDLen        = 64
	MaxTextLen      = 256 // names, templates, file and entry names
	MaxPathParts    = 8
	MaxSideFileUp   = 2 // "../" steps of a static rule file
	// MaxSideFileMatches bounds the files a glob of a constrained side
	// file reads.
	MaxSideFileMatches = 8
	// minNameLiteral is the number of characters other than glob
	// characters a constrained name pattern needs, so that it does not
	// match every executable.
	minNameLiteral   = 2
	MaxCapturedLen   = 64
	SideFileLimit    = 1 << 20   // default and maximum scan of a side file or zip entry
	BinaryLimit      = 256 << 20 // default and maximum scan of the matched file
	maxCompiledInsts = 20000
)

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	entryPattern   = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	// capturedPattern is the grammar of a version or build taken from a
	// table that is not built in.
	capturedPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z._+~:-]*$`)
)

// buildSettings are the Go build settings a table that is not built in may
// read.
var buildSettings = map[string]bool{"-ldflags": true, "-tags": true, "vcs.revision": true, "vcs.time": true}

// ValidCaptured reports whether s may be reported as the version or build
// found by a detector that is not built in: it starts with a digit, has at
// most MaxCapturedLen characters from [0-9A-Za-z._+~:-].
func ValidCaptured(s string) bool {
	return len(s) <= MaxCapturedLen && capturedPattern.MatchString(s)
}

// checkSpec checks one entry. constrained applies the rules for entries that
// differ from the built-in table: side files, zip entries and build
// settings are restricted. Exec fields are checked for size only; whether
// the command may run is decided by Resolve.
func checkSpec(d *report.DetectorSpec, constrained bool) error {
	switch {
	case d.ID == "" || len(d.ID) > MaxIDLen || !idPattern.MatchString(d.ID):
		return fmt.Errorf("id must be 1 to %d characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit", MaxIDLen)
	case d.Name == "":
		return errors.New("name is required")
	case len(d.Names) == 0:
		return errors.New("names is required")
	case len(d.Names) > MaxNames || len(d.Paths) > MaxNames:
		return fmt.Errorf("at most %d names and %d paths", MaxNames, MaxNames)
	case len(d.Parse) > MaxRules || len(d.Static) > MaxRules:
		return fmt.Errorf("at most %d parse rules and %d static rules", MaxRules, MaxRules)
	case len(d.Exec) > MaxExecArgs || len(d.Env) > MaxEnv:
		return fmt.Errorf("at most %d exec arguments and %d environment variables", MaxExecArgs, MaxEnv)
	case d.AddressSpaceMB < 0 || d.AddressSpaceMB > MaxAddressSpace:
		return fmt.Errorf("address_space_mb must be 0 to %d", MaxAddressSpace)
	case len(d.Exec) > 0 && len(d.Parse) == 0:
		return errors.New("exec needs parse rules")
	case len(d.Exec) == 0 && len(d.Static) == 0:
		return errors.New("no way to find a version: neither exec nor static rules")
	}
	for _, s := range []string{d.Name, d.PURL, d.CPE} {
		if err := checkText("name, purl and cpe", s); err != nil {
			return err
		}
	}
	for _, n := range d.Names {
		if err := checkText("names", n); err != nil {
			return err
		}
		if n == "" || strings.Contains(n, "/") {
			return fmt.Errorf("names: %q must be a file name pattern without '/'", n)
		}
		if constrained && literalChars(n) < minNameLiteral {
			return fmt.Errorf("names: %q must have at least %d characters that are not glob characters", n, minNameLiteral)
		}
		if _, err := path.Match(n, ""); err != nil {
			return fmt.Errorf("names: %q: %v", n, err)
		}
	}
	for _, p := range d.Paths {
		if err := checkText("paths", p); err != nil {
			return err
		}
		if p == "" || strings.HasPrefix(p, "/") || strings.Count(p, "/")+1 > MaxPathParts || hasDotPart(p) {
			return fmt.Errorf("paths: %q must be relative, clean and at most %d components", p, MaxPathParts)
		}
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("paths: %q: %v", p, err)
		}
	}
	for _, a := range d.Exec {
		if err := checkText("exec", a); err != nil {
			return err
		}
	}
	for _, e := range d.Env {
		if !envNamePattern.MatchString(e.Name) || len(e.Name) > MaxIDLen || e.Up < 0 || e.Up > MaxEnvUp {
			return fmt.Errorf("env: %q must be an upper case variable name with up 0 to %d", e.Name, MaxEnvUp)
		}
	}
	for i := range d.Parse {
		if err := checkRule(&d.Parse[i]); err != nil {
			return fmt.Errorf("parse rule %d: %w", i+1, err)
		}
	}
	for i := range d.Static {
		if err := checkStatic(&d.Static[i], d.Archive, constrained); err != nil {
			return fmt.Errorf("static rule %d: %w", i+1, err)
		}
	}
	return nil
}

func checkStatic(s *report.DetectorStatic, archive, constrained bool) error {
	if len(s.Rules) > MaxRules {
		return fmt.Errorf("at most %d rules", MaxRules)
	}
	limit := int64(SideFileLimit)
	switch {
	case s.GoMain:
		if s.File != "" || s.Entry != "" || s.BuildSetting != "" || len(s.Rules) > 0 || s.Limit != 0 {
			return errors.New("go_main takes no file, entry, build_setting, rules or limit")
		}
		return nil
	case s.BuildSetting != "":
		if s.File != "" || s.Entry != "" || s.Limit != 0 {
			return errors.New("build_setting takes no file, entry or limit")
		}
		if constrained && !buildSettings[s.BuildSetting] {
			return fmt.Errorf("build_setting %q is not one of -ldflags, -tags, vcs.revision, vcs.time", s.BuildSetting)
		}
		if err := checkText("build_setting", s.BuildSetting); err != nil {
			return err
		}
	case s.File == "" && s.Entry == "":
		limit = BinaryLimit
	}
	if len(s.Rules) == 0 {
		return errors.New("rules are required")
	}
	if s.Limit < 0 || s.Limit > limit {
		return fmt.Errorf("limit must be 0 to %d", limit)
	}
	if s.File != "" {
		if err := checkSideFile(s.File, constrained); err != nil {
			return err
		}
	}
	if s.Entry != "" {
		if err := checkEntry(s.Entry, s.File == "" && !archive, constrained); err != nil {
			return err
		}
	}
	for i := range s.Rules {
		if err := checkRule(&s.Rules[i]); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

// checkSideFile checks a file relative to the matched file's directory.
func checkSideFile(f string, constrained bool) error {
	if err := checkText("file", f); err != nil {
		return err
	}
	if !constrained {
		return nil
	}
	if strings.HasPrefix(f, "/") || strings.Contains(f, `\`) || path.Clean(f) != f {
		return fmt.Errorf("file %q must be a clean relative path", f)
	}
	parts := strings.Split(f, "/")
	up := 0
	for up < len(parts) && parts[up] == ".." {
		up++
	}
	if up > MaxSideFileUp {
		return fmt.Errorf("file %q goes up more than %d directories", f, MaxSideFileUp)
	}
	if up == len(parts) || len(parts) > MaxPathParts+MaxSideFileUp || hasDotPart(strings.Join(parts[up:], "/")) {
		return fmt.Errorf("file %q must name a file below the parent directories", f)
	}
	if deniedName(parts[len(parts)-1]) {
		return fmt.Errorf("file %q names a file that may hold secrets", f)
	}
	return nil
}

// checkEntry checks a zip entry name. Entries that differ from the built-in
// table may only read metadata under META-INF/.
func checkEntry(e string, notArchive, constrained bool) error {
	if err := checkText("entry", e); err != nil {
		return err
	}
	if notArchive {
		return errors.New("entry needs an archive: set file, or archive on the detector")
	}
	if !constrained {
		return nil
	}
	if !entryPattern.MatchString(e) || path.Clean(e) != e || strings.HasPrefix(e, "/") || hasDotPart(e) {
		return fmt.Errorf("entry %q must be a clean relative name of A-Z, a-z, 0-9, '.', '_', '-' and '/'", e)
	}
	if !strings.HasPrefix(strings.ToUpper(e), "META-INF/") {
		return fmt.Errorf("entry %q must be under META-INF/", e)
	}
	if deniedName(path.Base(e)) {
		return fmt.Errorf("entry %q names a file that may hold secrets", e)
	}
	return nil
}

func checkRule(r *report.DetectorRule) error {
	for _, s := range []string{r.Name, r.PURL, r.CPE} {
		if err := checkText("name, purl and cpe", s); err != nil {
			return err
		}
	}
	_, err := compileRule(r.Pattern)
	return err
}

// compileRule compiles a pattern of a table with the limits of a table.
func compileRule(p string) (*regexp.Regexp, error) {
	if p == "" || len(p) > MaxPatternLen {
		return nil, fmt.Errorf("pattern must be 1 to %d bytes", MaxPatternLen)
	}
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("pattern: %v", err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, fmt.Errorf("pattern: %v", err)
	}
	if len(prog.Inst) > maxCompiledInsts {
		return nil, fmt.Errorf("pattern compiles to %d instructions, at most %d", len(prog.Inst), maxCompiledInsts)
	}
	out, err := regexp.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("pattern: %v", err)
	}
	n := out.NumSubexp()
	switch {
	case n < 1:
		return nil, errors.New("pattern has no group for the version")
	case n > MaxGroups:
		return nil, fmt.Errorf("pattern has %d groups, at most %d", n, MaxGroups)
	case out.SubexpIndex("build") > 0 && out.SubexpIndex("version") < 0:
		return nil, errors.New(`a pattern with a "build" group needs a "version" group`)
	}
	return out, nil
}

// Compile compiles a pattern of a table that Resolve accepted.
func Compile(p string) (*regexp.Regexp, error) { return compileRule(p) }

func checkText(field, s string) error {
	if len(s) > MaxTextLen {
		return fmt.Errorf("%s: value longer than %d bytes", field, MaxTextLen)
	}
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) {
		return fmt.Errorf("%s: value with control characters", field)
	}
	return nil
}

// literalChars counts the characters of a path.Match pattern outside
// '*', '?' and character classes.
func literalChars(p string) int {
	n := 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*', '?':
		case '[':
			if j := strings.IndexByte(p[i:], ']'); j > 0 {
				i += j
			}
		case '\\':
			i++
			n++
		default:
			n++
		}
	}
	return n
}

// hasDotPart reports whether p has an empty, "." or ".." component.
func hasDotPart(p string) bool {
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." {
			return true
		}
	}
	return false
}
