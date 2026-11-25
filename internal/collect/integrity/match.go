// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package integrity

import (
	"path"
	"strings"
)

// builtinExcludes are never package content worth checking.
var builtinExcludes = []string{"/proc", "/sys", "/dev", "/run"}

// matcher holds exclude patterns: plain absolute paths match themselves and
// everything below; patterns with glob characters are matched segment by
// segment with path.Match, where a "**" segment matches any number of
// segments.
type matcher struct {
	prefixes []string
	globs    [][]string
}

func newMatcher(patterns []string) *matcher {
	m := &matcher{}
	for _, p := range append(append([]string{}, builtinExcludes...), patterns...) {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		if strings.ContainsAny(p, "*?[") {
			m.globs = append(m.globs, strings.Split(strings.Trim(p, "/"), "/"))
			continue
		}
		m.prefixes = append(m.prefixes, path.Clean(p))
	}
	return m
}

func (m *matcher) match(p string) bool {
	for _, e := range m.prefixes {
		if p == e || e == "/" || strings.HasPrefix(p, e+"/") {
			return true
		}
	}
	if len(m.globs) == 0 {
		return false
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for _, g := range m.globs {
		if matchSegs(g, segs) {
			return true
		}
	}
	return false
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 0; i <= len(segs); i++ {
				if matchSegs(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], segs[0]); !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}
