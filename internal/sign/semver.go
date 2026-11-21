// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import (
	"fmt"
	"strconv"
	"strings"
)

// version is a parsed Semantic Versioning 2.0.0 version. Build metadata is
// dropped because it does not take part in precedence.
type version struct {
	major, minor, patch uint64
	pre                 []string
}

// parseVersion parses a strict semver string without a "v" prefix.
func parseVersion(s string) (version, error) {
	var v version
	if len(s) == 0 || len(s) > 128 {
		return v, fmt.Errorf("sign: invalid version %q", s)
	}
	core := s
	if i := strings.IndexByte(core, '+'); i >= 0 {
		if !validIdents(core[i+1:], false) {
			return v, fmt.Errorf("sign: invalid build metadata in version %q", s)
		}
		core = core[:i]
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		pre := core[i+1:]
		if !validIdents(pre, true) {
			return v, fmt.Errorf("sign: invalid pre-release in version %q", s)
		}
		v.pre = strings.Split(pre, ".")
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("sign: invalid version %q", s)
	}
	nums := [3]*uint64{&v.major, &v.minor, &v.patch}
	for i, p := range parts {
		if !isNumeric(p) || (len(p) > 1 && p[0] == '0') {
			return v, fmt.Errorf("sign: invalid version %q", s)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("sign: invalid version %q", s)
		}
		*nums[i] = n
	}
	return v, nil
}

func validIdents(s string, pre bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
		}
		if pre && isNumeric(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (a version) compare(b version) int {
	if c := cmpUint(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpUint(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpUint(a.patch, b.patch); c != 0 {
		return c
	}
	// A version without pre-release has higher precedence.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := isNumeric(x), isNumeric(y)
		var c int
		switch {
		case xn && yn:
			// Compare by length first: identifiers have no leading zeros
			// and may exceed uint64.
			if c = cmpUint(uint64(len(x)), uint64(len(y))); c == 0 {
				c = strings.Compare(x, y)
			}
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(a.pre)), uint64(len(b.pre)))
}

// ValidVersion reports whether s is a Semantic Versioning 2.0.0 version
// (no "v" prefix).
func ValidVersion(s string) bool {
	_, err := parseVersion(s)
	return err == nil
}

// CompareVersions compares two semver versions by precedence and returns
// -1, 0 or +1. Build metadata is ignored.
func CompareVersions(a, b string) (int, error) {
	va, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.compare(vb), nil
}

// Newer reports whether candidate has higher semver precedence than
// installed. It is the rollback check for updates: it returns false when
// either version is invalid, so an unparsable version never upgrades.
func Newer(candidate, installed string) bool {
	c, err := CompareVersions(candidate, installed)
	return err == nil && c > 0
}
