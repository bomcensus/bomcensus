// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import "strings"

// MaxVersion returns the highest of the fixed versions of a component's
// vulnerabilities, the update that fixes them all. OS package versions are
// compared as dpkg does (also right for apk and close for rpm); language
// ecosystem versions as semantic versions, where a pre-release is lower
// than its release. Empty without versions.
func MaxVersion(componentType string, versions []string) string {
	cmp := comparator(componentType)
	best := ""
	for _, v := range versions {
		if v == "" {
			continue
		}
		if best == "" || cmp(v, best) > 0 {
			best = v
		}
	}
	return best
}

// LastAffectedBound returns the highest last affected version of a
// component's vulnerabilities when it bounds the update: when it is at or
// above the highest fixed version, so that following the fixed version
// would leave the component in a range. Empty otherwise.
func LastAffectedBound(componentType string, fixed, lastAffected []string) string {
	la := MaxVersion(componentType, lastAffected)
	f := MaxVersion(componentType, fixed)
	if la == "" || f == "" || comparator(componentType)(la, f) >= 0 {
		return la
	}
	return ""
}

func comparator(componentType string) func(a, b string) int {
	if osPackageTypes[componentType] {
		return compareDebian
	}
	return compareSemverish
}

// compareDebian compares [epoch:]upstream[-revision] versions.
func compareDebian(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if c := compareNum(ea, eb); c != 0 {
		return c
	}
	ua, va := splitRevision(ra)
	ub, vb := splitRevision(rb)
	if c := compareDebianPart(ua, ub); c != 0 {
		return c
	}
	return compareDebianPart(va, vb)
}

func splitEpoch(v string) (string, string) {
	if i := strings.IndexByte(v, ':'); i > 0 && isDigits(v[:i]) {
		return v[:i], v[i+1:]
	}
	return "0", v
}

func splitRevision(v string) (string, string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// compareDebianPart is dpkg's verrevcmp: alternating non-digit and digit
// runs; letters sort before non-letters and "~" before everything, even
// the end of the string.
func compareDebianPart(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ca, cb := order(a), order(b)
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
			a, b = a[1:], b[1:]
		}
		da, db := leadingDigits(a), leadingDigits(b)
		if c := compareNum(da, db); c != 0 {
			return c
		}
		a, b = a[len(da):], b[len(db):]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// order is dpkg's weight of the first character of s (0 at the end).
func order(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	switch {
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i]
}

// compareNum compares digit strings of any length.
func compareNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// compareSemverish compares versions such as 2.17.1, v1.2.3, go1.21.11 or
// 1.0.0-rc1: dot-separated release parts first, then a release above any of
// its pre-releases.
func compareSemverish(a, b string) int {
	ra, pa := splitPre(a)
	rb, pb := splitPre(b)
	if c := compareDebianPart(ra, rb); c != 0 {
		return c
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return compareDebianPart(pa, pb)
}

func splitPre(v string) (string, string) {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "go"), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		if v[i] == '+' {
			return v[:i], "" // build metadata does not order
		}
		return v[:i], v[i+1:]
	}
	return v, ""
}
