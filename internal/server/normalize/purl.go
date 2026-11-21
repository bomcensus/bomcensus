// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package normalize turns report items into component identities: purls,
// distro qualifiers and origins. It does no I/O.
package normalize

import (
	"sort"
	"strings"
)

// PURL is a package URL in its component form.
type PURL struct {
	Type       string
	Namespace  string // segments separated by '/'
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// String builds the canonical form (ECMA-427 "How to build"): every
// component is percent-encoded except for alphanumerics, ".-_~" and ':';
// namespace and subpath segments are encoded one by one; qualifiers with an
// empty value are dropped, keys are lowercased and the pairs are sorted.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(strings.ToLower(p.Type))
	b.WriteByte('/')
	if ns := strings.Trim(p.Namespace, "/"); ns != "" {
		for _, seg := range strings.Split(ns, "/") {
			if seg == "" {
				continue
			}
			b.WriteString(Escape(seg))
			b.WriteByte('/')
		}
	}
	b.WriteString(Escape(strings.Trim(p.Name, "/")))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(Escape(p.Version))
	}
	var quals []string
	for k, v := range p.Qualifiers {
		if v == "" {
			continue
		}
		quals = append(quals, strings.ToLower(k)+"="+Escape(v))
	}
	if len(quals) > 0 {
		sort.Strings(quals)
		b.WriteByte('?')
		b.WriteString(strings.Join(quals, "&"))
	}
	var segs []string
	for _, seg := range strings.Split(p.Subpath, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		segs = append(segs, Escape(seg))
	}
	if len(segs) > 0 {
		b.WriteByte('#')
		b.WriteString(strings.Join(segs, "/"))
	}
	return b.String()
}

// Escape percent-encodes s for use inside one purl component. Alphanumerics,
// '.', '-', '_', '~' and ':' are kept; every other byte of the UTF-8
// encoding becomes %XX with uppercase hex digits.
func Escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

func unreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '.', '-', '_', '~', ':':
		return true
	}
	return false
}
