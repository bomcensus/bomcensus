// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import "strings"

// ImageDigest returns the bare digest ("sha256:…") of an image id as
// runtimes report it: "docker-pullable://repo@sha256:…", "repo@sha256:…",
// "docker://sha256:…" or "sha256:…". Values without an algorithm prefix are
// returned unchanged.
func ImageDigest(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	return s
}

// ImageTag returns the tag form of an image reference: "repo:tag" stays,
// "repo:tag@sha256:…" loses its digest, and a reference that only names a
// digest ("repo@sha256:…") gives "".
func ImageTag(ref string) string {
	ref = strings.TrimSpace(ref)
	i := strings.IndexByte(ref, '@')
	if i < 0 {
		return ref
	}
	name := ref[:i]
	if j := strings.LastIndexByte(name, ':'); j > strings.LastIndexByte(name, '/') {
		return name
	}
	return ""
}
