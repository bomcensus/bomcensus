// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package container

import "strings"

const (
	defaultDomain = "docker.io"
	legacyDomain  = "index.docker.io"
	officialRepo  = "library/"
)

// normalizeRef expands an image reference to its fully qualified form, the
// way containerd and Kubernetes print it: "alpine:3.20" becomes
// "docker.io/library/alpine:3.20" and a reference without tag or digest gets
// ":latest". Docker keeps the short form on disk; containerd keeps the long
// one. Normalizing both lets the same image match across runtimes.
//
// Image ids ("sha256:<hex>") are returned unchanged.
func normalizeRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "sha256:") {
		return ref
	}

	name, digest, _ := strings.Cut(ref, "@")
	tag := ""
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name, tag = name[:i], name[i+1:]
	}

	domain, rest := defaultDomain, name
	if i := strings.IndexByte(name, '/'); i >= 0 {
		first := name[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" || strings.ToLower(first) != first {
			domain, rest = first, name[i+1:]
		}
	}
	if domain == legacyDomain {
		domain = defaultDomain
	}
	if domain == defaultDomain && !strings.Contains(rest, "/") {
		rest = officialRepo + rest
	}

	out := domain + "/" + rest
	if tag != "" {
		out += ":" + tag
	}
	if digest != "" {
		out += "@" + digest
	}
	if tag == "" && digest == "" {
		out += ":latest"
	}
	return out
}

// isDigestRef reports whether a stored image name pins a digest rather than
// naming a tag ("repo@sha256:…" or a bare "sha256:…" id).
func isDigestRef(name string) bool {
	return strings.Contains(name, "@") || strings.HasPrefix(name, "sha256:")
}

// isHexID reports whether s looks like a full or abbreviated image id that
// Docker accepts in place of a reference.
func isHexID(s string) bool {
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validDigest accepts "sha256:" followed by 64 lowercase hex characters.
func validDigest(d string) bool {
	hex, ok := strings.CutPrefix(d, "sha256:")
	return ok && len(hex) == 64 && isHexID(hex)
}
