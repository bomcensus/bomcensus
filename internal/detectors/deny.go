// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package detectors

import (
	"path"
	"strings"
)

// deniedDirs are directories whose files detectors that are not built in
// never read as side files: home directories, kernel interfaces, and where
// credentials, keys and container or agent state are kept.
var deniedDirs = []string{
	"/root", "/home", "/proc", "/sys", "/dev", "/boot",
	"/run/secrets", "/var/run/secrets", "/run/user", "/run/containerd", "/var/run/containerd",
	"/var/lib/kubelet", "/etc/kubernetes", "/var/lib/rancher", "/etc/rancher",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers",
	"/etc/ssh", "/etc/ssl/private", "/etc/pki/tls/private", "/etc/pki/CA/private",
	"/etc/sudoers.d", "/etc/security", "/var/lib/sss", "/etc/sssd",
	"/var/lib/bomcensus", "/var/lib/bomcensus-agent", "/var/lib/bomcensus-scanner", "/etc/bomcensus",
}

// deniedNames are file name patterns (path.Match, lower case) that detectors
// that are not built in never read: password databases, keys, certificates
// with keys, credentials and shell history.
var deniedNames = []string{
	"shadow", "shadow-", "gshadow", "gshadow-", "passwd", "passwd-", "opasswd", "sudoers",
	"*.key", "*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.truststore", "*.kdbx", "*.keytab", "*.gpg", "*.asc",
	"id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "authorized_keys*", "known_hosts*",
	".netrc", ".pgpass", ".my.cnf", ".git-credentials", ".htpasswd", ".dockercfg", "kubeconfig", "*.kubeconfig",
	".env", ".env.*", "*.env", "credentials", "credentials.*", "*secret*", "*token*", "*password*", "*passwd*",
	"*_history", ".*history",
}

// DeniedPath reports whether a detector that is not built in must not read
// the file at the absolute, clean path p: it is in a denied directory or
// has a denied name.
func DeniedPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return true
	}
	p = path.Clean(p)
	for _, d := range deniedDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return deniedName(path.Base(p))
}

func deniedName(name string) bool {
	n := strings.ToLower(name)
	for _, pat := range deniedNames {
		if ok, _ := path.Match(pat, n); ok {
			return true
		}
	}
	return false
}
