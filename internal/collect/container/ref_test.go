// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package container

import "testing"

func TestNormalizeRef(t *testing.T) {
	d := "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	for in, want := range map[string]string{
		"alpine":                        "docker.io/library/alpine:latest",
		"alpine:3.20":                   "docker.io/library/alpine:3.20",
		"local/alpine:mine":             "docker.io/local/alpine:mine",
		"docker.io/library/alpine:3.20": "docker.io/library/alpine:3.20",
		"index.docker.io/alpine":        "docker.io/library/alpine:latest",
		"alpine@" + d:                   "docker.io/library/alpine@" + d,
		"alpine:3.20@" + d:              "docker.io/library/alpine:3.20@" + d,
		"localhost/app":                 "localhost/app:latest",
		"localhost:5000/team/app:v1":    "localhost:5000/team/app:v1",
		"registry.k8s.io/pause:3.10":    "registry.k8s.io/pause:3.10",
		"ghcr.io/org/repo/img":          "ghcr.io/org/repo/img:latest",
		"registry:5000/img":             "registry:5000/img:latest",
		d:                               d,
		"":                              "",
	} {
		if got := normalizeRef(in); got != want {
			t.Errorf("normalizeRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDockerImageRef(t *testing.T) {
	id := "sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731"
	for _, tc := range []struct{ ref, want string }{
		{"alpine:3.20", "docker.io/library/alpine:3.20"},
		{"bf8527eb54c3", "bf8527eb54c3"},
		{id, id},
		// Hex-looking repository names that are not a prefix of the id.
		{"abcdefabcdef", "docker.io/library/abcdefabcdef:latest"},
	} {
		if got := dockerImageRef(tc.ref, id); got != tc.want {
			t.Errorf("dockerImageRef(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}
