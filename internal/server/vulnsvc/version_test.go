// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import "testing"

func TestMaxVersion(t *testing.T) {
	for _, tc := range []struct {
		typ  string
		in   []string
		want string
	}{
		{"deb", []string{"1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u10", "9.9"}, "1:9.2p1-2+deb12u10"},
		{"deb", []string{"1.0~rc1-1", "1.0-1"}, "1.0-1"},
		{"apk", []string{"3.3.2-r1", "3.3.6-r0", "3.3.10-r0"}, "3.3.10-r0"},
		{"rpm", []string{"1.1.1k-12.el8_9", "1.1.1k-9.el8"}, "1.1.1k-12.el8_9"},
		{"maven", []string{"2.15.0", "2.17.1", "2.16.0", "2.17.0"}, "2.17.1"},
		{"maven", []string{"3.0.0-rc1", "3.0.0"}, "3.0.0"},
		{"golang", []string{"go1.21.11", "go1.21.3", "go1.23.6"}, "go1.23.6"},
		{"golang", []string{"v0.17.0", "v0.9.0"}, "v0.17.0"},
		{"maven", nil, ""},
		{"maven", []string{"", "1.0"}, "1.0"},
	} {
		if got := MaxVersion(tc.typ, tc.in); got != tc.want {
			t.Errorf("%s %v: %q, want %q", tc.typ, tc.in, got, tc.want)
		}
	}
}
