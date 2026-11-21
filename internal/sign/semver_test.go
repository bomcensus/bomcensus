// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sign

import "testing"

func TestVersionOrder(t *testing.T) {
	// Ascending precedence, from the Semantic Versioning 2.0.0 examples.
	order := []string{
		"0.0.0-dev",
		"0.9.9",
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.1.0",
		"1.10.0",
		"2.0.0",
	}
	for i := range order {
		for j := range order {
			c, err := CompareVersions(order[i], order[j])
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if c != want {
				t.Errorf("compare(%s, %s) = %d, want %d", order[i], order[j], c, want)
			}
			if got := Newer(order[i], order[j]); got != (i > j) {
				t.Errorf("Newer(%s, %s) = %v", order[i], order[j], got)
			}
		}
	}
}

func TestVersionParse(t *testing.T) {
	valid := []string{"0.0.0", "1.2.3-rc.1+build.5", "1.2.3+20260101", "10.20.30-x-y.0"}
	invalid := []string{"", "v1.2.3", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "1.2.3-01", "1.2.3-a..b", "1.2.3+", "1.2.3-a_b", "1.-2.3"}
	for _, v := range valid {
		if !ValidVersion(v) {
			t.Errorf("%q rejected", v)
		}
	}
	for _, v := range invalid {
		if ValidVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
	if c, _ := CompareVersions("1.2.3+a", "1.2.3+b"); c != 0 {
		t.Errorf("build metadata affected precedence")
	}
	if Newer("garbage", "1.0.0") || Newer("2.0.0", "garbage") {
		t.Error("invalid version treated as newer")
	}
}
