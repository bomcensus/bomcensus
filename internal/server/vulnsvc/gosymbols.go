// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"slices"

	"github.com/bomcensus/bomcensus/internal/server/normalize"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// sourceBinaries returns the Go executables a source component is in: the
// ones at its locations, in its container and layer.
func sourceBinaries(in store.FindingInputs, s store.FindingSource) []store.FindingGoBinary {
	if s.Component.Type != normalize.TypeGolang {
		return nil
	}
	var out []store.FindingGoBinary
	for _, b := range in.GoBinaries {
		if b.Container != s.Container || !slices.Contains(s.Locations, b.Path) {
			continue
		}
		switch {
		case s.ImageDigest != "":
			if b.ImageDigest != s.ImageDigest {
				continue
			}
		case b.ImageDigest != "" || b.Layer != s.Layer:
			continue
		}
		out = append(out, b)
	}
	return out
}

// binaryReach tells whether a vulnerability's functions are in one
// executable: present, absent or "" (not known). Imports for other
// targets do not count.
func binaryReach(in store.FindingInputs, b store.FindingGoBinary, imps []store.GoImport) string {
	answers := in.SymbolResults[b.SHA256]
	unknown := false
	for _, imp := range imps {
		if !imp.Applies(b.GOOS, b.GOARCH) {
			continue
		}
		for _, n := range imp.Names() {
			switch answers[n].Result {
			case store.GoSymbolPresent:
				return store.ReachSymbolPresent
			case store.GoSymbolAbsent:
			default:
				unknown = true
			}
		}
	}
	if unknown {
		return ""
	}
	return store.ReachSymbolAbsent
}

// reachabilityOf is the reachability of a vulnerability of a source
// component: present when one of its executables links a vulnerable
// function, absent when every executable is known to link none, otherwise
// not known.
func reachabilityOf(in store.FindingInputs, s store.FindingSource, vuln string) string {
	imps := in.Symbols[store.SymbolKey(s.Component.ID, vuln)]
	if len(imps) == 0 {
		return ""
	}
	bins := sourceBinaries(in, s)
	if len(bins) == 0 {
		return ""
	}
	out := store.ReachSymbolAbsent
	for _, b := range bins {
		switch binaryReach(in, b, imps) {
		case store.ReachSymbolPresent:
			return store.ReachSymbolPresent
		case "":
			out = ""
		}
	}
	return out
}
