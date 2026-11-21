// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package console embeds the built web console.
//
// `make console` builds the frontend and copies its static output into dist/.
// Only dist/placeholder/ is committed: a page saying that the console was not
// built into the binary, so that the package always compiles. The placeholder
// lives in its own directory because the built console brings its own
// index.html, which would otherwise overwrite a committed file.
package console

import (
	"embed"
	"io/fs"
)

// The all: prefix keeps Nuxt's _nuxt/ directory, which a plain pattern
// would skip.
//
//go:embed all:dist
var files embed.FS

// FS returns the console files. built is false when the binary carries only
// the placeholder page; the returned FS then serves that page.
func FS() (fsys fs.FS, built bool) {
	// fs.Sub fails only for an invalid path name; both names are constant.
	dist, _ := fs.Sub(files, "dist")
	if st, err := fs.Stat(dist, "index.html"); err == nil && st.Mode().IsRegular() {
		return dist, true
	}
	placeholder, _ := fs.Sub(dist, "placeholder")
	return placeholder, false
}
