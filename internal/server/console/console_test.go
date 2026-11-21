// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package console

import (
	"io/fs"
	"strings"
	"testing"
)

func TestFS(t *testing.T) {
	fsys, built := FS()
	b, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	placeholder := strings.Contains(string(b), "was not built into this binary")
	if built == placeholder {
		t.Fatalf("built=%v but index.html is the placeholder: %v", built, placeholder)
	}
}
