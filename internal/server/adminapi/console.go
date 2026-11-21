// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package adminapi

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
)

// consoleHandler serves the built console. A path that names no file is
// answered with the SPA entry page (200.html, else index.html) so that the
// client router can handle it; paths under /api/ and missing hashed assets
// are 404.
type consoleHandler struct {
	fsys fs.FS
}

func (c *consoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		apierr.Write(w, http.StatusNotFound, gen.Error{Code: apierr.CodeNotFound, Message: "no such endpoint"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.fsys == nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if c.serve(w, r, name) || c.serve(w, r, path.Join(name, "index.html")) {
		return
	}
	if strings.HasPrefix(name, "_nuxt/") {
		http.NotFound(w, r)
		return
	}
	if c.serve(w, r, "200.html") || c.serve(w, r, "index.html") {
		return
	}
	http.NotFound(w, r)
}

// serve sends the regular file name, if it exists.
func (c *consoleHandler) serve(w http.ResponseWriter, r *http.Request, name string) bool {
	if !fs.ValidPath(name) {
		return false
	}
	f, err := c.fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	content, ok := f.(io.ReadSeeker)
	if !ok {
		b, err := io.ReadAll(f)
		if err != nil {
			return false
		}
		content = bytes.NewReader(b)
	}
	if strings.HasPrefix(name, "_nuxt/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	modTime := st.ModTime()
	if modTime.Equal(time.Unix(0, 0)) {
		modTime = time.Time{}
	}
	http.ServeContent(w, r, name, modTime, content)
	return true
}
