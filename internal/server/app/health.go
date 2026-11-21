// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package app

import (
	"context"
	"net/http"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
)

// Health endpoints of the console listener. They need no session and sit
// outside /api/v1.
const (
	PathHealthz = "/healthz"
	PathReadyz  = "/readyz"
)

const readyTimeout = 2 * time.Second

type health struct {
	db     *postgres.DB
	pki    *pkisvc.Service
	webTLS bool
}

// withHealth serves the health endpoints and passes everything else to next.
// The answers are plain text and name only the failing part, never an
// error message.
func withHealth(next http.Handler, h health) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathHealthz, func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, http.StatusOK, "ok")
	})
	mux.HandleFunc("GET "+PathReadyz, func(w http.ResponseWriter, r *http.Request) {
		if what := h.notReady(r.Context()); what != "" {
			writeHealth(w, http.StatusServiceUnavailable, "not ready: "+what)
			return
		}
		writeHealth(w, http.StatusOK, "ok")
	})
	mux.Handle("/", next)
	return mux
}

// notReady names the first part that is not ready, or returns "".
func (h health) notReady(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := h.db.Pool().Ping(ctx); err != nil {
		return "database"
	}
	if _, chain := h.pki.Signer(); len(chain) == 0 {
		return "pki"
	}
	if _, err := h.pki.AgentCA(); err != nil {
		return "pki"
	}
	if h.webTLS {
		if _, err := h.pki.WebCertificate(); err != nil {
			return "pki"
		}
	}
	return ""
}

func writeHealth(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}
