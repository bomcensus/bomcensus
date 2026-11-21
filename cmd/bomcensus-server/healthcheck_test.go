// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/server/config"
)

func readyServer(t *testing.T, tls bool, status int) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("not ready: database\n"))
	}))
	if tls {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// An all-interfaces address, as in the default ":8080".
	return ":" + port
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestHealthcheck(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		tls     bool
		webTLS  string
		status  int
		wantErr string
	}{
		{name: "https default", tls: true, status: http.StatusOK},
		{name: "https manual", tls: true, webTLS: "manual", status: http.StatusOK},
		{name: "http off", tls: false, webTLS: "off", status: http.StatusOK},
		{name: "not ready", tls: true, status: http.StatusServiceUnavailable, wantErr: "503"},
		{name: "wrong scheme", tls: false, status: http.StatusOK, wantErr: "healthcheck"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listen := readyServer(t, tc.tls, tc.status)
			err := healthcheck(ctx, env(map[string]string{
				config.EnvWebListen: listen,
				config.EnvWebTLS:    tc.webTLS,
			}))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestHealthcheckBadListen(t *testing.T) {
	err := healthcheck(context.Background(), env(map[string]string{config.EnvWebListen: "8080"}))
	if err == nil || !strings.Contains(err.Error(), config.EnvWebListen) {
		t.Fatalf("error %v, want one naming %s", err, config.EnvWebListen)
	}
}
