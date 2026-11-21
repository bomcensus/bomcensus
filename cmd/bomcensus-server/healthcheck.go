// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/app"
	"github.com/bomcensus/bomcensus/internal/server/config"
)

// healthcheckTimeout bounds the whole check.
const healthcheckTimeout = 3 * time.Second

// healthcheck requests the readiness endpoint of the local console listener
// and fails unless it answers 200. It reads only BOMCENSUS_WEB_LISTEN and
// BOMCENSUS_WEB_TLS, so it works in a container that has no shell and
// without the database URL or the master key.
func healthcheck(ctx context.Context, getenv func(string) string) error {
	listen := strings.TrimSpace(getenv(config.EnvWebListen))
	if listen == "" {
		listen = config.DefaultWebListen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%s: %w", config.EnvWebListen, err)
	}
	// A listener on all interfaces is reached through the loopback address.
	if a, err := netip.ParseAddr(host); host == "" || err == nil && a.IsUnspecified() {
		host = "127.0.0.1"
	}
	scheme := "https"
	if strings.EqualFold(strings.TrimSpace(getenv(config.EnvWebTLS)), string(config.WebTLSOff)) {
		scheme = "http"
	}
	url := scheme + "://" + net.JoinHostPort(host, port) + app.PathReadyz

	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			// The server's own certificate on a local address: there is
			// nothing to verify it against, and no proxy applies.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			Proxy:             nil,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		line, _ := bufio.NewReader(io.LimitReader(resp.Body, 256)).ReadString('\n')
		return fmt.Errorf("healthcheck: %s: %s %s", url, resp.Status, strings.TrimSpace(line))
	}
	return nil
}
