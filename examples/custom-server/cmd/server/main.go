// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command server is bomcensus-server serving the admin API only, with
// bearer tokens instead of the console login, tenant scopes, and agents
// connecting over the frame channel besides HTTP.
//
//	EXAMPLE_TOKENS='t1=alice:admin:*,t2=bob:viewer:team-a' \
//	EXAMPLE_FRAME_LISTEN=:9443 \
//	BOMCENSUS_DATABASE_URL=... BOMCENSUS_MASTER_KEY=... server
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/examples/custom-server/framechannel"
	"github.com/bomcensus/bomcensus/examples/custom-server/tokenauth"
	"github.com/bomcensus/bomcensus/server"
)

func main() {
	tokens, err := tokenauth.ParseTokens(os.Getenv("EXAMPLE_TOKENS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	frameAddr := os.Getenv("EXAMPLE_FRAME_LISTEN")
	if frameAddr == "" {
		frameAddr = ":9443"
	}
	server.Main(server.Options{
		// No console and no cookie login: the API is for programs.
		APIMiddleware: []func(http.Handler) http.Handler{tokenauth.Middleware(tokens)},
		Authorizer:    tokenauth.Authorizer{},
		AgentGateways: []agentproto.Gateway{&framechannel.Gateway{
			Addr:   frameAddr,
			Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)).With("component", "frame"),
		}},
	})
}
