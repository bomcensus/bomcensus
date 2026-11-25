// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package server runs bomcensus-server from a program of your own.
//
// The bomcensus-server command is
//
//	func main() {
//		server.Main(server.Options{Console: server.EmbeddedConsole(), Session: &server.Session{}})
//	}
//
// A build that serves the admin API only, with its own authentication and
// authorization, leaves Console and Session nil and sets APIMiddleware and
// Authorizer:
//
//	server.Main(server.Options{
//		APIMiddleware: []func(http.Handler) http.Handler{verifyJWT},
//		Authorizer:    rbac,
//	})
//
// verifyJWT puts the caller into the request context with
// auth.WithPrincipal; rbac decides each operation (authz.Op* constants) and
// returns the data scope of the request (package scope).
package server

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/internal/server/app"
	"github.com/bomcensus/bomcensus/internal/server/console"
	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/authz"
	"github.com/bomcensus/bomcensus/server/config"
)

// Options extend the server. The zero value serves the admin API without a
// login: every request needs a principal from APIMiddleware.
type Options struct {
	// Console is the web console served outside the API; nil serves none.
	// EmbeddedConsole is the one built into this module.
	Console fs.FS
	// Session enables the built-in login (POST /api/v1/auth/login) with
	// cookie sessions. Nil disables it.
	Session *Session

	// APIMiddleware runs on every admin API request, after the session
	// cookie was resolved and before authorization. An authenticating
	// middleware puts the principal into the context with
	// auth.WithPrincipal; requests authenticated that way are not subject
	// to the CSRF check of cookie sessions.
	APIMiddleware []func(http.Handler) http.Handler
	// Authorizer decides each operation and its data scope. Nil allows
	// every authenticated principal everything (authz.AllowAll).
	Authorizer authz.Authorizer
	// Mounts are extra handlers on the web listener by path prefix,
	// outside /api. They get security headers and request logging only.
	Mounts map[string]http.Handler

	// WebListener and AgentListener replace the listeners on
	// BOMCENSUS_WEB_LISTEN and BOMCENSUS_AGENT_LISTEN. The server owns
	// them.
	WebListener   net.Listener
	AgentListener net.Listener

	// AgentGateways are channels agents connect through besides (or,
	// with NoAgentListener, instead of) the built-in HTTP channel. Each
	// gets the agent protocol operations and authenticates the requests
	// it passes to them (agentproto.Server).
	AgentGateways []agentproto.Gateway
	// NoAgentListener turns off the HTTP channel's agent listener.
	NoAgentListener bool

	// Ready is called once the listeners accept connections.
	Ready func(Addrs)
	// ShutdownTimeout bounds each graceful shutdown step (default 15 s).
	ShutdownTimeout time.Duration
	// FeedTransport sends the requests to feed servers; nil uses the
	// network.
	FeedTransport http.RoundTripper
}

// Session configures the built-in login.
type Session struct {
	// Provider checks passwords. Nil is the single user of
	// BOMCENSUS_ADMIN_USER and BOMCENSUS_ADMIN_PASSWORD_HASH.
	Provider auth.PasswordProvider
	// Restore turns a stored session (principal id and name) back into a
	// principal on every request. Nil restores an auth.User. Returning a
	// nil principal ends the session.
	Restore func(ctx context.Context, id, name string) (auth.Principal, error)
	// Lifetime of a session after login (default 12 h).
	Lifetime time.Duration
}

// Addrs are the bound listener addresses. Agent is nil with
// NoAgentListener.
type Addrs struct {
	Web   net.Addr
	Agent net.Addr
}

// EmbeddedConsole returns the web console built into this module. A module
// built without the console (go build without the frontend build step)
// returns a page that says so.
func EmbeddedConsole() fs.FS {
	f, _ := console.FS()
	return f
}

// Run starts the server and blocks until ctx ends or a component fails. It
// returns nil after a shutdown caused by ctx.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger, opts Options) error {
	return app.Run(ctx, cfg, log, appOptions(opts))
}

// Migrate applies the database migrations.
func Migrate(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	return app.Migrate(ctx, cfg, log)
}

func appOptions(o Options) app.Options {
	ao := app.Options{
		Scans:           app.ScanService,
		ShutdownTimeout: o.ShutdownTimeout,
		FeedTransport:   o.FeedTransport,
		Console:         o.Console,
		APIMiddleware:   o.APIMiddleware,
		Authorizer:      o.Authorizer,
		Mounts:          o.Mounts,
		WebListener:     o.WebListener,
		AgentListener:   o.AgentListener,
		AgentGateways:   o.AgentGateways,
		NoAgentListener: o.NoAgentListener,
	}
	if o.Ready != nil {
		ao.Ready = func(a app.Addrs) { o.Ready(Addrs{Web: a.Web, Agent: a.Agent}) }
	}
	if o.Session != nil {
		ao.Session = &app.Session{Provider: o.Session.Provider, Restore: o.Session.Restore, Lifetime: o.Session.Lifetime}
	}
	return ao
}
