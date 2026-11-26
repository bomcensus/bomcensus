// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package app is the composition root of bomcensus-server: it wires the
// store, the services, the job queue and the two listeners from a
// config.Config and runs them until the context ends.
//
// The adapters between services that do not know each other live here as
// well (agentapi.Updates, agentapi.Ingest, the asset collector, the cleanup
// job's store).
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/bomcensus/bomcensus/agentproto"
	admingen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/inventoryapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/manageapi"
	"github.com/bomcensus/bomcensus/internal/server/agentapi"
	"github.com/bomcensus/bomcensus/internal/server/detectorsvc"
	"github.com/bomcensus/bomcensus/internal/server/dispatch"
	"github.com/bomcensus/bomcensus/internal/server/enrollsvc"
	"github.com/bomcensus/bomcensus/internal/server/feedsvc"
	"github.com/bomcensus/bomcensus/internal/server/ingest"
	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/session"
	"github.com/bomcensus/bomcensus/internal/server/store/postgres"
	"github.com/bomcensus/bomcensus/internal/server/updatesvc"
	"github.com/bomcensus/bomcensus/internal/server/vulnsvc"
	"github.com/bomcensus/bomcensus/internal/version"
	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/authz"
	"github.com/bomcensus/bomcensus/server/config"
	"github.com/bomcensus/bomcensus/server/scope"
)

// Defaults of Options.
const (
	DefaultShutdownTimeout = 15 * time.Second
	DefaultCleanupInterval = time.Hour
)

// Options are the optional parts of Run. The zero value runs the server
// without a scan service.
type Options struct {
	// Scans builds the scan service; nil runs without one (see Scans).
	Scans NewScans
	// Ready is called once both listeners accept connections.
	Ready func(Addrs)
	// ShutdownTimeout bounds each graceful shutdown step: in-flight console
	// requests, then running jobs. Default DefaultShutdownTimeout. The agent
	// listener has its own bound (agentapi.ServeOptions).
	ShutdownTimeout time.Duration
	// CleanupInterval is the period of the cleanup job. Default
	// DefaultCleanupInterval.
	CleanupInterval time.Duration
	// FeedTransport sends the requests to feed servers; nil uses the
	// network.
	FeedTransport http.RoundTripper

	// Console is the built console; nil serves the admin API only.
	Console fs.FS
	// Session enables the built-in login and cookie sessions; nil disables
	// them.
	Session *Session
	// APIMiddleware, Authorizer and Mounts extend the admin API
	// (adminapi.Options).
	APIMiddleware []func(http.Handler) http.Handler
	Authorizer    authz.Authorizer
	Mounts        map[string]http.Handler
	// WebListener and AgentListener replace the listeners on
	// Config.WebListen and Config.AgentListen. Run owns them.
	WebListener   net.Listener
	AgentListener net.Listener

	// NoAgentListener turns off the HTTP channel's agent listener; agents
	// then reach the server through AgentGateways (or listen-mode
	// targets) only.
	NoAgentListener bool
	// AgentGateways are further channels agents connect through. Each
	// runs with the agent protocol operations until the server stops.
	AgentGateways []agentproto.Gateway
}

// Session configures the built-in login.
type Session struct {
	// Provider checks passwords. Nil is the single user of
	// Config.AdminUser and Config.AdminPasswordHash.
	Provider auth.PasswordProvider
	// Restore turns a stored session back into a principal
	// (session.Config.Restore).
	Restore func(ctx context.Context, id, name string) (auth.Principal, error)
	// Lifetime defaults to session.DefaultSessionLifetime.
	Lifetime time.Duration
}

// Addrs are the bound listener addresses.
type Addrs struct {
	Web   net.Addr
	Agent net.Addr
}

// Run starts the server and blocks until ctx ends or a component fails.
// On the way out it stops accepting connections, lets in-flight requests and
// jobs finish within Options.ShutdownTimeout, stops the queue and closes the
// database pool. It returns nil after a shutdown caused by ctx.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger, opts Options) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = DefaultShutdownTimeout
	}
	if opts.CleanupInterval <= 0 {
		opts.CleanupInterval = DefaultCleanupInterval
	}

	// Checks that need no database come first.
	key, err := secret.LoadKey(cfg.MasterKey.Reveal(), cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	box, err := secret.New(key)
	clear(key)
	if err != nil {
		return err
	}
	var provider auth.PasswordProvider
	if opts.Session != nil {
		provider = opts.Session.Provider
		if provider == nil {
			env, err := session.NewEnvProvider(log, cfg.AdminUser, cfg.AdminPasswordHash)
			if err != nil {
				return fmt.Errorf("%s: %w", config.EnvAdminPasswordHash, err)
			}
			provider = env
		}
	}

	// Startup and the background components act for no principal. Console
	// requests do not derive from ctx; they get the scope of their
	// authorization.
	sys := scope.System(ctx)

	db, err := postgres.Open(ctx, cfg.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := migrateStore(ctx, db); err != nil {
		return err
	}
	dets, err := detectorsvc.New(detectorsvc.Config{Store: db, DefaultFile: cfg.DetectorsFile,
		Logger: log.With("component", "detectors")})
	if err != nil {
		return fmt.Errorf("%s: %w", config.EnvDetectorsFile, err)
	}

	webTLS := cfg.WebTLS != config.WebTLSOff
	pki, err := pkisvc.New(pkisvc.Config{
		Store:            db,
		Box:              box,
		WebTLS:           webTLS,
		WebServerNames:   cfg.WebServerNames,
		AgentServerNames: cfg.AgentServerNames,
		UnsyncedAgents:   manageapi.UnsyncedAgents(db),
		Logger:           log.With("component", "pki"),
	})
	if err != nil {
		return err
	}
	if err := pki.Bootstrap(sys); err != nil {
		return fmt.Errorf("pki bootstrap: %w", err)
	}

	upd, err := updatesvc.New(updatesvc.Config{Store: db, Logger: log.With("component", "updates")})
	if err != nil {
		return err
	}
	if cfg.ReleaseDir != "" {
		if err := upd.ImportDir(sys, cfg.ReleaseDir); err != nil {
			return fmt.Errorf("%s: %w", config.EnvReleaseDir, err)
		}
	}

	var authSvc *session.Service
	if opts.Session != nil {
		authSvc = session.NewService(session.Config{
			Provider:        provider,
			Sessions:        db,
			Restore:         opts.Session.Restore,
			SessionLifetime: opts.Session.Lifetime,
			Logger:          log.With("component", "auth"),
			TrustProxy:      cfg.TrustProxy,
		})
	}
	disp := dispatch.New(db)
	enroll, err := enrollsvc.New(enrollsvc.Options{Store: db, PKI: pki, Logger: log.With("component", "enroll")})
	if err != nil {
		return err
	}
	ing := ingest.New(db, log.With("component", "ingest"), nil)
	feed, err := feedsvc.New(feedsvc.Config{Store: db, Box: box, Version: version.Version, Base: opts.FeedTransport,
		Logger: log.With("component", "feed")})
	if err != nil {
		return err
	}
	// Deferred before the queue starts, so it runs after the jobs stopped.
	defer feed.Close()

	queue := job.NewRiver(db.Pool(), log.With("component", "queue"), job.RiverConfig{})
	jobLog := log.With("component", "job")
	cleanup := cleanupStore{Store: db, sessions: authSvc, enroll: enroll, dispatch: disp}
	refresher, err := vulnsvc.NewRefresher(db, queue, log.With("component", "findings"))
	if err != nil {
		return err
	}
	matcher, err := vulnsvc.New(vulnsvc.Config{Store: db, Feed: feed, Queue: queue, Logger: log.With("component", "match"),
		Matched: func(ctx context.Context) {
			if err := refresher.Trigger(ctx, 0); err != nil {
				log.Warn("queue findings refresh", "error", err)
			}
		}})
	if err != nil {
		return err
	}
	if err := errors.Join(
		queue.Register(job.KindIngestReport, afterIngest(job.IngestReportHandler(ing, jobLog), matcher, refresher, jobLog)),
		queue.Register(job.KindCleanup, job.CleanupHandler(cleanup, job.DefaultRetention(), jobLog, nil)),
		queue.Periodic(job.KindCleanup, opts.CleanupInterval, job.CleanupArgs{}),
		matcher.Register(queue, vulnsvc.DefaultInterval),
		refresher.Register(queue, vulnsvc.DefaultRefreshInterval),
		vulnsvc.NewExpirer(db, log.With("component", "triage")).Register(queue, vulnsvc.DefaultExpireInterval),
		vulnsvc.NewSymbolChecker(db, disp, log.With("component", "gosymbols")).Register(queue, vulnsvc.DefaultSymbolCheckInterval),
	); err != nil {
		return err
	}

	var scans Scans
	if opts.Scans != nil {
		scans, err = opts.Scans(sys, Services{
			Config: cfg, Store: db, Queue: queue, Dispatch: disp, Ingest: ing,
			Updates: upd, PKI: pki, Secrets: box, Detectors: dets, Logger: log.With("component", "scans"),
		})
		if err != nil {
			return fmt.Errorf("scan service: %w", err)
		}
	}

	// Console API.
	inv := inventoryapi.Config{
		Store:        db,
		Agents:       db,
		Collector:    collector{dispatch: disp, scans: scans},
		Credentials:  inventoryapi.StoreCredentials{Store: db},
		AgentAddress: agentAddress(cfg),
		Logger:       log.With("component", "api"),
	}
	mgmt := manageapi.Config{
		Store:       db,
		PKI:         pki,
		Updates:     upd,
		Secrets:     box,
		Feed:        feed,
		Matcher:     matcher,
		Detectors:   dets,
		PrincipalID: auth.IDFrom,
		Logger:      log.With("component", "api"),
	}
	if authSvc != nil {
		inv.Auth = authSvc
	}
	if scans != nil {
		inv.Syncer = scans
		mgmt.ScanRunner = scans
	}
	manage, err := manageapi.New(mgmt)
	if err != nil {
		return err
	}
	api, err := adminapi.NewRouter(adminapi.Options{
		Handlers:   consoleAPI{Handlers: inventoryapi.New(inv), manageHandlers: manageHandlers{manage}},
		Session:    authSvc,
		TrustProxy: cfg.TrustProxy,
		Middleware: opts.APIMiddleware,
		Authorizer: opts.Authorizer,
		Mounts:     opts.Mounts,
		Logger:     log.With("component", "http"),
		Console:    opts.Console,
	})
	if err != nil {
		return err
	}
	webHandler := withHealth(api, health{db: db, pki: pki, webTLS: webTLS})

	// Agent API.
	agentSvc, err := agentapi.New(agentapi.Options{
		Store:     db,
		PKI:       pki,
		Enroll:    enroll,
		Dispatch:  disp,
		Updates:   updates{svc: upd},
		Ingest:    &reportIngest{ing: ing, queue: queue, scans: scans, log: log.With("component", "agentapi")},
		Detectors: dets,
		Logger:    log.With("component", "agentapi"),
	})
	if err != nil {
		return err
	}
	agentHandler := agentSvc.HTTP()
	verifier := agentapi.NewAgentVerifier(pki)
	reverse, err := agentapi.NewReverseManager(agentapi.ReverseOptions{
		Store:             db,
		Handler:           agentHandler,
		Verifier:          verifier,
		ClientCertificate: pki.AgentClientCertificate,
		Logger:            log.With("component", "reverse"),
	})
	if err != nil {
		return err
	}

	// Listeners are bound before the queue starts so that a taken port
	// fails the start without side effects.
	webLn, agentLn, err := listeners(ctx, cfg, opts)
	if err != nil {
		return err
	}

	if err := queue.Start(sys); err != nil {
		_ = webLn.Close()
		if agentLn != nil {
			_ = agentLn.Close()
		}
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.ShutdownTimeout)
		defer cancel()
		if err := queue.Stop(sctx); err != nil {
			log.Warn("job queue stop", "error", err)
		}
	}()

	webSrv := &http.Server{
		Handler:           webHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.With("component", "http").Handler(), slog.LevelWarn),
	}
	if webTLS {
		webSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return pki.WebCertificate()
			},
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return serveWeb(gctx, webSrv, webLn, webTLS, opts.ShutdownTimeout) })
	if agentLn != nil {
		g.Go(func() error {
			return agentapi.Serve(gctx, agentLn, agentapi.ServeOptions{
				Handler:         agentHandler,
				Certificate:     pki.AgentServerCertificate,
				Verifier:        verifier,
				ShutdownTimeout: opts.ShutdownTimeout,
				Logger:          log.With("component", "agentapi"),
			})
		})
	}
	for i, gw := range opts.AgentGateways {
		name := fmt.Sprintf("agent gateway %d", i)
		g.Go(func() error {
			return background(gctx, name, func(ctx context.Context) error { return gw.Run(ctx, agentSvc.Gateway()) })
		})
	}
	g.Go(func() error { return background(gctx, "reverse dialing", reverse.Run) })
	g.Go(func() error { return background(gctx, "pki maintenance", pki.Run) })
	g.Go(func() error { return background(gctx, "feed connection", feed.Run) })
	if scans != nil {
		g.Go(func() error { return background(gctx, "scan service", scans.Run) })
	}

	var agentAddr net.Addr
	if agentLn != nil {
		agentAddr = agentLn.Addr()
	}
	logStartup(sys, log, pki, cfg, webLn.Addr(), agentAddr, opts, scans != nil, reverse.Owner())
	if opts.Ready != nil {
		opts.Ready(Addrs{Web: webLn.Addr(), Agent: agentAddr})
	}

	if err := g.Wait(); err != nil {
		log.Error("server stopped", "error", err)
		return err
	}
	log.Info("listeners closed, stopping")
	return nil
}

// afterIngest queues component matching and a findings refresh shortly
// after a report was applied. Reports that arrive in the meantime share the
// runs.
func afterIngest(h job.Handler, m *vulnsvc.Matcher, r *vulnsvc.Refresher, log *slog.Logger) job.Handler {
	return func(ctx context.Context, j job.Job) error {
		if err := h(ctx, j); err != nil {
			return err
		}
		if err := m.Trigger(ctx, time.Minute); err != nil {
			log.Warn("queue component matching", "error", err)
		}
		if err := r.Trigger(ctx, 30*time.Second); err != nil {
			log.Warn("queue findings refresh", "error", err)
		}
		return nil
	}
}

// consoleAPI is the complete console API. The management handlers sit one
// level deeper because both embedded types are named Handlers.
type consoleAPI struct {
	*inventoryapi.Handlers
	manageHandlers
}

type manageHandlers struct{ *manageapi.Handlers }

var _ admingen.StrictServerInterface = consoleAPI{}

// serveWeb runs the console listener until ctx ends, then shuts it down
// within timeout.
func serveWeb(ctx context.Context, srv *http.Server, ln net.Listener, useTLS bool, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		if useTLS {
			done <- srv.ServeTLS(ln, "", "")
		} else {
			done <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-done:
		return fmt.Errorf("web listener: %w", err)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("web listener: %w", err)
	}
	return nil
}

// background runs a component loop with the system data scope; ending
// because ctx ended is not an error, ending before is.
func background(ctx context.Context, name string, run func(context.Context) error) error {
	err := run(scope.System(ctx))
	switch {
	case ctx.Err() != nil:
		return nil
	case err == nil:
		return fmt.Errorf("%s stopped unexpectedly", name)
	}
	return fmt.Errorf("%s: %w", name, err)
}

// logStartup writes the one startup summary line. It names no secrets.
func logStartup(ctx context.Context, log *slog.Logger, pki *pkisvc.Service, cfg config.Config,
	web, agent net.Addr, opts Options, scans bool, owner string) {
	webMode, agentMode := string(config.WebTLSOff), "unknown"
	st, err := pki.Status(ctx)
	if err != nil {
		log.Warn("tls status", "error", err)
	} else {
		agentMode = st.Agent.Mode
		if cfg.WebTLS != config.WebTLSOff {
			webMode = st.Web.Mode
			if cfg.WebTLS == config.WebTLSManual && st.Web.Mode != pkisvc.ModeManual {
				log.Warn("no manual Web/API certificate is stored; serving the automatic one until one is uploaded",
					"setting", config.EnvWebTLS)
			}
		}
	}
	log.Info("bomcensus server started",
		"version", version.Version,
		"web_listen", web.String(),
		"web_tls", webMode,
		"agent_listen", addrString(agent),
		"agent_gateways", len(opts.AgentGateways),
		"agent_tls", agentMode,
		"agent_server_names", cfg.AgentServerNames,
		"console", opts.Console != nil,
		"login", opts.Session != nil && (opts.Session.Provider != nil || cfg.AdminUser != ""),
		"api_middleware", len(opts.APIMiddleware),
		"custom_authorizer", opts.Authorizer != nil,
		"trust_proxy", cfg.TrustProxy,
		"scan_service", scans,
		"embedded_scanner", cfg.EmbeddedScanner && scans,
		"replica", owner,
	)
}

// listeners returns the listeners of Options or binds Config's addresses.
func listeners(ctx context.Context, cfg config.Config, opts Options) (web, agent net.Listener, err error) {
	var lc net.ListenConfig
	web, agent = opts.WebListener, opts.AgentListener
	if web == nil {
		if web, err = lc.Listen(ctx, "tcp", cfg.WebListen); err != nil {
			if agent != nil {
				_ = agent.Close()
			}
			return nil, nil, fmt.Errorf("%s: %w", config.EnvWebListen, err)
		}
	}
	if opts.NoAgentListener {
		if agent != nil {
			_ = agent.Close()
		}
		return web, nil, nil
	}
	if agent == nil {
		if agent, err = lc.Listen(ctx, "tcp", cfg.AgentListen); err != nil {
			_ = web.Close()
			return nil, nil, fmt.Errorf("%s: %w", config.EnvAgentListen, err)
		}
	}
	return web, agent, nil
}

// agentAddress is the address agents are told to connect to: the first
// Agent TLS server name with the port of the agent listener.
func agentAddress(cfg config.Config) string {
	if len(cfg.AgentServerNames) == 0 {
		return ""
	}
	_, port, err := net.SplitHostPort(cfg.AgentListen)
	if err != nil || port == "" || port == "0" {
		return ""
	}
	return net.JoinHostPort(cfg.AgentServerNames[0], port)
}

func addrString(a net.Addr) string {
	if a == nil {
		return "off"
	}
	return a.String()
}
