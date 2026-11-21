// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bomcensus/bomcensus/internal/link"
)

// ServeOptions configures Serve.
type ServeOptions struct {
	// Handler is the NewHandler result.
	Handler http.Handler
	// Certificate returns the Agent TLS server certificate with its chain
	// (PKI.AgentTLSCertificate).
	Certificate func() (*tls.Certificate, error)
	// Verifier checks client certificates during the handshake
	// (NewAgentVerifier).
	Verifier *link.AgentVerifier
	// ShutdownTimeout bounds the graceful shutdown (default 10 s).
	ShutdownTimeout time.Duration
	Logger          *slog.Logger
}

// Timeouts of the connect-mode server. Reads and writes are long enough
// for report uploads and bundle downloads; a long poll answers within
// 30 s.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 15 * time.Minute
	writeTimeout      = 15 * time.Minute
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 64 << 10
)

// Serve runs the connect-mode HTTPS server on ln until ctx is done, then
// shuts it down gracefully. It owns ln. It returns nil after a shutdown
// caused by ctx.
func Serve(ctx context.Context, ln net.Listener, o ServeOptions) error {
	if o.Handler == nil {
		return errors.New("agentapi: Serve needs a handler")
	}
	tlsConf, err := link.ServerTLSConfig(o.Certificate, o.Verifier)
	if err != nil {
		_ = ln.Close()
		return err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	srv := &http.Server{
		Handler:           o.Handler,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-done:
		return fmt.Errorf("agentapi: serve: %w", err)
	case <-ctx.Done():
	}
	timeout := o.ShutdownTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("agentapi: serve: %w", err)
	}
	return nil
}
