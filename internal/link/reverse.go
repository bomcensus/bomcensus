// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// ReversePeer is the identity of a listen-mode agent: either a verified
// agent id or Unenrolled for a temporary certificate.
type ReversePeer struct {
	AgentID    string
	Unenrolled bool
}

// ReverseDialConfig configures DialReverse.
type ReverseDialConfig struct {
	// ClientCertificate returns the server's Agent TLS client certificate
	// with its chain. Required.
	ClientCertificate func() (*tls.Certificate, error)

	// VerifyAgent classifies the agent's certificate chain (leaf first).
	// Returning an error aborts the connection. AgentVerifier.VerifyReverse
	// is the usual base; the caller adds its own policy, such as the agent
	// id bound to the dialed address. Required.
	VerifyAgent func(chain []*x509.Certificate) (ReversePeer, error)

	// DialTimeout defaults to 15 s, HandshakeTimeout to 15 s.
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// PingInterval and PingTimeout detect dead connections. Defaults 30 s
	// and 15 s.
	PingInterval time.Duration
	PingTimeout  time.Duration

	// Logger receives HTTP/2 server errors. Nil discards them.
	Logger *slog.Logger
}

// DialReverse connects to a listen-mode agent at addr, performs the TLS
// handshake as client offering only ALPNReverse, and then serves HTTP/2
// with handler on the connection until it ends or ctx is done. Requests
// carry the agent identity (PeerAgentID, PeerUnenrolled, PeerReverse) and
// the dialed address in r.RemoteAddr.
//
// It returns an error if the connection could not be set up, including
// when the agent rejected the handshake or closed the connection before
// HTTP/2 started; nil when an established connection ended; ctx.Err() on
// cancellation.
func DialReverse(ctx context.Context, addr string, cfg ReverseDialConfig, handler http.Handler) error {
	if cfg.ClientCertificate == nil || cfg.VerifyAgent == nil {
		return errors.New("link: reverse dial needs a client certificate and an agent verifier")
	}
	if handler == nil {
		return errors.New("link: reverse dial needs a handler")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	dialer := &net.Dialer{Timeout: orDefault(cfg.DialTimeout, 15*time.Second), KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("link: dial %s: %w", addr, err)
	}

	var p ReversePeer
	getCert, verifyAgent := cfg.ClientCertificate, cfg.VerifyAgent
	tc := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPNReverse},
		// The agent certificate is not issued for a host name; it is
		// verified against the Agent CA in VerifyConnection.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, err := getCert()
			if err != nil {
				return nil, fmt.Errorf("link: client certificate: %w", err)
			}
			if c == nil {
				return nil, errors.New("link: no client certificate")
			}
			return c, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != ALPNReverse {
				return fmt.Errorf("link: agent negotiated ALPN %q, want %q", cs.NegotiatedProtocol, ALPNReverse)
			}
			got, err := verifyAgent(cs.PeerCertificates)
			if err != nil {
				return fmt.Errorf("link: agent certificate: %w", err)
			}
			if (got.AgentID == "") == !got.Unenrolled {
				return errors.New("link: agent verifier returned neither an agent id nor unenrolled")
			}
			p = got
			return nil
		},
	})
	hctx, cancel := context.WithTimeout(ctx, orDefault(cfg.HandshakeTimeout, 15*time.Second))
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		_ = tc.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("link: TLS handshake with %s: %w", addr, err)
	}

	conn := &readTracker{Conn: tc}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	srv := &http2.Server{
		ReadIdleTimeout: orDefault(cfg.PingInterval, 30*time.Second),
		PingTimeout:     orDefault(cfg.PingTimeout, 15*time.Second),
	}
	base := &http.Server{ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn)}
	reqCtx := withPeer(ctx, peer{agentID: p.AgentID, unenrolled: p.Unenrolled, reverse: true})
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: reqCtx, BaseConfig: base, Handler: handler})
	_ = conn.Close()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !conn.started.Load() {
		if rerr := conn.readErr(); rerr != nil {
			return fmt.Errorf("link: agent %s closed the connection before HTTP/2 started: %w", addr, rerr)
		}
		return fmt.Errorf("link: agent %s closed the connection before HTTP/2 started", addr)
	}
	return nil
}

// readTracker records whether any application data arrived. In TLS 1.3 the
// client finishes its handshake before the server has checked the client
// certificate, so a rejection by the agent only shows up on the first read.
type readTracker struct {
	*tls.Conn
	started atomic.Bool
	mu      sync.Mutex
	err     error
}

func (c *readTracker) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.started.Store(true)
	}
	if err != nil {
		c.mu.Lock()
		if c.err == nil {
			c.err = err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *readTracker) readErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
