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
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// ListenConfig configures the agent's listen-mode listener.
type ListenConfig struct {
	// Certificate returns the listener certificate: the temporary
	// self-signed one (pki.NewTemporaryCertificate) before enrollment, the
	// issued agent certificate afterwards. Called for every handshake.
	// Required.
	Certificate func() (*tls.Certificate, error)

	// Verify checks the client certificate the server presents, with
	// clientAuth usage: PinnedVerifier before enrollment, AnchorVerifier
	// afterwards. Required.
	Verify ServerVerifier

	// ObservePeer, if set, receives the server's client certificate after
	// every accepted handshake.
	ObservePeer PeerObserver

	// AllowedSources, if not empty, restricts the peer addresses that may
	// connect. Others are closed before the handshake.
	AllowedSources []netip.Prefix

	// MaxHandshakes bounds concurrent unauthenticated connections. A
	// connection arriving while the limit is reached is closed. Default 8.
	MaxHandshakes int
	// HandshakeTimeout bounds the TLS handshake and HTTP/2 setup. Default
	// 10 s.
	HandshakeTimeout time.Duration
	// PingInterval and PingTimeout detect dead connections. Defaults 30 s
	// and 15 s.
	PingInterval time.Duration
	PingTimeout  time.Duration

	// Logger receives connection events. Nil discards them.
	Logger *slog.Logger
}

// Listener accepts reverse connections from the server (SECURITY §4.5).
type Listener struct {
	ln      net.Listener
	tlsConf *tls.Config
	h2      *http2.Transport
	sem     chan struct{}
	allow   []netip.Prefix
	timeout time.Duration
	logger  *slog.Logger

	mu    sync.Mutex
	conns map[*ReverseConn]struct{}
}

// Listen listens on the TCP address addr.
func Listen(ctx context.Context, addr string, cfg ListenConfig) (*Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("link: listen %s: %w", addr, err)
	}
	l, err := NewListener(ln, cfg)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return l, nil
}

// NewListener serves reverse connections on ln. The Listener owns ln.
func NewListener(ln net.Listener, cfg ListenConfig) (*Listener, error) {
	if cfg.Certificate == nil || cfg.Verify == nil {
		return nil, errors.New("link: listener needs a certificate and a server verifier")
	}
	maxHS := cfg.MaxHandshakes
	if maxHS <= 0 {
		maxHS = 8
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	getCert, verify, obs := cfg.Certificate, cfg.Verify, cfg.ObservePeer
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPNReverse},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := getCert()
			if err != nil {
				return nil, fmt.Errorf("link: listener certificate: %w", err)
			}
			if c == nil {
				return nil, errors.New("link: no listener certificate")
			}
			return c, nil
		},
		ClientAuth: tls.RequireAnyClientCert,
		// Every connection is verified with the current certificate and
		// trust state; resumption would carry over the previous ones.
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != ALPNReverse {
				return fmt.Errorf("link: peer did not negotiate %q", ALPNReverse)
			}
			if err := verify(cs.PeerCertificates, x509.ExtKeyUsageClientAuth); err != nil {
				return fmt.Errorf("link: server client certificate: %w", err)
			}
			observe(obs, cs.PeerCertificates)
			return nil
		},
	}
	return &Listener{
		ln:      ln,
		tlsConf: tlsConf,
		h2: &http2.Transport{
			ReadIdleTimeout: orDefault(cfg.PingInterval, 30*time.Second),
			PingTimeout:     orDefault(cfg.PingTimeout, 15*time.Second),
			// Requests wait for a free stream instead of making the
			// connection look unusable while it is busy.
			StrictMaxConcurrentStreams: true,
		},
		sem:     make(chan struct{}, maxHS),
		allow:   cfg.AllowedSources,
		timeout: orDefault(cfg.HandshakeTimeout, 10*time.Second),
		logger:  logger,
		conns:   make(map[*ReverseConn]struct{}),
	}, nil
}

// Addr returns the listen address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Serve accepts connections until ctx is done or the listener fails. For
// every verified connection it calls accept with the HTTP/2 client
// connection, typically ReverseHolder.Set; accept must not block. When
// Serve returns, the listener and all connections it handed out are closed.
// It returns ctx.Err() after cancellation.
func (l *Listener) Serve(ctx context.Context, accept func(*ReverseConn)) error {
	if accept == nil {
		return errors.New("link: Serve needs an accept function")
	}
	stop := context.AfterFunc(ctx, func() { _ = l.ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	defer func() {
		_ = l.ln.Close()
		wg.Wait()
		l.mu.Lock()
		conns := l.conns
		l.conns = nil
		l.mu.Unlock()
		for c := range conns {
			_ = c.Close()
		}
	}()

	var backoff time.Duration
	for {
		raw, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(backoff):
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return fmt.Errorf("link: accept: %w", err)
		}
		backoff = 0
		if !l.allowed(raw.RemoteAddr()) {
			l.logger.Debug("reverse connection from disallowed address", "remote", raw.RemoteAddr().String())
			_ = raw.Close()
			continue
		}
		select {
		case l.sem <- struct{}{}:
		default:
			l.logger.Debug("reverse handshake limit reached", "remote", raw.RemoteAddr().String())
			_ = raw.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc := l.handshake(ctx, raw)
			<-l.sem
			if rc == nil {
				return
			}
			if !l.track(rc) {
				_ = rc.Close()
				return
			}
			accept(rc)
		}()
	}
}

func (l *Listener) allowed(a net.Addr) bool {
	if len(l.allow) == 0 {
		return true
	}
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip := ta.AddrPort().Addr().Unmap()
	for _, p := range l.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// handshake runs TLS and the HTTP/2 client setup under the handshake
// timeout. It returns nil on failure, after closing raw.
func (l *Listener) handshake(ctx context.Context, raw net.Conn) *ReverseConn {
	remote := raw.RemoteAddr()
	deadline := time.Now().Add(l.timeout)
	_ = raw.SetDeadline(deadline)
	tc := tls.Server(raw, l.tlsConf)
	hctx, cancel := context.WithDeadline(ctx, deadline)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		l.logger.Info("reverse handshake failed", "remote", remote.String(), "error", err)
		_ = tc.Close()
		return nil
	}
	nc := &notifyConn{Conn: tc, done: make(chan struct{})}
	cc, err := l.h2.NewClientConn(nc)
	if err != nil {
		l.logger.Info("reverse HTTP/2 setup failed", "remote", remote.String(), "error", err)
		_ = nc.Close()
		return nil
	}
	_ = raw.SetDeadline(time.Time{})
	l.logger.Info("reverse connection established", "remote", remote.String())
	return &ReverseConn{cc: cc, conn: nc, remote: remote}
}

// track registers rc until it is closed. It returns false after Serve has
// finished.
func (l *Listener) track(rc *ReverseConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns == nil {
		return false
	}
	l.conns[rc] = struct{}{}
	go func() {
		<-rc.Done()
		l.mu.Lock()
		if l.conns != nil {
			delete(l.conns, rc)
		}
		l.mu.Unlock()
	}()
	return true
}

// notifyConn closes done when the HTTP/2 client connection closes its
// transport, which it does on read errors, lost pings and Close.
type notifyConn struct {
	*tls.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// ReverseConn is an HTTP/2 client connection on a connection the server
// dialed. Requests sent through it reach the server's handlers.
type ReverseConn struct {
	cc     *http2.ClientConn
	conn   *notifyConn
	remote net.Addr
}

// RoundTrip sends req on this connection.
func (c *ReverseConn) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.cc.RoundTrip(req)
}

// RemoteAddr returns the server's address.
func (c *ReverseConn) RemoteAddr() net.Addr { return c.remote }

// Done is closed when the connection has ended.
func (c *ReverseConn) Done() <-chan struct{} { return c.conn.done }

// Close closes the connection immediately.
func (c *ReverseConn) Close() error { return c.cc.Close() }

// Shutdown stops new requests, waits for running ones until ctx is done
// and closes the connection.
func (c *ReverseConn) Shutdown(ctx context.Context) error {
	err := c.cc.Shutdown(ctx)
	if err != nil {
		_ = c.cc.Close()
	}
	return err
}

func (c *ReverseConn) usable() bool {
	select {
	case <-c.conn.done:
		return false
	default:
	}
	return c.cc.CanTakeNewRequest()
}

// ReverseHolder is an http.RoundTripper over the current reverse
// connection, so agent code can use one http.Client in both connection
// modes. RoundTrip waits, bounded by the request context, until a usable
// connection exists. When the server reconnects, Set switches new requests
// to the newer connection and shuts the previous one down after its running
// requests. The zero value is ready to use.
type ReverseHolder struct {
	// DrainTimeout bounds how long a replaced connection may finish its
	// running requests. Default 1 min.
	DrainTimeout time.Duration

	mu      sync.Mutex
	cur     *ReverseConn
	changed chan struct{}
}

// Set makes c the current connection. It can be passed to Listener.Serve.
func (h *ReverseHolder) Set(c *ReverseConn) {
	h.mu.Lock()
	old := h.cur
	h.cur = c
	if h.changed != nil {
		close(h.changed)
	}
	h.changed = make(chan struct{})
	h.mu.Unlock()
	if old != nil && old != c {
		drain := orDefault(h.DrainTimeout, time.Minute)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), drain)
			defer cancel()
			_ = old.Shutdown(ctx)
		}()
	}
}

func (h *ReverseHolder) current() (*ReverseConn, <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.changed == nil {
		h.changed = make(chan struct{})
	}
	return h.cur, h.changed
}

// RoundTrip sends req on the current connection. A request that fails
// because its connection died while it was sent is not retried.
func (h *ReverseHolder) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	for {
		c, changed := h.current()
		if c != nil && c.usable() {
			return c.RoundTrip(req)
		}
		select {
		case <-changed:
		case <-ctx.Done():
			closeBody(req)
			return nil, fmt.Errorf("link: waiting for a reverse connection: %w", ctx.Err())
		}
	}
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
