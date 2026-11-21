// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package link

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ClientConfig configures the agent's TLS client in connect mode.
type ClientConfig struct {
	Mode TLSMode

	// Verify checks the server chain in TLSPinned mode: PinnedVerifier
	// during enrollment, AnchorVerifier afterwards. Required for TLSPinned,
	// ignored otherwise.
	Verify ServerVerifier

	// ClientCertificate returns the agent certificate to present in
	// TLSPinned mode. It is called for every handshake; (nil, nil) sends no
	// certificate, as before enrollment. Ignored in other modes.
	ClientCertificate func() (*tls.Certificate, error)

	// ExtraRoots are trusted in addition to the OS trust store in
	// TLSSystem mode.
	ExtraRoots []*x509.Certificate

	// ObservePeer, if set, receives the server leaf after every successful
	// handshake in every mode.
	ObservePeer PeerObserver
}

// ClientTLSConfig builds the TLS client configuration for connect mode.
// The server name is taken from the request URL by the HTTP transport; in
// TLSPinned mode the name checked is the one the verifier was built with.
func ClientTLSConfig(cfg ClientConfig) (*tls.Config, error) {
	obs := cfg.ObservePeer
	switch cfg.Mode {
	case TLSPinned, "":
		if cfg.Verify == nil {
			return nil, errors.New("link: pinned mode needs a verifier")
		}
		verify, getCert := cfg.Verify, cfg.ClientCertificate
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The chain is verified by VerifyConnection against the pin or
			// the trust bundle; system roots are never used.
			InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				if err := verify(cs.PeerCertificates, x509.ExtKeyUsageServerAuth); err != nil {
					return fmt.Errorf("link: server certificate: %w", err)
				}
				observe(obs, cs.PeerCertificates)
				return nil
			},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if getCert == nil {
					return &tls.Certificate{}, nil
				}
				c, err := getCert()
				if err != nil {
					return nil, fmt.Errorf("link: client certificate: %w", err)
				}
				if c == nil {
					return &tls.Certificate{}, nil
				}
				return c, nil
			},
		}, nil
	case TLSSystem:
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		for _, c := range cfg.ExtraRoots {
			pool.AddCert(c)
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			VerifyConnection: func(cs tls.ConnectionState) error {
				observe(obs, cs.PeerCertificates)
				return nil
			},
		}, nil
	case TLSNone:
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // explicit relaxed mode, SECURITY §4.7
			VerifyConnection: func(cs tls.ConnectionState) error {
				observe(obs, cs.PeerCertificates)
				return nil
			},
		}, nil
	}
	return nil, fmt.Errorf("link: unknown TLS mode %q", cfg.Mode)
}

// ConnectOptions tunes NewConnectTransport. Zero values select defaults.
type ConnectOptions struct {
	// ProxyFromEnvironment uses HTTPS_PROXY / NO_PROXY. Off by default.
	ProxyFromEnvironment bool
	// DialTimeout defaults to 15 s.
	DialTimeout time.Duration
	// TLSHandshakeTimeout defaults to 15 s.
	TLSHandshakeTimeout time.Duration
	// ResponseHeaderTimeout defaults to 2 min, which leaves room for the
	// 30 s long-poll.
	ResponseHeaderTimeout time.Duration
	// IdleConnTimeout defaults to 90 s.
	IdleConnTimeout time.Duration
	// PingInterval is the HTTP/2 idle time after which a ping checks the
	// connection. Defaults to 30 s.
	PingInterval time.Duration
	// PingTimeout closes a connection whose ping is not answered. Defaults
	// to 15 s.
	PingTimeout time.Duration
}

// NewConnectTransport returns the HTTP transport for connect mode. tlsConfig
// should come from ClientTLSConfig; a nil config fails every handshake. The
// transport negotiates HTTP/2 and reuses connections.
func NewConnectTransport(tlsConfig *tls.Config, opts ConnectOptions) http.RoundTripper {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // VerifyConnection always fails
			VerifyConnection: func(tls.ConnectionState) error {
				return errors.New("link: no TLS configuration")
			},
		}
	}
	dialer := &net.Dialer{
		Timeout:   orDefault(opts.DialTimeout, 15*time.Second),
		KeepAlive: 30 * time.Second,
	}
	t := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig.Clone(),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   orDefault(opts.TLSHandshakeTimeout, 15*time.Second),
		ResponseHeaderTimeout: orDefault(opts.ResponseHeaderTimeout, 2*time.Minute),
		IdleConnTimeout:       orDefault(opts.IdleConnTimeout, 90*time.Second),
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: orDefault(opts.PingInterval, 30*time.Second),
			PingTimeout:     orDefault(opts.PingTimeout, 15*time.Second),
		},
	}
	if opts.ProxyFromEnvironment {
		t.Proxy = http.ProxyFromEnvironment
	}
	return t
}

func orDefault(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}
