// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
)

// BasePath is the path prefix of the agent protocol.
const BasePath = "/agent/v1"

// Connection modes.
const (
	ModeConnect = "connect"
	ModeListen  = "listen"
)

// exemptPaths are signed requests whose responses are streamed unsigned.
var exemptPaths = msgsig.Paths{BasePath + "/update/bundle/", BasePath + "/probe/"}

// maxJSONBody bounds unsigned JSON responses (enrollment, server chain).
const maxJSONBody = 4 << 20

// linkParams describes the connection to the server.
type linkParams struct {
	mode       string
	serverURL  string
	serverName string
	tlsMode    link.TLSMode
	verify     link.ServerVerifier
	extraRoots []*x509.Certificate
	// cert returns the client certificate (connect, pinned) or the
	// listener certificate (listen).
	cert        func() (*tls.Certificate, error)
	listenAddr  string
	onListening func(net.Addr)
	connect     link.ConnectOptions
	logger      *slog.Logger
}

// linkConn is an open connection setup: an unsigned round tripper and the
// base URL of the protocol.
type linkConn struct {
	base     http.RoundTripper
	baseURL  string
	observed *link.ObservedPeer
	// reset drops open connections so that the next request performs a
	// new handshake with the current certificate.
	reset func()
	close func()
}

// serverVerifier verifies server chains against the trust bundle anchors
// when there is a bundle and against the enrollment pin before that.
func serverVerifier(pin [32]byte, serverName string, bundle func() *pki.TrustBundle) link.ServerVerifier {
	return func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error {
		if b := bundle(); b != nil {
			return pki.VerifyAnchors(chain, b.Anchors, serverName, usage)
		}
		return pki.VerifyPinned(chain, pin, serverName, usage)
	}
}

// NormalizeServerURL checks an https server address and strips a trailing
// slash and the protocol base path.
func NormalizeServerURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("server address must be https://HOST[:PORT], got %q", s)
	}
	p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), BasePath)
	u.Path = strings.TrimSuffix(p, "/")
	return u.String(), nil
}

func openLink(ctx context.Context, p linkParams) (*linkConn, error) {
	obs := &link.ObservedPeer{}
	switch p.mode {
	case ModeConnect, "":
		var getCert func() (*tls.Certificate, error)
		if p.tlsMode == link.TLSPinned {
			getCert = p.cert
		}
		tc, err := link.ClientTLSConfig(link.ClientConfig{
			Mode:              p.tlsMode,
			Verify:            p.verify,
			ClientCertificate: getCert,
			ExtraRoots:        p.extraRoots,
			ObservePeer:       obs.Observe,
		})
		if err != nil {
			return nil, err
		}
		rt := link.NewConnectTransport(tc, p.connect)
		return &linkConn{
			base:     rt,
			baseURL:  p.serverURL + BasePath + "/",
			observed: obs,
			reset: func() {
				if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
					c.CloseIdleConnections()
				}
			},
			close: func() {
				if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
					c.CloseIdleConnections()
				}
			},
		}, nil
	case ModeListen:
		l, err := link.Listen(ctx, p.listenAddr, link.ListenConfig{
			Certificate: p.cert,
			Verify:      p.verify,
			ObservePeer: obs.Observe,
			Logger:      p.logger,
		})
		if err != nil {
			return nil, err
		}
		if p.onListening != nil {
			p.onListening(l.Addr())
		}
		p.logger.Info("waiting for the server to connect", "address", l.Addr().String())
		holder := &link.ReverseHolder{}
		var (
			mu  sync.Mutex
			cur *link.ReverseConn
		)
		accept := func(rc *link.ReverseConn) {
			mu.Lock()
			cur = rc
			mu.Unlock()
			holder.Set(rc)
		}
		sctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := l.Serve(sctx, accept); err != nil && sctx.Err() == nil {
				p.logger.Error("listener stopped", "error", err)
			}
		}()
		return &linkConn{
			base:     holder,
			baseURL:  "https://" + p.serverName + BasePath + "/",
			observed: obs,
			reset: func() {
				// The server reconnects and sees the new certificate.
				mu.Lock()
				c := cur
				mu.Unlock()
				if c != nil {
					_ = c.Close()
				}
			},
			close: func() {
				cancel()
				<-done
			},
		}, nil
	}
	return nil, fmt.Errorf("unknown connect mode %q", p.mode)
}

// serverKeys resolves response key ids through GET /server-chain and caches
// the verified leaf keys (PROTOCOL §3.4).
type serverKeys struct {
	fetch  func(ctx context.Context) ([]*x509.Certificate, error)
	verify func(chain []*x509.Certificate) error

	mu   sync.Mutex
	keys map[string]crypto.PublicKey
}

func (k *serverKeys) add(cert *x509.Certificate) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil {
		k.keys = map[string]crypto.PublicKey{}
	}
	k.keys[msgsig.KeyID(cert)] = cert.PublicKey
}

// ServerKey implements msgsig.ServerKeys.
func (k *serverKeys) ServerKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	k.mu.Lock()
	pub, ok := k.keys[keyID]
	k.mu.Unlock()
	if ok {
		return pub, nil
	}
	chain, err := k.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch server chain: %w", err)
	}
	if err := k.verify(chain); err != nil {
		return nil, fmt.Errorf("server chain: %w", err)
	}
	if got := msgsig.KeyID(chain[0]); got != keyID {
		return nil, fmt.Errorf("server chain is for key %s, not %s", got, keyID)
	}
	k.add(chain[0])
	return chain[0].PublicKey, nil
}

// fetchServerChain performs the unsigned GET /server-chain.
func fetchServerChain(ctx context.Context, rt http.RoundTripper, baseURL string) ([]*x509.Certificate, error) {
	req, err := agentapi.NewGetServerChainRequest(baseURL)
	if err != nil {
		return nil, err
	}
	status, _, body, err := doRaw(ctx, rt, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	var sc agentapi.ServerChain
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var chain []*x509.Certificate
	for _, p := range sc.ChainPem {
		certs, err := pki.ParseCertificatesPEM([]byte(p))
		if err != nil {
			return nil, err
		}
		chain = append(chain, certs...)
	}
	if len(chain) == 0 {
		return nil, pki.ErrEmptyChain
	}
	return chain, nil
}

// doRaw sends req and returns the status, header and the complete body.
func doRaw(ctx context.Context, rt http.RoundTripper, req *http.Request) (int, http.Header, []byte, error) {
	resp, err := (&http.Client{Transport: rt}).Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBody+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxJSONBody {
		return 0, nil, nil, errors.New("response too large")
	}
	return resp.StatusCode, resp.Header, body, nil
}

// APIError is a non-success response of the server.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("server returned status %d", e.Status)
	}
	return fmt.Sprintf("server returned status %d (%s): %s", e.Status, e.Code, e.Message)
}

// IsStatus reports whether err is an APIError with the given status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

func apiError(status int, body []byte) error {
	e := &APIError{Status: status}
	var eb agentapi.Error
	if json.Unmarshal(body, &eb) == nil {
		e.Code = eb.Code
		e.Message = truncate(eb.Message, 256)
	}
	return e
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// DecodeResponse checks the status of a response and decodes its JSON body
// into v (nil skips decoding). Other statuses yield an *APIError.
func DecodeResponse(resp *http.Response, body []byte, want int, v any) error {
	if resp == nil {
		return errors.New("no response")
	}
	if resp.StatusCode != want {
		return apiError(resp.StatusCode, body)
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
