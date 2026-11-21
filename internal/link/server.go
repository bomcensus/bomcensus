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
	"math/big"
	"net/http"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// AgentVerifier verifies agent certificate chains on the server.
type AgentVerifier struct {
	// AgentCA returns the current Agent CA certificate. Required.
	AgentCA func() *x509.Certificate
	// Revoked reports whether a certificate serial is blocked. An error
	// rejects the certificate. Nil means no serial is revoked. It is
	// called for every handshake and, through Middleware, every request, so
	// it should answer from memory.
	Revoked func(serial *big.Int) (bool, error)
}

// ErrRevoked is returned for a certificate whose serial is blocked.
var ErrRevoked = errors.New("link: agent certificate is revoked")

// ErrRevocationCheck wraps an error of the Revoked callback: the
// certificate is rejected because its state could not be determined.
var ErrRevocationCheck = errors.New("link: revocation check failed")

// Verify checks chain (leaf first) against the Agent CA for usage and the
// revocation check, and returns the agent id.
func (v *AgentVerifier) Verify(chain []*x509.Certificate, usage x509.ExtKeyUsage) (string, error) {
	if v == nil || v.AgentCA == nil {
		return "", errors.New("link: no Agent CA configured")
	}
	id, err := pki.VerifyAgent(chain, v.AgentCA(), usage)
	if err != nil {
		return "", err
	}
	if v.Revoked != nil {
		revoked, err := v.Revoked(chain[0].SerialNumber)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrRevocationCheck, err)
		}
		if revoked {
			return "", ErrRevoked
		}
	}
	return id, nil
}

// VerifyReverse classifies the certificate a listen-mode agent presented,
// for ReverseDialConfig.VerifyAgent: a chain issued by the Agent CA must
// verify (serverAuth) and yields the agent id; any other certificate is the
// temporary one of an agent that has not enrolled yet. A certificate signed
// by the Agent CA that fails verification (expired, revoked) is an error,
// never "unenrolled".
func (v *AgentVerifier) VerifyReverse(chain []*x509.Certificate) (ReversePeer, error) {
	if len(chain) == 0 {
		return ReversePeer{}, pki.ErrEmptyChain
	}
	if v == nil || v.AgentCA == nil {
		return ReversePeer{}, errors.New("link: no Agent CA configured")
	}
	ca := v.AgentCA()
	if ca == nil {
		return ReversePeer{}, errors.New("link: no Agent CA configured")
	}
	if chain[0].CheckSignatureFrom(ca) != nil {
		return ReversePeer{Unenrolled: true}, nil
	}
	id, err := v.Verify(chain, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return ReversePeer{}, err
	}
	return ReversePeer{AgentID: id}, nil
}

// ServerTLSConfig builds the TLS configuration of the server's agent
// listener (connect mode). certificate returns the Agent TLS server
// certificate with its full chain up to the anchor, so pinned agents can
// find the ca-hash. A client certificate is optional (enrollment and
// relaxed TLS modes); when one is presented it must pass agents.Verify for
// clientAuth or the handshake fails.
func ServerTLSConfig(certificate func() (*tls.Certificate, error), agents *AgentVerifier) (*tls.Config, error) {
	if certificate == nil {
		return nil, errors.New("link: certificate getter is required")
	}
	if agents == nil || agents.AgentCA == nil {
		return nil, errors.New("link: agent verifier is required")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := certificate()
			if err != nil {
				return nil, fmt.Errorf("link: server certificate: %w", err)
			}
			if c == nil {
				return nil, errors.New("link: no server certificate")
			}
			return c, nil
		},
		ClientAuth: tls.RequestClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return nil
			}
			if _, err := agents.Verify(cs.PeerCertificates, x509.ExtKeyUsageClientAuth); err != nil {
				return fmt.Errorf("link: client certificate: %w", err)
			}
			return nil
		},
	}, nil
}

// peer is the connection identity stored in the request context.
type peer struct {
	agentID    string
	unenrolled bool
	reverse    bool
	// certErr is why the client certificate failed the per-request check
	// of a request passed on by DeferringMiddleware.
	certErr error
}

type peerKey struct{}

func withPeer(ctx context.Context, p peer) context.Context {
	return context.WithValue(ctx, peerKey{}, p)
}

func peerFrom(ctx context.Context) (peer, bool) {
	p, ok := ctx.Value(peerKey{}).(peer)
	return p, ok
}

// PeerAgentID returns the agent id proven by the TLS peer certificate of
// the connection the request arrived on: the client certificate in connect
// mode (set by Middleware) or the listener certificate in listen mode (set
// by DialReverse).
func PeerAgentID(ctx context.Context) (id string, ok bool) {
	p, found := peerFrom(ctx)
	if !found || p.agentID == "" {
		return "", false
	}
	return p.agentID, true
}

// PeerUnenrolled reports whether the request arrived on a reverse
// connection to an agent that presented a temporary certificate. Such a
// connection may only be used for enrollment.
func PeerUnenrolled(ctx context.Context) bool {
	p, _ := peerFrom(ctx)
	return p.unenrolled
}

// PeerReverse reports whether the request arrived on a listen-mode
// connection the server dialed.
func PeerReverse(ctx context.Context) bool {
	p, _ := peerFrom(ctx)
	return p.reverse
}

// PeerCertError returns why the client certificate of the request failed
// the per-request check, for a request DeferringMiddleware passed on instead
// of answering it. The error matches ErrRevoked for a blocked serial and
// ErrRevocationCheck when the revocation state could not be determined; any
// other error means the chain does not verify. Such a request has no
// PeerAgentID and must be rejected by the handler.
func PeerCertError(ctx context.Context) error {
	p, _ := peerFrom(ctx)
	return p.certErr
}

// Middleware exposes the agent id of a connect-mode client certificate
// through PeerAgentID. The chain is verified again for every request, so a
// revocation also applies to connections that are already open; a request
// whose certificate no longer verifies gets a plain 403. Requests without a
// client certificate pass without an id. Requests served by DialReverse
// already carry their identity and pass unchanged, so one handler stack can
// serve both directions.
func (v *AgentVerifier) Middleware(next http.Handler) http.Handler {
	return v.DeferringMiddleware(nil, next)
}

// DeferringMiddleware is Middleware, except that a request whose
// certificate fails the per-request check and for which deferred returns
// true is not answered here: it is passed to next without an agent id and
// with the failure available through PeerCertError, so that next can answer
// in its own (signed) error format. next must reject such a request.
func (v *AgentVerifier) DeferringMiddleware(deferred func(*http.Request) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := peerFrom(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		id, err := v.Verify(r.TLS.PeerCertificates, x509.ExtKeyUsageClientAuth)
		if err != nil {
			if deferred != nil && deferred(r) {
				next.ServeHTTP(w, r.WithContext(withPeer(r.Context(), peer{certErr: err})))
				return
			}
			http.Error(w, "client certificate rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withPeer(r.Context(), peer{agentID: id})))
	})
}
