// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package link is the transport between agents and the server. It builds
// the TLS configurations of both sides, the connect-mode HTTP transport and
// the listen-mode reverse connection (SECURITY §4.5), where the server dials
// the agent and the HTTP roles are swapped after the TLS handshake.
//
// The package knows TLS and connections only. Callers plug in http.Handlers
// and get http.RoundTrippers; paths, message signatures and enrollment are
// handled elsewhere.
package link

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/bomcensus/bomcensus/internal/pki"
)

// ALPNReverse is the only ALPN protocol of a listen-mode connection.
const ALPNReverse = "bomcensus-reverse/1"

// TLSMode is the agent's verification mode for the server certificate in
// connect mode (SECURITY §4.7).
type TLSMode string

const (
	// TLSPinned verifies the server against the pinned anchor or the trust
	// bundle and presents the agent certificate.
	TLSPinned TLSMode = "pinned"
	// TLSSystem verifies the server against the OS trust store plus
	// configured CAs and presents no client certificate.
	TLSSystem TLSMode = "system"
	// TLSNone does not verify the server and presents no client
	// certificate.
	TLSNone TLSMode = "none"
)

// ParseTLSMode parses a mode name. The empty string is TLSPinned.
func ParseTLSMode(s string) (TLSMode, error) {
	switch TLSMode(s) {
	case "", TLSPinned:
		return TLSPinned, nil
	case TLSSystem, TLSNone:
		return TLSMode(s), nil
	}
	return "", fmt.Errorf("link: unknown TLS mode %q", s)
}

// ServerVerifier verifies the certificate chain (leaf first) the bomcensus
// server presented. usage is serverAuth in connect mode, where the server
// is the TLS server, and clientAuth in listen mode, where the server
// presents its Agent TLS client certificate.
type ServerVerifier func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error

// PinnedVerifier verifies against the ca-hash of the enrollment string
// (pki.VerifyPinned). It is used until the agent has a trust bundle.
func PinnedVerifier(pin [32]byte, serverName string) ServerVerifier {
	return func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error {
		return pki.VerifyPinned(chain, pin, serverName, usage)
	}
}

// AnchorVerifier verifies against the Agent TLS anchors returned by
// anchors at the time of each handshake (pki.VerifyAnchors), so trust
// bundle updates apply to new connections without rebuilding anything.
func AnchorVerifier(anchors func() []*x509.Certificate, serverName string) ServerVerifier {
	return func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error {
		if anchors == nil {
			return errors.New("link: no trust anchors")
		}
		return pki.VerifyAnchors(chain, anchors(), serverName, usage)
	}
}

// PeerObserver is called after every successful handshake with the SHA-256
// fingerprint (pki.Fingerprint) and the leaf certificate the server
// presented. The agent reports the fingerprint so the server can detect
// TLS termination in transit.
type PeerObserver func(fingerprint [32]byte, leaf *x509.Certificate)

// ObservedPeer keeps the last observed server certificate. Its Observe
// method is a PeerObserver. The zero value is ready to use.
type ObservedPeer struct {
	mu   sync.Mutex
	fp   [32]byte
	leaf *x509.Certificate
}

// Observe records a handshake.
func (o *ObservedPeer) Observe(fingerprint [32]byte, leaf *x509.Certificate) {
	o.mu.Lock()
	o.fp, o.leaf = fingerprint, leaf
	o.mu.Unlock()
}

// Last returns the last observed fingerprint and leaf. ok is false before
// the first handshake.
func (o *ObservedPeer) Last() (fingerprint [32]byte, leaf *x509.Certificate, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.fp, o.leaf, o.leaf != nil
}

func observe(obs PeerObserver, chain []*x509.Certificate) {
	if obs != nil && len(chain) > 0 {
		obs(pki.Fingerprint(chain[0]), chain[0])
	}
}
