// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentproto

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
)

// Channel is the agent end of a channel, opened for one run of an agent or
// scanner.
type Channel interface {
	API
	// Reset drops open connections so that the next call authenticates
	// again with the current certificate (after a renewal or a revocation
	// answer). Channels without such state do nothing.
	Reset()
	// Close ends the channel.
	Close() error
}

// PeerObserving is implemented by channels that see the server's
// certificate. The agent reports the last one to the server, which detects
// TLS termination in transit with it.
type PeerObserving interface {
	// ObservedServer returns the SHA-256 fingerprint and the leaf of the
	// last server certificate seen and, when the chain carried it, the
	// certificate that signed the leaf. ok is false before the first
	// connection.
	ObservedServer() (fingerprint [32]byte, leaf, issuer *x509.Certificate, ok bool)
}

// ServerVerifier verifies the certificate chain (leaf first) the server
// presented: against the pinned anchor of the enrollment string until the
// agent has a trust bundle, against the bundle's anchors afterwards. usage
// is serverAuth when the server is the TLS server and clientAuth when it
// presents its client certificate (listen mode).
type ServerVerifier func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error

// Identity is what the agent authenticates with.
type Identity struct {
	// AgentID is the id assigned at enrollment.
	AgentID string
	// Key is the identity key.
	Key ed25519.PrivateKey
}

// CounterSource provides the agent's monotonic request counter.
type CounterSource interface {
	// Next returns a value greater than every value returned before and
	// greater than every value passed to Observe. It is persisted before
	// it is returned.
	Next(ctx context.Context) (uint64, error)
	// Observe records the last counter the server accepted, taken from an
	// authenticated answer.
	Observe(ctx context.Context, last uint64) error
}

// ServerKeys resolves the key id of a server signature to the server's
// public key, verified against the agent's trust anchors.
type ServerKeys interface {
	ServerKey(ctx context.Context, keyID string) (crypto.PublicKey, error)
}

// ChannelParams describe the connection an agent makes, from its
// enrollment and current state.
type ChannelParams struct {
	// Name is the channel name chosen at enrollment.
	Name string
	// ServerURL is the server address given at enrollment.
	ServerURL string
	// ServerName is the name the server certificates are issued for.
	ServerName string
	// ListenAddress is where a listening channel listens.
	ListenAddress string
	// Settings are the channel settings given at enrollment
	// (bomcensus-agent enroll --channel-setting key=value).
	Settings map[string]string
	// TLSMode is the server verification mode of the HTTP channel
	// ("pinned", "system", "none").
	TLSMode string
	// VerifyServer verifies server certificates; channels that see one
	// call it on every handshake.
	VerifyServer ServerVerifier
	// ExtraRoots are trusted in addition to the OS store in "system" mode.
	ExtraRoots []*x509.Certificate
	// ClientCertificate returns the agent certificate to authenticate with,
	// or (nil, nil) before there is one or while the agent must not
	// present it. It is called for every handshake.
	ClientCertificate func() (*tls.Certificate, error)
	// ListenerCertificate returns the certificate of a listening channel:
	// a temporary one before enrollment, the agent certificate afterwards.
	ListenerCertificate func() (*tls.Certificate, error)
	// OnListening is called with the bound address of a listening channel.
	OnListening func(net.Addr)

	// Identity returns the identity to authenticate a call with; the zero
	// Identity before enrollment. It is called for every call, with the
	// call's context.
	Identity func(ctx context.Context) Identity
	// Counter supplies the counters of state-changing calls.
	Counter CounterSource
	// ServerKeys resolves the keys of server signatures.
	ServerKeys ServerKeys

	Logger *slog.Logger
}

// ChannelFactory opens the agent end of a channel.
type ChannelFactory func(ctx context.Context, p ChannelParams) (Channel, error)
