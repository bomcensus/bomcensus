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
	"errors"
	"log/slog"
	"net/netip"
)

// Gateway is the server end of a channel. Run accepts connections (or
// makes them) until ctx is done and passes every operation to s.API.
type Gateway interface {
	Run(ctx context.Context, s *Server) error
}

// Server is what a gateway gets from the server.
type Server struct {
	// API serves the operations. A gateway authenticates the caller, then
	// calls it with a context carrying the agent (WithAgent) and the
	// connection facts (WithPeer).
	API API
	// Agents is what a gateway needs to authenticate agents.
	Agents Agents
	Logger *slog.Logger
}

// Agents is the server's knowledge of enrolled agents and its own signing
// key, for gateways that authenticate requests and responses.
type Agents interface {
	// AgentKey returns the identity key and state of an agent, or an error
	// matching ErrUnknownAgent.
	AgentKey(ctx context.Context, agentID string) (AgentKey, error)
	// AdvanceCounter stores n as the agent's request counter if it is
	// greater than the stored value. It returns the stored value after the
	// call and whether n was accepted.
	AdvanceCounter(ctx context.Context, agentID string, n uint64) (current uint64, ok bool, err error)
	// SigningKey returns the server's response signing key and its
	// certificate chain, leaf first: the chain GetServerChain returns and
	// agents verify against their trust anchors.
	SigningKey(ctx context.Context) (crypto.Signer, []*x509.Certificate, error)
	// ServerCertificate returns the Agent TLS server certificate with its
	// chain, which agents verify against the anchor of their enrollment
	// (ChannelParams.VerifyServer), for gateways that serve TLS.
	ServerCertificate() (*tls.Certificate, error)
	// VerifyCertificate verifies an agent certificate chain (leaf first)
	// for client authentication against the Agent CA and the revocation
	// list, and returns its agent id.
	VerifyCertificate(chain []*x509.Certificate) (agentID string, err error)
}

// ErrUnknownAgent is returned by Agents.AgentKey for an agent id that does
// not exist.
var ErrUnknownAgent = errors.New("agentproto: unknown agent")

// State is the enrollment state of an agent.
type State int

// Agent states.
const (
	StateApproved State = iota + 1
	StatePending
	StateRevoked
)

func (s State) String() string {
	switch s {
	case StateApproved:
		return "approved"
	case StatePending:
		return "pending"
	case StateRevoked:
		return "revoked"
	}
	return "invalid"
}

// AgentKey is what the server knows about an agent's identity.
type AgentKey struct {
	// PublicKey is the agent's Ed25519 identity key.
	PublicKey ed25519.PublicKey
	State     State
	// RequireCertificate is set for agents that hold a valid certificate
	// and whose Register Key does not allow relaxed TLS: their requests
	// must arrive on a connection authenticated with that certificate.
	RequireCertificate bool
}

// Peer is what a gateway knows about the connection of a request.
type Peer struct {
	// RemoteAddr is the agent's address, if the channel can vouch for it.
	// Register Key address limits refuse an unknown (invalid) address.
	RemoteAddr netip.Addr
	// Reverse marks a connection the server made to the agent.
	Reverse bool
}

type ctxKey int

const (
	peerKey ctxKey = iota
	agentKey
)

// WithPeer returns ctx carrying the connection facts of a request.
func WithPeer(ctx context.Context, p Peer) context.Context {
	return context.WithValue(ctx, peerKey, p)
}

// PeerFrom returns the connection facts of a request.
func PeerFrom(ctx context.Context) Peer {
	p, _ := ctx.Value(peerKey).(Peer)
	return p
}

// WithAgent returns ctx carrying the id of the agent the gateway
// authenticated the request as.
func WithAgent(ctx context.Context, agentID string) context.Context {
	return context.WithValue(ctx, agentKey, agentID)
}

// AgentFrom returns the authenticated agent id of a request.
func AgentFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(agentKey).(string)
	return id, ok && id != ""
}
