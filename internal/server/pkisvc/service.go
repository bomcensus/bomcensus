// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package pkisvc owns the certificates and CAs of the server: the Web/API
// TLS certificate, the Agent TLS certificates and trust anchors, and the
// Agent CA that issues agent certificates.
//
// All material lives in the database (store.PKI) with private keys sealed by
// the master key, so every replica serves the same certificates. Each replica
// keeps an in-memory snapshot that it reloads periodically (Run) and after
// every change it makes itself; changes made by another replica are picked
// up within the refresh interval.
//
// Objects (names in package store, plus the staged ones below):
//
//	agent-ca                  Agent CA (always)
//	web-ca, web-leaf          Web/API TLS internal CA and certificate
//	agent-tls-ca              Agent TLS internal CA (automatic mode)
//	agent-tls-anchor          the current Agent TLS trust anchor (certificate only)
//	agent-tls-leaf            Agent TLS server certificate; its key signs enrollment and messages
//	agent-tls-client          client certificate presented to listen-mode agents
//	agent-tls-anchor-pending  a prepared next anchor; with a key when it is a new internal CA
//	agent-tls-leaf-pending, agent-tls-client-pending
//	                          manual certificates under the prepared anchor, used on activation
package pkisvc

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Object names in addition to those defined by package store.
const (
	ObjAgentTLSAnchor        = "agent-tls-anchor"
	ObjAgentTLSLeafPending   = "agent-tls-leaf-pending"
	ObjAgentTLSClientPending = "agent-tls-client-pending"
)

// Defaults for Config.
const (
	DefaultRefreshInterval   = 30 * time.Second
	DefaultAgentCertLifetime = 90 * 24 * time.Hour
)

// backdate is subtracted from NotBefore of everything the service issues to
// tolerate clock skew between the server and its peers.
const backdate = 5 * time.Minute

// Errors returned by the service. Validation failures wrap ErrInvalid.
var (
	ErrInvalid         = errors.New("pkisvc: invalid input")
	ErrAnchorMismatch  = errors.New("pkisvc: certificate does not chain to the Agent TLS trust anchor")
	ErrAgentsNotSynced = errors.New("pkisvc: agents have not synchronized the trust bundle")
	ErrAnchorPending   = errors.New("pkisvc: an anchor change is already prepared")
	ErrNoPendingAnchor = errors.New("pkisvc: no anchor change is prepared")
	ErrNotStaged       = errors.New("pkisvc: no certificate under the prepared anchor has been uploaded")
	ErrWebTLSOff       = errors.New("pkisvc: Web/API TLS is off")
	ErrNotReady        = errors.New("pkisvc: certificates are not loaded")
)

// Store is what the service needs from the database.
type Store interface {
	store.PKI
	store.AgentCerts
	WithTx(ctx context.Context, fn func(store.Store) error) error
}

// Config configures a Service.
type Config struct {
	Store Store
	Box   *secret.Box
	// WebTLS is false when the server does not terminate Web/API TLS
	// (BOMCENSUS_WEB_TLS=off). No web material is managed then.
	WebTLS bool
	// WebServerNames are the SANs of the automatic web certificate
	// (BOMCENSUS_WEB_SERVER_NAMES). Default: localhost.
	WebServerNames []string
	// AgentServerNames are the SANs of the automatic Agent TLS certificates
	// (BOMCENSUS_AGENT_SERVER_NAMES). Default: localhost.
	AgentServerNames []string
	// UnsyncedAgents returns the number of non-revoked agents whose trust
	// bundle version is below the current one. Required for anchor changes.
	UnsyncedAgents func(ctx context.Context) (int, error)
	// RefreshInterval is how often Run reloads the snapshot, renews leaves
	// and refreshes the revocation cache. Default DefaultRefreshInterval.
	RefreshInterval time.Duration
	// LeafLifetime of automatic TLS certificates. Default
	// pki.DefaultLeafLifetime. Leaves are renewed after two thirds.
	LeafLifetime time.Duration
	// CALifetime of internal CAs. Default pki.DefaultCALifetime.
	CALifetime time.Duration
	// AgentCertLifetime of agent certificates. Default
	// DefaultAgentCertLifetime.
	AgentCertLifetime time.Duration
	Logger            *slog.Logger
	// Now is the clock. Default time.Now.
	Now func() time.Time
}

// Service manages the server PKI. Create it with New, call Bootstrap once
// at start and keep Run going.
type Service struct {
	cfg  Config
	st   Store
	box  *secret.Box
	log  *slog.Logger
	now  func() time.Time
	snap atomic.Pointer[snapshot]

	// refreshMu serializes snapshot loads so an older load cannot replace a
	// newer one.
	refreshMu sync.Mutex

	rev revocationCache
}

// New validates cfg and returns a Service. It does not touch the database.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Box == nil {
		return nil, errors.New("pkisvc: store and secret box are required")
	}
	if len(cfg.WebServerNames) == 0 {
		cfg.WebServerNames = []string{"localhost"}
	}
	if len(cfg.AgentServerNames) == 0 {
		cfg.AgentServerNames = []string{"localhost"}
	}
	for _, list := range [][]string{cfg.WebServerNames, cfg.AgentServerNames} {
		for _, n := range list {
			if n == "" || strings.ContainsAny(n, " \t\r\n,") {
				return nil, fmt.Errorf("pkisvc: invalid server name %q", n)
			}
		}
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}
	if cfg.LeafLifetime <= 0 {
		cfg.LeafLifetime = pki.DefaultLeafLifetime
	}
	if cfg.CALifetime <= 0 {
		cfg.CALifetime = pki.DefaultCALifetime
	}
	if cfg.AgentCertLifetime <= 0 {
		cfg.AgentCertLifetime = DefaultAgentCertLifetime
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Service{cfg: cfg, st: cfg.Store, box: cfg.Box, log: cfg.Logger, now: cfg.Now}
	s.rev = newRevocationCache()
	return s, nil
}

// snapshot is one consistent view of the material, loaded from the store.
type snapshot struct {
	bundleVersion int64
	webMode       store.TLSMode
	agentMode     store.TLSMode

	web         *tls.Certificate
	webChain    []*x509.Certificate
	agentServer *tls.Certificate
	agentChain  []*x509.Certificate
	agentKey    crypto.Signer
	agentClient *tls.Certificate
	clientChain []*x509.Certificate

	anchor  *x509.Certificate
	pending *object
	agentCA *pki.CA
}

func (s *Service) current() (*snapshot, error) {
	sn := s.snap.Load()
	if sn == nil {
		return nil, ErrNotReady
	}
	return sn, nil
}

// Refresh reloads the snapshot from the store.
func (s *Service) Refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	// The bundle version is read before the objects: a bundle may then carry
	// newer anchors than its version promises, never older ones.
	version, err := s.st.TrustBundleVersion(ctx)
	if err != nil {
		return err
	}
	webSet, err := s.st.GetTLSSetting(ctx, store.TLSEndpointWeb)
	if err != nil {
		return err
	}
	agentSet, err := s.st.GetTLSSetting(ctx, store.TLSEndpointAgent)
	if err != nil {
		return err
	}
	raw, err := s.st.ListPKIObjects(ctx)
	if err != nil {
		return err
	}
	objs := make(map[string]*object, len(raw))
	for _, r := range raw {
		o, err := s.decode(r)
		if err != nil {
			return err
		}
		objs[r.Name] = o
	}

	sn := &snapshot{bundleVersion: version, webMode: webSet.Mode, agentMode: agentSet.Mode}
	ca := objs[store.PKIAgentCA]
	if ca == nil || ca.key == nil {
		return fmt.Errorf("pkisvc: %s is missing", store.PKIAgentCA)
	}
	if sn.agentCA, err = pki.LoadCA(ca.chain[0], ca.key); err != nil {
		return fmt.Errorf("pkisvc: %s: %w", store.PKIAgentCA, err)
	}
	anchor := objs[ObjAgentTLSAnchor]
	if anchor == nil {
		return fmt.Errorf("pkisvc: %s is missing", ObjAgentTLSAnchor)
	}
	sn.anchor = anchor.chain[0]
	leaf := objs[store.PKIAgentTLSLeaf]
	if leaf == nil || leaf.key == nil {
		return fmt.Errorf("pkisvc: %s is missing", store.PKIAgentTLSLeaf)
	}
	c := pki.TLSCertificate(leaf.chain, leaf.key)
	sn.agentServer, sn.agentChain, sn.agentKey = &c, leaf.chain, leaf.key
	if cl := objs[store.PKIAgentTLSClient]; cl != nil && cl.key != nil {
		c := pki.TLSCertificate(cl.chain, cl.key)
		sn.agentClient, sn.clientChain = &c, cl.chain
	}
	if s.cfg.WebTLS {
		if w := objs[store.PKIWebLeaf]; w != nil && w.key != nil {
			c := pki.TLSCertificate(w.chain, w.key)
			sn.web, sn.webChain = &c, w.chain
		}
	}
	sn.pending = objs[store.PKIAgentTLSAnchorPending]
	s.snap.Store(sn)
	return nil
}

// Run refreshes the snapshot, renews automatic leaves and refreshes the
// revocation cache every RefreshInterval until ctx ends. Errors are logged.
func (s *Service) Run(ctx context.Context) error {
	t := time.NewTicker(s.cfg.RefreshInterval)
	defer t.Stop()
	s.refreshRevocations(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		if err := s.Maintain(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("pki maintenance failed", "err", err)
		}
		s.refreshRevocations(ctx)
	}
}

// Maintain renews automatic leaves that are due and reloads the snapshot.
// Run calls it periodically.
func (s *Service) Maintain(ctx context.Context) error {
	var errs []error
	if s.cfg.WebTLS {
		errs = append(errs, s.ensureAutoLeaf(ctx, store.TLSEndpointWeb, store.PKIWebLeaf, store.PKIWebCA, x509.ExtKeyUsageServerAuth, s.cfg.WebServerNames))
	}
	errs = append(errs,
		s.ensureAutoLeaf(ctx, store.TLSEndpointAgent, store.PKIAgentTLSLeaf, store.PKIAgentTLSCA, x509.ExtKeyUsageServerAuth, s.cfg.AgentServerNames),
		s.ensureAutoLeaf(ctx, store.TLSEndpointAgent, store.PKIAgentTLSClient, store.PKIAgentTLSCA, x509.ExtKeyUsageClientAuth, s.cfg.AgentServerNames),
		s.Refresh(ctx))
	s.warnManualExpiry()
	return errors.Join(errs...)
}

func (s *Service) warnManualExpiry() {
	sn := s.snap.Load()
	if sn == nil {
		return
	}
	now := s.now()
	check := func(endpoint string, mode store.TLSMode, chain []*x509.Certificate) {
		if mode != store.TLSModeManual || len(chain) == 0 {
			return
		}
		if left := chain[0].NotAfter.Sub(now); left < 30*24*time.Hour {
			s.log.Warn("manual TLS certificate expires soon", "endpoint", endpoint, "expires_at", chain[0].NotAfter)
		}
	}
	check("web", sn.webMode, sn.webChain)
	check("agent", sn.agentMode, sn.agentChain)
	check("agent-client", sn.agentMode, sn.clientChain)
}

// WebCertificate returns the Web/API TLS certificate.
func (s *Service) WebCertificate() (*tls.Certificate, error) {
	if !s.cfg.WebTLS {
		return nil, ErrWebTLSOff
	}
	sn, err := s.current()
	if err != nil {
		return nil, err
	}
	if sn.web == nil {
		return nil, fmt.Errorf("pkisvc: no web certificate: %w", ErrNotReady)
	}
	return sn.web, nil
}

// AgentServerCertificate returns the certificate of the agent listener.
func (s *Service) AgentServerCertificate() (*tls.Certificate, error) {
	sn, err := s.current()
	if err != nil {
		return nil, err
	}
	return sn.agentServer, nil
}

// AgentClientCertificate returns the client certificate the server presents
// when it dials a listen-mode agent.
func (s *Service) AgentClientCertificate() (*tls.Certificate, error) {
	sn, err := s.current()
	if err != nil {
		return nil, err
	}
	if sn.agentClient == nil {
		return nil, fmt.Errorf("pkisvc: no agent client certificate: %w", ErrNotReady)
	}
	return sn.agentClient, nil
}

// Signer returns the key the server signs enrollment exchanges and messages
// with, and its certificate chain (leaf first). It is the Agent TLS server
// certificate. Both are nil before the first successful Refresh.
func (s *Service) Signer() (crypto.Signer, []*x509.Certificate) {
	sn := s.snap.Load()
	if sn == nil {
		return nil, nil
	}
	return sn.agentKey, sn.agentChain
}

// AnchorHash returns the SPKI hash of the current Agent TLS trust anchor, the
// ca-hash of new enrollment strings.
func (s *Service) AnchorHash() ([32]byte, error) {
	sn, err := s.current()
	if err != nil {
		return [32]byte{}, err
	}
	return pki.SPKIHash(sn.anchor), nil
}

// AgentCA returns the Agent CA certificate.
func (s *Service) AgentCA() (*x509.Certificate, error) {
	sn, err := s.current()
	if err != nil {
		return nil, err
	}
	return sn.agentCA.Cert, nil
}

// TrustBundle returns what agents trust: the current anchor, a prepared
// anchor if any, and the Agent CA, with the store's bundle version.
func (s *Service) TrustBundle() (*pki.TrustBundle, error) {
	sn, err := s.current()
	if err != nil {
		return nil, err
	}
	b := &pki.TrustBundle{Version: uint64(sn.bundleVersion), Anchors: []*x509.Certificate{sn.anchor}, AgentCA: sn.agentCA.Cert}
	if sn.pending != nil {
		b.Anchors = append(b.Anchors, sn.pending.chain[0])
	}
	return b, nil
}

// splitNames separates IP addresses from DNS names.
func splitNames(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

// certNames returns the SANs of a certificate as strings.
func certNames(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}
