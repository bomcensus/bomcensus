// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/internal/agent/httpchannel"
	"github.com/bomcensus/bomcensus/internal/msgsig"
	"github.com/bomcensus/bomcensus/internal/pki"
)

// BasePath is the path prefix of the agent protocol on the HTTP channel.
const BasePath = httpchannel.BasePath

// Connection modes. They are also the names of the HTTP channel's two
// channels; other channels are registered in Options.Channels.
const (
	ModeConnect = httpchannel.NameConnect
	ModeListen  = httpchannel.NameListen
)

// serverVerifier verifies server chains against the trust bundle anchors
// when there is a bundle and against the enrollment pin before that.
func serverVerifier(pin [32]byte, serverName string, bundle func() *pki.TrustBundle) agentproto.ServerVerifier {
	return func(chain []*x509.Certificate, usage x509.ExtKeyUsage) error {
		if b := bundle(); b != nil {
			return pki.VerifyAnchors(chain, b.Anchors, serverName, usage)
		}
		return pki.VerifyPinned(chain, pin, serverName, usage)
	}
}

// NormalizeServerURL checks an https server address and strips a trailing
// slash and the protocol base path.
func NormalizeServerURL(s string) (string, error) { return httpchannel.NormalizeServerURL(s) }

// channelName is the channel of an enrollment: the registered channel it
// was made with, or the HTTP channel of its connect mode.
func channelName(channel, connectMode string) string {
	if channel != "" {
		return channel
	}
	if connectMode == "" {
		return ModeConnect
	}
	return connectMode
}

// factory returns the channel factory registered under name.
func (o *Options) factory(name string) (agentproto.ChannelFactory, error) {
	if f, ok := o.Channels[name]; ok && f != nil {
		return f, nil
	}
	if name == ModeConnect || name == ModeListen {
		return httpchannel.Factory(httpchannel.Options{Connect: o.Connect, Now: o.Now}), nil
	}
	return nil, fmt.Errorf("unknown channel %q (not registered in this build)", name)
}

// builtinChannel reports whether name is one of the HTTP channel's modes,
// which keep their own server address rules.
func builtinChannel(name string, o *Options) bool {
	if _, custom := o.Channels[name]; custom {
		return false
	}
	return name == ModeConnect || name == ModeListen
}

// channelOwner is the runtime a channel authenticates calls for. The
// connection callbacks (certificates, server verification) stay with the
// runtime that opened the channel; the identity, the counter and the server
// keys are those of the runtime it is attached to. A channel opened for
// enrollment passes to the runtime that waits for approval.
type channelOwner struct{ r atomic.Pointer[Runtime] }

func (o *channelOwner) identity(ctx context.Context) agentproto.Identity {
	if r := o.r.Load(); r != nil {
		return r.channelIdentity(ctx)
	}
	return agentproto.Identity{}
}

var errNotAttached = errors.New("channel is not attached to an enrolled runtime")

// Next implements agentproto.CounterSource.
func (o *channelOwner) Next(ctx context.Context) (uint64, error) {
	r := o.r.Load()
	if r == nil || r.counter == nil {
		return 0, errNotAttached
	}
	return r.counter.Next(ctx)
}

// Observe implements agentproto.CounterSource.
func (o *channelOwner) Observe(ctx context.Context, last uint64) error {
	r := o.r.Load()
	if r == nil || r.counter == nil {
		return errNotAttached
	}
	return r.counter.Observe(ctx, last)
}

// ServerKey implements agentproto.ServerKeys.
func (o *channelOwner) ServerKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	r := o.r.Load()
	if r == nil || r.keys == nil {
		return nil, errNotAttached
	}
	return r.keys.ServerKey(ctx, keyID)
}

// openChannel opens the channel of the runtime's enrollment.
func (r *Runtime) openChannel(ctx context.Context) (agentproto.Channel, *channelOwner, error) {
	r.mu.RLock()
	enr := r.enr
	extra := r.extra
	r.mu.RUnlock()
	name := channelName(enr.Channel, enr.ConnectMode)
	f, err := r.opts.factory(name)
	if err != nil {
		return nil, nil, err
	}
	owner := &channelOwner{}
	p := agentproto.ChannelParams{
		Name:                name,
		ServerURL:           enr.ServerURL,
		ServerName:          enr.ServerName,
		ListenAddress:       enr.ListenAddress,
		Settings:            enr.ChannelSettings,
		TLSMode:             enr.TLSMode,
		VerifyServer:        serverVerifier(r.pin, enr.ServerName, r.currentBundle),
		ExtraRoots:          extra,
		ClientCertificate:   r.clientCert,
		ListenerCertificate: r.listenerCert,
		OnListening:         r.opts.OnListening,
		Identity:            owner.identity,
		Counter:             owner,
		ServerKeys:          owner,
		Logger:              r.log,
	}
	ch, err := f(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	return ch, owner, nil
}

// serverNameOf returns the host of a server URL, for the default server
// name of a channel.
func serverNameOf(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
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

// ServerKey implements agentproto.ServerKeys.
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

// fetchServerChain asks the channel for the unauthenticated server chain.
func fetchServerChain(ctx context.Context, api agentproto.API) ([]*x509.Certificate, error) {
	sc, err := api.GetServerChain(ctx)
	if err != nil {
		return nil, err
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

// IsStatus reports whether err is an answer of the server with the given
// status. Channels only return answers they authenticated.
func IsStatus(err error, status int) bool { return agentproto.IsStatus(err, status) }
