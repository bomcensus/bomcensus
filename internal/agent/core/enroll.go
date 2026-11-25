// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package core

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/enroll"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/token"
)

// ErrAlreadyEnrolled is returned by Enroll for a state directory that holds
// an approved enrollment.
var ErrAlreadyEnrolled = errors.New("already enrolled")

// EnrollOptions configures Enroll.
type EnrollOptions struct {
	State   *state.Dir
	Kind    Kind
	Version string
	// Token is the enrollment string. Its secret is used for one
	// signature and is never stored or logged.
	Token string
	// ServerURL is the server address in connect mode (https://HOST:PORT).
	ServerURL string
	// ServerName is the name the server certificates must carry. It
	// defaults to the host of ServerURL and is required in listen mode.
	ServerName string
	// ConnectMode is ModeConnect (default) or ModeListen.
	ConnectMode string
	// Channel is a channel registered in Runtime.Channels; empty is the
	// HTTP channel of ConnectMode. ServerURL and ServerName are then
	// passed to the channel as given.
	Channel string
	// ChannelSettings are passed to Channel.
	ChannelSettings map[string]string
	// ListenAddress is the listen-mode address, for example ":7443".
	ListenAddress string
	// TLSMode is the connect-mode verification of the TLS server
	// certificate (default pinned).
	TLSMode link.TLSMode
	// ExtraRoots are trusted besides the OS store in the system mode.
	ExtraRoots []*x509.Certificate
	// Host describes the host in the enrollment request.
	Host dto.HostFacts
	// HostFunc, when set, replaces Host. It is called only for a new
	// enrollment, not when one is resumed or already approved.
	HostFunc func(context.Context) (dto.HostFacts, error)
	// HPKEPublicKey is the scanner's encryption public key.
	HPKEPublicKey []byte

	Logger      *slog.Logger
	OnListening func(net.Addr)
	// Runtime tunes waiting for approval; its State, Kind, Version and
	// Logger are taken from these options.
	Runtime Options
}

// Enroll performs the enrollment exchange (SECURITY §4.3, PROTOCOL §2),
// stores identity, trust bundle and enrollment parameters and, when the
// server holds the enrollment for approval, keeps asking until it is
// approved or ctx ends. An interrupted pending enrollment is resumed by
// Enroll or by Runtime.Run.
func Enroll(ctx context.Context, o EnrollOptions) (*state.Enrollment, error) {
	if o.State == nil {
		return nil, errors.New("enroll: state directory is required")
	}
	if o.Kind == "" {
		o.Kind = KindAgent
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	ropts := o.Runtime
	ropts.State, ropts.Kind, ropts.Version, ropts.Logger = o.State, o.Kind, o.Version, o.Logger
	if ropts.OnListening == nil {
		ropts.OnListening = o.OnListening
	}

	switch existing, err := o.State.LoadEnrollment(); {
	case err == nil && existing.Status == state.StatusApproved:
		return nil, ErrAlreadyEnrolled
	case err == nil:
		o.Logger.Info("resuming pending enrollment", "agent_id", existing.AgentID)
		return resumePending(ctx, ropts)
	case !errors.Is(err, state.ErrNotEnrolled):
		return nil, err
	}

	tok, err := token.Parse(o.Token)
	if err != nil {
		return nil, err
	}
	if o.HostFunc != nil {
		if o.Host, err = o.HostFunc(ctx); err != nil {
			return nil, err
		}
	}
	registerKey := tok.PrivateKey()
	defer func() {
		clear(tok.Secret[:])
		clear(registerKey)
	}()
	enr, err := enrollmentParams(o, tok.CAHash)
	if err != nil {
		return nil, err
	}
	o.Logger.Info("enrolling", "token", tok, "server_name", enr.ServerName, "connect_mode", enr.ConnectMode, "tls_mode", enr.TLSMode)

	key, err := pki.GenerateAgentKey()
	if err != nil {
		return nil, err
	}
	csr, err := pki.CreateAgentCSR(key)
	if err != nil {
		return nil, err
	}

	// A bare runtime provides the connection parameters and, in listen
	// mode, the temporary listener certificate.
	r := &Runtime{opts: ropts, log: o.Logger, st: o.State, pin: tok.CAHash, enr: *enr, extra: o.ExtraRoots,
		handlers: map[string]DirectiveHandler{}, seen: map[string]struct{}{}}
	r.opts.defaults()
	r.ident = &state.Identity{Key: key}
	ch, owner, err := r.openChannel(ctx)
	if err != nil {
		return nil, err
	}
	defer ch.Close()

	startBody, err := json.Marshal(dto.EnrollStartRequest{
		KeyId:         tok.KeyID.String(),
		AgentNonce:    randomBytes(32),
		Csr:           csr,
		Kind:          dto.AgentKind(o.Kind),
		Version:       o.Version,
		Host:          o.Host,
		ConnectMode:   dto.ConnectMode(enr.ConnectMode),
		ListenAddress: optional(enr.ListenAddress),
		TlsMode:       dto.TlsMode(enr.TLSMode),
		HpkePublicKey: optionalBytes(o.HPKEPublicKey),
	})
	if err != nil {
		return nil, err
	}
	startMsg, err := ch.EnrollStart(ctx, startBody)
	if err != nil {
		return nil, fmt.Errorf("enroll start: %w", err)
	}
	startResp := startMsg.Body
	var sess dto.EnrollSession
	if err := json.Unmarshal(startResp, &sess); err != nil {
		return nil, fmt.Errorf("enroll start: decode: %w", err)
	}
	chain, err := pki.ParseChain(sess.ServerChain)
	if err != nil {
		return nil, fmt.Errorf("enroll start: %w", err)
	}
	tr := enroll.NewTranscript(startBody, startResp)
	leaf, err := enroll.VerifyServerStart(chain, tok.CAHash, enr.ServerName, tr, startMsg.Signature)
	if err != nil {
		return nil, err
	}

	agentSig, err := enroll.SignAgent(registerKey, tr)
	if err != nil {
		return nil, err
	}
	finishBody, err := json.Marshal(dto.EnrollFinishRequest{SessionId: sess.SessionId, Signature: agentSig})
	if err != nil {
		return nil, err
	}
	finishMsg, err := ch.EnrollFinish(ctx, finishBody)
	if err != nil {
		return nil, fmt.Errorf("enroll finish: %w", err)
	}
	finishResp := finishMsg.Body
	if err := enroll.VerifyResult(leaf, tr, finishResp, finishMsg.Signature); err != nil {
		return nil, err
	}
	var res dto.EnrollResult
	if err := json.Unmarshal(finishResp, &res); err != nil {
		return nil, fmt.Errorf("enroll finish: decode: %w", err)
	}
	if err := pki.ValidateAgentID(res.AgentId); err != nil {
		return nil, fmt.Errorf("enroll finish: %w", err)
	}
	enr.AgentID = res.AgentId
	enr.EnrolledAt = time.Now().UTC()

	if err := o.State.SaveExtraRoots(o.ExtraRoots); err != nil {
		return nil, err
	}
	if err := o.State.ClearRevocation(); err != nil {
		return nil, err
	}
	switch res.Status {
	case dto.EnrollStatusApproved:
		if _, _, err := acceptResult(o.State, enr, key, res); err != nil {
			return nil, err
		}
		o.Logger.Info("enrolled", "agent_id", enr.AgentID)
		return enr, nil
	case dto.EnrollStatusPending:
	default:
		return nil, ErrNotApproved
	}

	// Pending: store the identity key and the enrollment, then wait.
	if err := o.State.SaveIdentity(&state.Identity{Key: key}); err != nil {
		return nil, err
	}
	enr.Status = state.StatusPending
	if err := o.State.SaveEnrollment(enr); err != nil {
		return nil, err
	}
	rt, err := New(ropts)
	if err != nil {
		return nil, err
	}
	// Keep the connection (in listen mode the server is connected to the
	// listener opened above).
	rt.keys = &serverKeys{}
	rt.keys.add(leaf)
	if err := rt.attach(ch, owner); err != nil {
		return nil, err
	}
	if err := rt.waitApproved(ctx); err != nil {
		return nil, err
	}
	out := rt.Enrollment()
	return &out, nil
}

// resumePending waits for approval of a stored pending enrollment.
func resumePending(ctx context.Context, opts Options) (*state.Enrollment, error) {
	rt, err := New(opts)
	if err != nil {
		return nil, err
	}
	ch, owner, err := rt.openChannel(ctx)
	if err != nil {
		return nil, err
	}
	defer ch.Close()
	if err := rt.attach(ch, owner); err != nil {
		return nil, err
	}
	if err := rt.waitApproved(ctx); err != nil {
		return nil, err
	}
	out := rt.Enrollment()
	return &out, nil
}

func enrollmentParams(o EnrollOptions, pin [32]byte) (*state.Enrollment, error) {
	enr := &state.Enrollment{
		Kind:            string(o.Kind),
		ConnectMode:     o.ConnectMode,
		ServerName:      o.ServerName,
		TLSMode:         string(o.TLSMode),
		Channel:         o.Channel,
		ChannelSettings: o.ChannelSettings,
	}
	enr.SetPin(pin)
	if enr.TLSMode == "" {
		enr.TLSMode = string(link.TLSPinned)
	}
	if _, err := link.ParseTLSMode(enr.TLSMode); err != nil {
		return nil, err
	}
	if o.Channel != "" && !builtinChannel(o.Channel, &o.Runtime) {
		return customChannelParams(o, enr)
	}
	enr.Channel = ""
	switch o.ConnectMode {
	case "", ModeConnect:
		enr.ConnectMode = ModeConnect
		u, err := NormalizeServerURL(o.ServerURL)
		if err != nil {
			return nil, err
		}
		enr.ServerURL = u
		if enr.ServerName == "" {
			pu, _ := url.Parse(u)
			enr.ServerName = pu.Hostname()
		}
	case ModeListen:
		if o.Kind == KindScanner {
			return nil, errors.New("scanners support connect mode only")
		}
		if o.ListenAddress == "" || o.ServerName == "" {
			return nil, errors.New("listen mode needs a listen address and the server name")
		}
		if enr.TLSMode != string(link.TLSPinned) {
			return nil, errors.New("relaxed TLS modes are defined for connect mode only")
		}
		enr.ListenAddress = o.ListenAddress
	default:
		return nil, fmt.Errorf("unknown connect mode %q", o.ConnectMode)
	}
	return enr, nil
}

// customChannelParams completes the enrollment of a registered channel,
// which gets the server address and name as given.
func customChannelParams(o EnrollOptions, enr *state.Enrollment) (*state.Enrollment, error) {
	if _, err := o.Runtime.factory(o.Channel); err != nil {
		return nil, err
	}
	if enr.ConnectMode == "" {
		enr.ConnectMode = ModeConnect
	}
	if enr.ConnectMode != ModeConnect && enr.ConnectMode != ModeListen {
		return nil, fmt.Errorf("unknown connect mode %q", enr.ConnectMode)
	}
	enr.ServerURL, enr.ListenAddress = o.ServerURL, o.ListenAddress
	if enr.ServerName == "" {
		enr.ServerName = serverNameOf(o.ServerURL)
	}
	if enr.ServerName == "" {
		return nil, errors.New("the channel needs the server name (the name in the server certificates)")
	}
	return enr, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optionalBytes(b []byte) *[]byte {
	if len(b) == 0 {
		return nil
	}
	return &b
}
