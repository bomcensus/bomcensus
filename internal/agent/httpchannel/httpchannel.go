// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package httpchannel is the agent end of the built-in HTTP channel
// (docs/PROTOCOL.md): the agent protocol over HTTPS under /agent/v1, with
// requests signed by the agent identity key and responses verified against
// the server's signing key (internal/msgsig), in connect mode (the agent
// dials the server) or listen mode (the server dials the agent).
package httpchannel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/enroll"
	"github.com/bomcensus/bomcensus/internal/gen/agentapi"
	"github.com/bomcensus/bomcensus/internal/link"
	"github.com/bomcensus/bomcensus/internal/msgsig"
)

// BasePath is the path prefix of the agent protocol.
const BasePath = "/agent/v1"

// Channel names, which are also the connection modes.
const (
	NameConnect = "connect"
	NameListen  = "listen"
)

// exemptPaths are signed requests whose responses are streamed unsigned.
var exemptPaths = msgsig.Paths{BasePath + "/update/bundle/", BasePath + "/probe/"}

// maxJSONBody bounds unsigned JSON responses (enrollment, server chain).
const maxJSONBody = 4 << 20

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

// Options tune the channel.
type Options struct {
	// Connect tunes the connect-mode HTTP transport.
	Connect link.ConnectOptions
	// Now is the clock of the signatures (default time.Now).
	Now func() time.Time
}

// Factory returns the factory of the HTTP channel. It opens connect mode
// or listen mode by ChannelParams.Name.
func Factory(o Options) agentproto.ChannelFactory {
	return func(ctx context.Context, p agentproto.ChannelParams) (agentproto.Channel, error) {
		lc, err := openLink(ctx, p, o.Connect)
		if err != nil {
			return nil, err
		}
		c := &channel{lc: lc, p: p, now: o.Now}
		c.client, err = agentapi.NewClientWithResponses(lc.baseURL, agentapi.WithHTTPClient(&http.Client{Transport: &signer{c: c}}))
		if err != nil {
			lc.close()
			return nil, err
		}
		return c, nil
	}
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

func openLink(ctx context.Context, p agentproto.ChannelParams, connect link.ConnectOptions) (*linkConn, error) {
	obs := &link.ObservedPeer{}
	verify := link.ServerVerifier(p.VerifyServer)
	switch p.Name {
	case NameConnect, "":
		tlsMode, err := link.ParseTLSMode(p.TLSMode)
		if err != nil {
			return nil, err
		}
		var getCert func() (*tls.Certificate, error)
		if tlsMode == link.TLSPinned {
			getCert = p.ClientCertificate
		}
		tc, err := link.ClientTLSConfig(link.ClientConfig{
			Mode:              tlsMode,
			Verify:            verify,
			ClientCertificate: getCert,
			ExtraRoots:        p.ExtraRoots,
			ObservePeer:       obs.Observe,
		})
		if err != nil {
			return nil, err
		}
		rt := link.NewConnectTransport(tc, connect)
		closeIdle := func() {
			if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
				c.CloseIdleConnections()
			}
		}
		return &linkConn{
			base:     rt,
			baseURL:  p.ServerURL + BasePath + "/",
			observed: obs,
			reset:    closeIdle,
			close:    closeIdle,
		}, nil
	case NameListen:
		l, err := link.Listen(ctx, p.ListenAddress, link.ListenConfig{
			Certificate: p.ListenerCertificate,
			Verify:      verify,
			ObservePeer: obs.Observe,
			Logger:      p.Logger,
		})
		if err != nil {
			return nil, err
		}
		if p.OnListening != nil {
			p.OnListening(l.Addr())
		}
		p.Logger.Info("waiting for the server to connect", "address", l.Addr().String())
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
				p.Logger.Error("listener stopped", "error", err)
			}
		}()
		return &linkConn{
			base:     holder,
			baseURL:  "https://" + p.ServerName + BasePath + "/",
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
	return nil, fmt.Errorf("unknown connect mode %q", p.Name)
}

// channel implements agentproto.Channel over a linkConn.
type channel struct {
	lc     *linkConn
	p      agentproto.ChannelParams
	now    func() time.Time
	client *agentapi.ClientWithResponses
}

var (
	_ agentproto.Channel       = (*channel)(nil)
	_ agentproto.PeerObserving = (*channel)(nil)
)

func (c *channel) Reset() {
	if c.lc.reset != nil {
		c.lc.reset()
	}
}

func (c *channel) Close() error {
	c.lc.close()
	return nil
}

// ObservedServer implements agentproto.PeerObserving.
func (c *channel) ObservedServer() (fingerprint [32]byte, leaf, issuer *x509.Certificate, ok bool) {
	fingerprint, leaf, ok = c.lc.observed.Last()
	return fingerprint, leaf, c.lc.observed.Issuer(), ok
}

// signer signs with the identity current at the time of each request.
type signer struct{ c *channel }

func (s *signer) RoundTrip(req *http.Request) (*http.Response, error) {
	var id agentproto.Identity
	if s.c.p.Identity != nil {
		id = s.c.p.Identity(req.Context())
	}
	t := &msgsig.Transport{
		Base:       s.c.lc.base,
		AgentID:    id.AgentID,
		Key:        id.Key,
		Counter:    s.c.p.Counter,
		ServerKeys: s.c.p.ServerKeys,
		Exempt:     exemptPaths,
		Now:        s.c.now,
	}
	return t.RoundTrip(req)
}

// doRaw sends req unsigned and returns the status, header and the complete
// body.
func (c *channel) doRaw(ctx context.Context, req *http.Request) (int, http.Header, []byte, error) {
	resp, err := (&http.Client{Transport: c.lc.base}).Do(req.WithContext(ctx))
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

func apiError(status int, body []byte) error {
	e := &agentproto.Error{Status: status}
	var eb dto.Error
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

// decodeResponse checks the status of a response and decodes its JSON body
// into v (nil skips decoding). Other statuses yield an *agentproto.Error;
// the transport only returns responses whose signature verified.
func decodeResponse(resp *http.Response, body []byte, want int, v any) error {
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

// enrollMessage performs an unsigned enrollment request.
func (c *channel) enrollMessage(ctx context.Context, req *http.Request, err error) (*agentproto.SignedMessage, error) {
	if err != nil {
		return nil, err
	}
	status, hdr, body, err := c.doRaw(ctx, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError(status, body)
	}
	return &agentproto.SignedMessage{Body: body, Signature: hdr.Get(enroll.HeaderSignature)}, nil
}

func (c *channel) EnrollStart(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	req, err := agentapi.NewEnrollStartRequestWithBody(c.lc.baseURL, "application/json", bytes.NewReader(body))
	return c.enrollMessage(ctx, req, err)
}

func (c *channel) EnrollFinish(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	req, err := agentapi.NewEnrollFinishRequestWithBody(c.lc.baseURL, "application/json", bytes.NewReader(body))
	return c.enrollMessage(ctx, req, err)
}

// GetServerChain performs the unsigned GET /server-chain.
func (c *channel) GetServerChain(ctx context.Context) (*dto.ServerChain, error) {
	req, err := agentapi.NewGetServerChainRequest(c.lc.baseURL)
	if err != nil {
		return nil, err
	}
	status, _, body, err := c.doRaw(ctx, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError(status, body)
	}
	var sc dto.ServerChain
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &sc, nil
}

func (c *channel) GetEnrollResult(ctx context.Context) (*dto.EnrollResult, error) {
	resp, err := c.client.GetEnrollResultWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	var res dto.EnrollResult
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *channel) RenewCert(ctx context.Context, req *dto.CertRenewRequest) (*dto.RenewedCert, error) {
	var body dto.CertRenewRequest
	if req != nil {
		body = *req
	}
	resp, err := c.client.RenewCertWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	var rc dto.RenewedCert
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &rc); err != nil {
		return nil, err
	}
	return &rc, nil
}

func (c *channel) GetTrustBundle(ctx context.Context) (*dto.TrustBundle, error) {
	resp, err := c.client.GetTrustBundleWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	var tb dto.TrustBundle
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &tb); err != nil {
		return nil, err
	}
	return &tb, nil
}

func (c *channel) Poll(ctx context.Context, req *dto.PollRequest) (*dto.PollResult, error) {
	resp, err := c.client.PollWithResponse(ctx, *req)
	if err != nil {
		return nil, err
	}
	var res dto.PollResult
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *channel) UploadReport(ctx context.Context, params dto.UploadReportParams, report io.Reader) (*dto.ReportAccepted, error) {
	resp, err := c.client.UploadReportWithBodyWithResponse(ctx, &params, "application/octet-stream", report)
	if err != nil {
		return nil, err
	}
	var acc dto.ReportAccepted
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusAccepted, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

func (c *channel) UploadK8sInventory(ctx context.Context, inv *dto.K8sInventory) error {
	resp, err := c.client.UploadK8sInventoryWithResponse(ctx, *inv)
	if err != nil {
		return err
	}
	return decodeResponse(resp.HTTPResponse, resp.Body, http.StatusNoContent, nil)
}

func (c *channel) SubmitScanJobResult(ctx context.Context, jobID string, res *dto.ScanJobResult) error {
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	resp, err := c.client.SubmitScanJobResultWithBodyWithResponse(ctx, jobID, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return decodeResponse(resp.HTTPResponse, resp.Body, http.StatusNoContent, nil)
}

func (c *channel) CheckUpdate(ctx context.Context, params dto.CheckUpdateParams) (*dto.UpdateCheck, error) {
	resp, err := c.client.CheckUpdateWithResponse(ctx, &params)
	if err != nil {
		return nil, err
	}
	uc := &dto.UpdateCheck{}
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, uc); err != nil {
		return nil, err
	}
	return uc, nil
}

// DownloadUpdateBundle streams the bundle; its response is not signed.
func (c *channel) DownloadUpdateBundle(ctx context.Context, version string, params dto.DownloadUpdateBundleParams) (*agentproto.Download, error) {
	resp, err := c.client.DownloadUpdateBundle(ctx, version, &params)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxJSONBody))
		resp.Body.Close()
		return nil, apiError(resp.StatusCode, body)
	}
	return &agentproto.Download{Body: resp.Body, Size: resp.ContentLength}, nil
}

// DownloadProbe downloads the probe; its response is not signed.
func (c *channel) DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*agentproto.Download, error) {
	resp, err := c.client.DownloadProbeWithResponse(ctx, os, arch)
	if err != nil {
		return nil, err
	}
	if err := decodeResponse(resp.HTTPResponse, resp.Body, http.StatusOK, nil); err != nil {
		return nil, err
	}
	return &agentproto.Download{Body: io.NopCloser(bytes.NewReader(resp.Body)), Size: int64(len(resp.Body)),
		Version: resp.HTTPResponse.Header.Get("Bomcensus-Probe-Version")}, nil
}
