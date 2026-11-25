// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package framechannel is an example agent channel without HTTP: the
// operations of agentproto.API as length-prefixed JSON frames over one TLS
// connection, several calls in flight at once.
//
// The adapter authenticates both directions itself:
//
//   - TLS with the server's Agent TLS certificate, which the agent verifies
//     with ChannelParams.VerifyServer (the anchor of its enrollment, later
//     its trust bundle). Answers are trusted because the connection is.
//   - The agent presents its certificate when it has one; the gateway
//     verifies it with Agents.VerifyCertificate.
//   - Every request after enrollment is signed with the agent identity key
//     over the operation, the agent id, a timestamp, a nonce and the hashes
//     of its arguments. The gateway verifies it with the key from
//     Agents.AgentKey, refuses old timestamps and repeated nonces, and
//     requires the agent certificate on the connection for agents whose
//     key says so.
//
// The agent's state and the scanner-only operations are checked by the
// server's API. The example keeps the nonces in memory, so one gateway
// process must serve an agent; it does not use the request counters of the
// HTTP channel.
package framechannel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
)

// Name is the channel name agents enroll with (--channel frame).
const Name = "frame"

// maxFrame bounds one frame (reports and bundles travel in frames).
const maxFrame = 512 << 20

// maxSkew is the accepted difference between a request's timestamp and
// the gateway clock.
const maxSkew = 5 * time.Minute

// Operations.
const (
	opEnrollStart          = "enrollStart"
	opEnrollFinish         = "enrollFinish"
	opGetEnrollResult      = "getEnrollResult"
	opRenewCert            = "renewCert"
	opGetServerChain       = "getServerChain"
	opGetTrustBundle       = "getTrustBundle"
	opPoll                 = "poll"
	opUploadReport         = "uploadReport"
	opUploadK8sInventory   = "uploadK8sInventory"
	opSubmitScanJobResult  = "submitScanJobResult"
	opCheckUpdate          = "checkUpdate"
	opDownloadUpdateBundle = "downloadUpdateBundle"
	opDownloadProbe        = "downloadProbe"
)

// unsigned are the operations that carry no agent signature: enrollment
// messages are signed by the enrollment protocol, the server chain is
// verified by the agent.
var unsigned = map[string]bool{opEnrollStart: true, opEnrollFinish: true, opGetServerChain: true}

// request is the wire form of a call.
type request struct {
	ID   uint64            `json:"id"`
	Op   string            `json:"op"`
	Args map[string]string `json:"args,omitempty"`
	// Body is the request DTO.
	Body json.RawMessage `json:"body,omitempty"`
	// Data is a byte argument: an enrollment message or a report.
	Data []byte `json:"data,omitempty"`

	AgentID   string `json:"agent_id,omitempty"`
	Time      int64  `json:"time,omitempty"`
	Nonce     []byte `json:"nonce,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// response is the wire form of an answer.
type response struct {
	ID uint64 `json:"id"`
	// Body is the response DTO.
	Body json.RawMessage `json:"body,omitempty"`
	// Data is an enrollment message or a download.
	Data      []byte     `json:"data,omitempty"`
	Signature string     `json:"signature,omitempty"`
	Version   string     `json:"version,omitempty"`
	Err       *wireError `json:"err,omitempty"`
}

type wireError struct {
	Status       int    `json:"status"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
}

// signedMessage is what a request signature covers.
func (r *request) signedMessage() []byte {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte("bomcensus frame request"))
	field([]byte(r.Op))
	field([]byte(r.AgentID))
	field(binary.BigEndian.AppendUint64(nil, uint64(r.Time)))
	field(r.Nonce)
	keys := make([]string, 0, len(r.Args))
	for k := range r.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field([]byte(k))
		field([]byte(r.Args[k]))
	}
	field(r.Body)
	field(r.Data)
	return h.Sum(nil)
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return fmt.Errorf("framechannel: frame of %d bytes", len(b))
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxFrame {
		return fmt.Errorf("framechannel: frame of %d bytes", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ── gateway ────────────────────────────────────────────────────────────

// Gateway is the server end (agentproto.Gateway).
type Gateway struct {
	// Addr is the TCP address to listen on.
	Addr   string
	Logger *slog.Logger
	// Now is the clock (default time.Now).
	Now func() time.Time
}

var _ agentproto.Gateway = (*Gateway)(nil)

// Run implements agentproto.Gateway.
func (g *Gateway) Run(ctx context.Context, s *agentproto.Server) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", g.Addr)
	if err != nil {
		return err
	}
	return g.Serve(ctx, ln, s)
}

// Serve accepts connections on ln until ctx ends. It owns ln.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener, s *agentproto.Server) error {
	log := g.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := g.Now
	if now == nil {
		now = time.Now
	}
	gw := &gateway{s: s, log: log, now: now, nonces: map[string]time.Time{}}
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.Agents.ServerCertificate()
		},
		// The agent certificate is optional (enrollment, pending agents)
		// and verified against the Agent CA by the server.
		ClientAuth: tls.RequestClientCert,
	})
	go func() {
		<-ctx.Done()
		_ = tlsLn.Close()
	}()
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go gw.serveConn(ctx, conn.(*tls.Conn))
	}
}

type gateway struct {
	s   *agentproto.Server
	log *slog.Logger
	now func() time.Time

	mu     sync.Mutex
	nonces map[string]time.Time
}

// connection is what a gateway knows about one agent connection.
type connection struct {
	peer agentproto.Peer
	// certAgent is the agent the connection's certificate belongs to.
	certAgent string
	certErr   error
}

func (g *gateway) serveConn(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := conn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		g.log.Debug("handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	c := &connection{}
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		c.peer.RemoteAddr = ap.Addr().Unmap()
	}
	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		c.certAgent, c.certErr = g.s.Agents.VerifyCertificate(certs)
	}

	var wmu sync.Mutex
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	cctx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()
	for {
		var req request
		if err := readFrame(r, &req); err != nil {
			return
		}
		go func() {
			resp := g.serve(cctx, c, &req)
			resp.ID = req.ID
			wmu.Lock()
			defer wmu.Unlock()
			if writeFrame(w, resp) == nil {
				_ = w.Flush()
			}
		}()
	}
}

func errResponse(e *agentproto.Error) *response {
	return &response{Err: &wireError{Status: e.Status, Code: e.Code, Message: e.Message, RetryAfterMS: e.RetryAfter.Milliseconds()}}
}

// serve authenticates one request and runs it.
func (g *gateway) serve(ctx context.Context, c *connection, req *request) *response {
	ctx = agentproto.WithPeer(ctx, c.peer)
	if !unsigned[req.Op] {
		if e := g.authenticate(ctx, c, req); e != nil {
			g.log.Warn("request refused", "op", req.Op, "agent_id", req.AgentID, "code", e.Code, "reason", e.Message)
			return errResponse(e)
		}
		ctx = agentproto.WithAgent(ctx, req.AgentID)
	}
	resp, err := g.dispatch(ctx, req)
	if err != nil {
		if e, ok := agentproto.AsError(err); ok {
			return errResponse(e)
		}
		g.log.Error("operation failed", "op", req.Op, "error", err)
		return errResponse(agentproto.Errorf(http.StatusInternalServerError, agentproto.CodeInternal, "internal error"))
	}
	return resp
}

func (g *gateway) authenticate(ctx context.Context, c *connection, req *request) *agentproto.Error {
	unauthorized := func(msg string) *agentproto.Error {
		return agentproto.Errorf(http.StatusUnauthorized, agentproto.CodeUnauthorized, "%s", msg)
	}
	if req.AgentID == "" || len(req.Nonce) != 16 || len(req.Signature) != ed25519.SignatureSize {
		return unauthorized("unsigned request")
	}
	now := g.now()
	if d := now.Sub(time.Unix(req.Time, 0)); d > maxSkew || d < -maxSkew {
		return unauthorized("request time out of range")
	}
	key, err := g.s.Agents.AgentKey(ctx, req.AgentID)
	if err != nil {
		if !errors.Is(err, agentproto.ErrUnknownAgent) {
			g.log.Error("agent lookup", "agent_id", req.AgentID, "error", err)
		}
		return unauthorized("unknown agent")
	}
	if !ed25519.Verify(key.PublicKey, req.signedMessage(), req.Signature) {
		return unauthorized("bad signature")
	}
	if !g.fresh(string(req.Nonce), now) {
		return unauthorized("nonce replayed")
	}
	if c.certErr != nil || (c.certAgent != "" && c.certAgent != req.AgentID) ||
		(key.RequireCertificate && c.certAgent == "") {
		return agentproto.Errorf(http.StatusForbidden, agentproto.CodeClientCertMismatch, "the connection is not authenticated as this agent")
	}
	return nil
}

// fresh records a nonce and reports whether it was not seen within the
// skew window.
func (g *gateway) fresh(nonce string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for n, t := range g.nonces {
		if now.Sub(t) > 2*maxSkew {
			delete(g.nonces, n)
		}
	}
	if _, seen := g.nonces[nonce]; seen {
		return false
	}
	g.nonces[nonce] = now
	return true
}

func decode[T any](raw json.RawMessage) (*T, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	v := new(T)
	if err := json.Unmarshal(raw, v); err != nil {
		return nil, agentproto.Errorf(http.StatusBadRequest, agentproto.CodeInvalidRequest, "decode body: %v", err)
	}
	return v, nil
}

func bodyResponse(v any, err error) (*response, error) {
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &response{Body: b}, nil
}

func downloadResponse(d *agentproto.Download, err error) (*response, error) {
	if err != nil {
		return nil, err
	}
	defer d.Body.Close()
	data, err := io.ReadAll(io.LimitReader(d.Body, maxFrame/2))
	if err != nil {
		return nil, err
	}
	return &response{Data: data, Version: d.Version}, nil
}

// dispatch runs the operation of req.
func (g *gateway) dispatch(ctx context.Context, req *request) (*response, error) {
	api := g.s.API
	switch req.Op {
	case opEnrollStart, opEnrollFinish:
		call := api.EnrollStart
		if req.Op == opEnrollFinish {
			call = api.EnrollFinish
		}
		m, err := call(ctx, req.Data)
		if err != nil {
			return nil, err
		}
		return &response{Data: m.Body, Signature: m.Signature}, nil
	case opGetServerChain:
		return bodyResponse(api.GetServerChain(ctx))
	case opGetEnrollResult:
		return bodyResponse(api.GetEnrollResult(ctx))
	case opRenewCert:
		in, err := decode[dto.CertRenewRequest](req.Body)
		if err != nil {
			return nil, err
		}
		return bodyResponse(api.RenewCert(ctx, in))
	case opGetTrustBundle:
		return bodyResponse(api.GetTrustBundle(ctx))
	case opPoll:
		in, err := decode[dto.PollRequest](req.Body)
		if err != nil {
			return nil, err
		}
		return bodyResponse(api.Poll(ctx, in))
	case opUploadReport:
		var params dto.UploadReportParams
		if id, ok := req.Args["job_id"]; ok {
			params.JobId = &id
		}
		return bodyResponse(api.UploadReport(ctx, params, bytes.NewReader(req.Data)))
	case opUploadK8sInventory:
		in, err := decode[dto.K8sInventory](req.Body)
		if err != nil {
			return nil, err
		}
		return &response{}, api.UploadK8sInventory(ctx, in)
	case opSubmitScanJobResult:
		in, err := decode[dto.ScanJobResult](req.Body)
		if err != nil {
			return nil, err
		}
		return &response{}, api.SubmitScanJobResult(ctx, req.Args["job_id"], in)
	case opCheckUpdate:
		return bodyResponse(api.CheckUpdate(ctx, dto.CheckUpdateParams{
			Os: dto.TargetOs(req.Args["os"]), Arch: dto.TargetArch(req.Args["arch"])}))
	case opDownloadUpdateBundle:
		return downloadResponse(api.DownloadUpdateBundle(ctx, req.Args["version"], dto.DownloadUpdateBundleParams{
			Os: dto.TargetOs(req.Args["os"]), Arch: dto.TargetArch(req.Args["arch"])}))
	case opDownloadProbe:
		return downloadResponse(api.DownloadProbe(ctx, dto.TargetOs(req.Args["os"]), dto.TargetArch(req.Args["arch"])))
	}
	return nil, agentproto.Errorf(http.StatusNotFound, agentproto.CodeNotFound, "unknown operation %q", req.Op)
}

// ── agent ──────────────────────────────────────────────────────────────

// Factory returns the agent end (agentproto.ChannelFactory). The server
// address is HOST:PORT of the gateway.
func Factory() agentproto.ChannelFactory {
	return func(ctx context.Context, p agentproto.ChannelParams) (agentproto.Channel, error) {
		if p.ServerURL == "" || p.ServerName == "" {
			return nil, errors.New("framechannel: the server address and name are required")
		}
		return &Channel{p: p, pending: map[uint64]chan *response{}}, nil
	}
}

// Channel is the agent end of the frame channel.
type Channel struct {
	p agentproto.ChannelParams

	mu      sync.Mutex
	conn    *tls.Conn
	w       *bufio.Writer
	nextID  uint64
	pending map[uint64]chan *response
	closed  bool
}

var _ agentproto.Channel = (*Channel)(nil)

func (c *Channel) dial(ctx context.Context) (*tls.Conn, error) {
	d := tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: c.p.ServerName,
		// The chain is verified against the enrollment anchor below.
		InsecureSkipVerify: true, //nolint:gosec // verified by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if c.p.VerifyServer == nil {
				return errors.New("framechannel: no server verifier")
			}
			return c.p.VerifyServer(cs.PeerCertificates, x509.ExtKeyUsageServerAuth)
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c.p.ClientCertificate != nil {
				if cert, err := c.p.ClientCertificate(); err != nil || cert != nil {
					return cert, err
				}
			}
			return &tls.Certificate{}, nil
		},
	}}
	conn, err := d.DialContext(ctx, "tcp", c.p.ServerURL)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// connect returns the open connection, dialing one when there is none.
func (c *Channel) connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.conn != nil {
		return nil
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	c.conn, c.w = conn, bufio.NewWriter(conn)
	go c.readLoop(conn)
	return nil
}

func (c *Channel) readLoop(conn *tls.Conn) {
	r := bufio.NewReader(conn)
	for {
		var resp response
		if err := readFrame(r, &resp); err != nil {
			c.drop(conn)
			return
		}
		c.mu.Lock()
		ch := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- &resp
		}
	}
}

// drop closes conn and fails its calls.
func (c *Channel) drop(conn *tls.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return
	}
	_ = conn.Close()
	c.conn = nil
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

// Reset implements agentproto.Channel: the next call connects again and
// presents the current certificate.
func (c *Channel) Reset() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		c.drop(conn)
	}
}

// Close implements agentproto.Channel.
func (c *Channel) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.Reset()
	return nil
}

// call signs req (unless its operation is unsigned), sends it and waits
// for the answer.
func (c *Channel) call(ctx context.Context, req *request) (*response, error) {
	if !unsigned[req.Op] {
		id := c.p.Identity(ctx)
		if id.AgentID == "" || len(id.Key) != ed25519.PrivateKeySize {
			return nil, errors.New("framechannel: no identity to sign with")
		}
		req.AgentID, req.Time, req.Nonce = id.AgentID, time.Now().Unix(), make([]byte, 16)
		if _, err := rand.Read(req.Nonce); err != nil {
			return nil, err
		}
		req.Signature = ed25519.Sign(id.Key, req.signedMessage())
	}
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	ch := make(chan *response, 1)
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return nil, errors.New("framechannel: connection lost")
	}
	c.nextID++
	req.ID = c.nextID
	c.pending[req.ID] = ch
	conn, w := c.conn, c.w
	err := writeFrame(w, req)
	if err == nil {
		err = w.Flush()
	}
	c.mu.Unlock()
	if err != nil {
		c.drop(conn)
		return nil, err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("framechannel: connection lost")
		}
		if e := resp.Err; e != nil {
			return nil, &agentproto.Error{Status: e.Status, Code: e.Code, Message: e.Message,
				RetryAfter: time.Duration(e.RetryAfterMS) * time.Millisecond}
		}
		return resp, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

func callJSON[T any](ctx context.Context, c *Channel, req *request, in any) (*T, error) {
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		req.Body = b
	}
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	out := new(T)
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return nil, fmt.Errorf("framechannel: decode %s: %w", req.Op, err)
	}
	return out, nil
}

func (c *Channel) enroll(ctx context.Context, op string, body []byte) (*agentproto.SignedMessage, error) {
	resp, err := c.call(ctx, &request{Op: op, Data: body})
	if err != nil {
		return nil, err
	}
	return &agentproto.SignedMessage{Body: resp.Data, Signature: resp.Signature}, nil
}

func (c *Channel) EnrollStart(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	return c.enroll(ctx, opEnrollStart, body)
}

func (c *Channel) EnrollFinish(ctx context.Context, body []byte) (*agentproto.SignedMessage, error) {
	return c.enroll(ctx, opEnrollFinish, body)
}

func (c *Channel) GetEnrollResult(ctx context.Context) (*dto.EnrollResult, error) {
	return callJSON[dto.EnrollResult](ctx, c, &request{Op: opGetEnrollResult}, nil)
}

func (c *Channel) RenewCert(ctx context.Context, req *dto.CertRenewRequest) (*dto.RenewedCert, error) {
	return callJSON[dto.RenewedCert](ctx, c, &request{Op: opRenewCert}, req)
}

func (c *Channel) GetServerChain(ctx context.Context) (*dto.ServerChain, error) {
	return callJSON[dto.ServerChain](ctx, c, &request{Op: opGetServerChain}, nil)
}

func (c *Channel) GetTrustBundle(ctx context.Context) (*dto.TrustBundle, error) {
	return callJSON[dto.TrustBundle](ctx, c, &request{Op: opGetTrustBundle}, nil)
}

func (c *Channel) Poll(ctx context.Context, req *dto.PollRequest) (*dto.PollResult, error) {
	return callJSON[dto.PollResult](ctx, c, &request{Op: opPoll}, req)
}

func (c *Channel) UploadReport(ctx context.Context, params dto.UploadReportParams, report io.Reader) (*dto.ReportAccepted, error) {
	data, err := io.ReadAll(io.LimitReader(report, maxFrame/2))
	if err != nil {
		return nil, err
	}
	req := &request{Op: opUploadReport, Data: data}
	if params.JobId != nil {
		req.Args = map[string]string{"job_id": *params.JobId}
	}
	return callJSON[dto.ReportAccepted](ctx, c, req, nil)
}

func (c *Channel) UploadK8sInventory(ctx context.Context, inv *dto.K8sInventory) error {
	_, err := c.callBody(ctx, &request{Op: opUploadK8sInventory}, inv)
	return err
}

func (c *Channel) SubmitScanJobResult(ctx context.Context, jobID string, res *dto.ScanJobResult) error {
	_, err := c.callBody(ctx, &request{Op: opSubmitScanJobResult, Args: map[string]string{"job_id": jobID}}, res)
	return err
}

func (c *Channel) callBody(ctx context.Context, req *request, in any) (*response, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	req.Body = b
	return c.call(ctx, req)
}

func (c *Channel) CheckUpdate(ctx context.Context, params dto.CheckUpdateParams) (*dto.UpdateCheck, error) {
	return callJSON[dto.UpdateCheck](ctx, c, &request{Op: opCheckUpdate,
		Args: map[string]string{"os": string(params.Os), "arch": string(params.Arch)}}, nil)
}

func (c *Channel) download(ctx context.Context, req *request) (*agentproto.Download, error) {
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	return &agentproto.Download{Body: io.NopCloser(bytes.NewReader(resp.Data)), Size: int64(len(resp.Data)), Version: resp.Version}, nil
}

func (c *Channel) DownloadUpdateBundle(ctx context.Context, version string, params dto.DownloadUpdateBundleParams) (*agentproto.Download, error) {
	return c.download(ctx, &request{Op: opDownloadUpdateBundle,
		Args: map[string]string{"version": version, "os": string(params.Os), "arch": string(params.Arch)}})
}

func (c *Channel) DownloadProbe(ctx context.Context, os dto.TargetOs, arch dto.TargetArch) (*agentproto.Download, error) {
	return c.download(ctx, &request{Op: opDownloadProbe, Args: map[string]string{"os": string(os), "arch": string(arch)}})
}
