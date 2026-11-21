// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const (
	handshakeTimeout  = 30 * time.Second
	keepAliveInterval = 15 * time.Second
	keepAliveTimeout  = 30 * time.Second
	clientVersion     = "SSH-2.0-bomcensus"
)

// Host key algorithms in order of preference when no key is pinned.
// Certificates are not accepted because pinning is by plain key. ssh-rsa
// (RSA with SHA-1) is listed last: negotiation picks the first entry the
// server also offers, so it is used only by servers that offer no other
// algorithm (OpenSSH before 7.2 with only an RSA key). A forged SHA-1
// signature would need a chosen-prefix collision during the handshake, which
// is not practical, and a pinned key still has to match.
var tofuHostKeyAlgorithms = []string{
	gossh.KeyAlgoED25519,
	gossh.KeyAlgoECDSA256,
	gossh.KeyAlgoECDSA384,
	gossh.KeyAlgoECDSA521,
	gossh.KeyAlgoRSASHA512,
	gossh.KeyAlgoRSASHA256,
	gossh.KeyAlgoRSA,
}

// hostKeyAlgorithms restricts negotiation to the pinned key's type, so a
// server with several host keys presents the pinned one.
func hostKeyAlgorithms(pinned gossh.PublicKey) []string {
	if pinned == nil {
		return tofuHostKeyAlgorithms
	}
	if pinned.Type() == gossh.KeyAlgoRSA {
		return []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA}
	}
	return []string{pinned.Type()}
}

// cryptoConfig uses the library's list of algorithms without known
// weaknesses (no SHA-1 key exchange, no CBC or RC4) and also leaves out
// hmac-sha1, which only matters for servers older than OpenSSH 5.9.
func cryptoConfig() gossh.Config {
	a := gossh.SupportedAlgorithms()
	return gossh.Config{
		KeyExchanges: a.KeyExchanges,
		Ciphers:      a.Ciphers,
		MACs:         slices.DeleteFunc(a.MACs, func(m string) bool { return m == gossh.HMACSHA1 }),
	}
}

func (t *Target) addr() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(t.Address, strconv.Itoa(port))
}

// parseHostKey accepts SSH wire format or an authorized_keys line.
func parseHostKey(b []byte) (gossh.PublicKey, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if k, err := gossh.ParsePublicKey(b); err == nil {
		return k, nil
	}
	k, _, _, _, err := gossh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse pinned host key: %w", err)
	}
	return k, nil
}

func authMethods(a Auth) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod
	if len(a.PrivateKey) > 0 {
		var signer gossh.Signer
		var err error
		if len(a.Passphrase) > 0 {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(a.PrivateKey, a.Passphrase)
		} else {
			signer, err = gossh.ParsePrivateKey(a.PrivateKey)
		}
		if err != nil {
			var missing *gossh.PassphraseMissingError
			if errors.As(err, &missing) {
				return nil, errors.New("ssh: private key is encrypted and no passphrase was given")
			}
			return nil, fmt.Errorf("ssh: parse private key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}
	if a.Password != "" {
		pw := a.Password
		methods = append(methods,
			gossh.Password(pw),
			gossh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
				// Answer the usual single hidden "Password:" question; refuse
				// anything else rather than guess.
				switch {
				case len(questions) == 0:
					return nil, nil
				case len(questions) == 1 && !echos[0]:
					return []string{pw}, nil
				}
				return nil, errors.New("ssh: unsupported keyboard-interactive challenge")
			}))
	}
	return methods, nil
}

// conn is an established connection.
type conn struct {
	client  *gossh.Client
	hostKey []byte
	log     *slog.Logger
	stops   []func()
}

func dial(ctx context.Context, t *Target, log *slog.Logger) (*conn, error) {
	c := &conn{log: log}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr())
	if err != nil {
		return nil, fmt.Errorf("ssh: connect to %s: %w", t.addr(), err)
	}
	c.client, c.hostKey, err = handshake(ctx, raw, t)
	if err != nil {
		c.close()
		return nil, err
	}
	c.stops = append(c.stops, keepAlive(c.client, log))
	return c, nil
}

// handshake runs the SSH handshake on raw and takes ownership of it.
func handshake(ctx context.Context, raw net.Conn, t *Target) (*gossh.Client, []byte, error) {
	addr := t.addr()
	pinned, err := parseHostKey(t.HostKey)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	methods, err := authMethods(t.Auth)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	var seen []byte
	var changed *HostKeyChangedError
	cfg := &gossh.ClientConfig{
		Config:            cryptoConfig(),
		User:              t.User,
		Auth:              methods,
		ClientVersion:     clientVersion,
		HostKeyAlgorithms: hostKeyAlgorithms(pinned),
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			seen = key.Marshal()
			if pinned != nil && !bytes.Equal(seen, pinned.Marshal()) {
				changed = &HostKeyChangedError{Address: addr, Fingerprint: gossh.FingerprintSHA256(key), Key: seen}
				return changed
			}
			return nil
		},
	}
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(hctx, func() { raw.Close() })
	cc, chans, reqs, err := gossh.NewClientConn(raw, addr, cfg)
	if !stop() {
		if err == nil {
			cc.Close()
		}
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("ssh: handshake with %s: %w", addr, ctx.Err())
		}
		return nil, nil, fmt.Errorf("ssh: handshake with %s timed out", addr)
	}
	if err != nil {
		raw.Close()
		if changed != nil {
			return nil, nil, changed
		}
		return nil, nil, fmt.Errorf("ssh: handshake with %s: %w", addr, err)
	}
	return gossh.NewClient(cc, chans, reqs), seen, nil
}

// keepAlive closes client when the server stops answering keep-alive
// requests, so that a dead connection fails the collection instead of
// hanging until the deadline.
func keepAlive(client *gossh.Client, log *slog.Logger) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(keepAliveInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			reply := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				reply <- err
			}()
			select {
			case <-done:
				return
			case err := <-reply:
				if err != nil {
					return
				}
			case <-time.After(keepAliveTimeout):
				log.Warn("ssh keep-alive timed out, closing connection")
				client.Close()
				return
			}
		}
	}()
	return sync.OnceFunc(func() { close(done) })
}

func (c *conn) close() {
	for _, stop := range c.stops {
		stop()
	}
	if c.client != nil {
		c.client.Close()
	}
}

// remoteProc is a started remote command.
type remoteProc struct {
	s     *gossh.Session
	stdin interface {
		Write([]byte) (int, error)
		Close() error
	}
	done chan struct{}
	err  error
	stop func() bool
}

// start runs cmd in a new session. When ctx ends the remote command is sent
// SIGTERM (where the server supports signals) and the session is closed.
func (c *conn) start(ctx context.Context, cmd string, stdout, stderr *streamBuffer, sink *reportSink) (*remoteProc, error) {
	type opened struct {
		s   *gossh.Session
		err error
	}
	ch := make(chan opened, 1)
	go func() {
		s, err := c.client.NewSession()
		ch <- opened{s, err}
	}()
	var s *gossh.Session
	select {
	case o := <-ch:
		if o.err != nil {
			return nil, fmt.Errorf("ssh: open session: %w", o.err)
		}
		s = o.s
	case <-ctx.Done():
		go func() {
			if o := <-ch; o.s != nil {
				o.s.Close()
			}
		}()
		return nil, ctx.Err()
	}
	if sink != nil {
		s.Stdout = sink
	} else {
		s.Stdout = stdout
	}
	s.Stderr = stderr
	in, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("ssh: session stdin: %w", err)
	}
	c.log.Debug("remote command", "command", cmd)
	if err := s.Start(cmd); err != nil {
		s.Close()
		return nil, fmt.Errorf("ssh: start remote command: %w", err)
	}
	p := &remoteProc{s: s, stdin: in, done: make(chan struct{})}
	go func() {
		p.err = s.Wait()
		close(p.done)
	}()
	p.stop = context.AfterFunc(ctx, p.abort)
	return p, nil
}

func (p *remoteProc) abort() {
	_ = p.s.Signal(gossh.SIGTERM)
	_ = p.s.Close()
}

func (p *remoteProc) release() {
	p.stop()
	_ = p.s.Close()
}

// wait returns the exit status, or an error when the command did not exit
// normally or ctx ended first.
func (p *remoteProc) wait(ctx context.Context) (int, error) {
	select {
	case <-p.done:
	case <-ctx.Done():
		p.abort()
		return -1, ctx.Err()
	}
	return exitStatus(p.err)
}

func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *gossh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus(), nil
	}
	return -1, fmt.Errorf("ssh: remote command: %w", err)
}
