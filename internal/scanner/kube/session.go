// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

const (
	maxStatusLine = 8 << 10
	tokenQueue    = 64
)

type token struct {
	name, arg string
}

// statusWriter receives the session's stderr. Lines carrying the session
// prefix become tokens; everything else is kept as a bounded tail.
type statusWriter struct {
	mu      sync.Mutex
	prefix  string
	line    []byte
	tail    []byte
	tailMax int
	emit    func(token)
}

func newStatusWriter(nonce string, tailMax int, emit func(token)) *statusWriter {
	return &statusWriter{prefix: "@@BOMCENSUS-" + nonce + " ", tailMax: tailMax, emit: emit}
}

func (w *statusWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.line = append(w.line, p...)
			if len(w.line) > maxStatusLine {
				w.addTail(w.line)
				w.line = w.line[:0]
			}
			break
		}
		w.line = append(w.line, p[:i]...)
		w.handleLine()
		p = p[i+1:]
	}
	return n, nil
}

func (w *statusWriter) handleLine() {
	line := string(w.line)
	w.line = w.line[:0]
	if i := strings.Index(line, w.prefix); i >= 0 {
		if i > 0 {
			w.addTail([]byte(line[:i] + "\n"))
		}
		name, arg, _ := strings.Cut(line[i+len(w.prefix):], " ")
		w.emit(token{name: name, arg: arg})
		return
	}
	w.addTail([]byte(line + "\n"))
}

func (w *statusWriter) addTail(b []byte) {
	w.tail = append(w.tail, b...)
	if over := len(w.tail) - w.tailMax; over > 0 {
		w.tail = append(w.tail[:0], w.tail[over:]...)
	}
}

// finish handles an unterminated last line and returns the tail.
func (w *statusWriter) finish() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.line) > 0 {
		w.handleLine()
	}
	return strings.TrimSpace(string(w.tail))
}

// capWriter keeps up to max bytes and calls overflow once when more arrive.
type capWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int64
	over     bool
	overflow func()
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.over {
		return len(p), nil
	}
	if int64(w.buf.Len())+int64(len(p)) > w.max {
		w.over = true
		w.buf.Reset()
		if w.overflow != nil {
			w.overflow()
		}
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

func (w *capWriter) result() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes()), w.over
}

type sessionParams struct {
	nonce     string
	dirs      []string
	memLimit  string
	maxProcs  int
	maxStdout int64
	tailBytes int
	// probe returns the verified probe bytes. unameArch is what the
	// container reported. It is called right before the bytes are sent.
	probe   func(unameArch string) ([]byte, error)
	request []byte
}

type sessionResult struct {
	started   bool
	unameArch string
	noTool    string
	noDir     bool
	short     bool
	// path is the private file announced by WANT (validated).
	path     string
	ready    bool
	pid      string
	exitSeen bool
	exitCode int
	// badToken is set when the container sent an unexpected status line.
	badToken string
	execErr  error
	probeErr error
	stdout   []byte
	overflow bool
	tail     string
	// seq lists the status tokens in the order received.
	seq []string
}

func sessionCommand(p sessionParams) []string {
	cmd := []string{"sh", "-c", collectScript, "bomcensus", p.nonce, p.memLimit, strconv.Itoa(p.maxProcs)}
	return append(cmd, p.dirs...)
}

func expectedPaths(p sessionParams) map[string]bool {
	out := map[string]bool{}
	for _, d := range p.dirs {
		out[strings.TrimSuffix(d, "/")+"/"+probeFileName(p.nonce)] = true
	}
	return out
}

var errSessionClosed = errors.New("session closed")

// eofReader ends the stdin stream with EOF instead of an error when the
// session is torn down, so that the exec transport does not report a copy
// failure for a session that already finished.
type eofReader struct{ r io.Reader }

func (e eofReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, errSessionClosed) {
		err = io.EOF
	}
	return n, err
}

// runSession runs collectScript in the container and drives the stdin
// protocol described there.
func runSession(ctx context.Context, ex Executor, ns, pod, container string, p sessionParams) sessionResult {
	var res sessionResult
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	toks := make(chan token, tokenQueue)
	sw := newStatusWriter(p.nonce, p.tailBytes, func(t token) {
		select {
		case toks <- t:
		default:
		}
	})
	stdout := &capWriter{max: p.maxStdout, overflow: cancel}
	pr, pw := io.Pipe()
	defer pr.CloseWithError(errSessionClosed)
	defer pw.CloseWithError(errSessionClosed)

	execDone := make(chan error, 1)
	go func() {
		execDone <- ex.Exec(sctx, ExecRequest{
			Namespace: ns, Pod: pod, Container: container,
			Command: sessionCommand(p),
			Stdin:   eofReader{pr}, Stdout: stdout, Stderr: sw,
		})
	}()

	allowed := expectedPaths(p)
	readyCh := make(chan struct{})
	readyClosed := false
	sending := false

	handle := func(t token, live bool) {
		res.seq = append(res.seq, t.name)
		switch t.name {
		case tokStart:
			res.started = true
			res.unameArch = strings.TrimSpace(t.arg)
		case tokNoTool:
			res.noTool = strings.TrimSpace(t.arg)
			if !sending {
				pw.Close()
			}
		case tokNoDir:
			res.noDir = true
			if !sending {
				pw.Close()
			}
		case tokShort:
			res.short = true
		case tokWant:
			if !allowed[t.arg] || res.path != "" {
				res.badToken = tokWant + " " + t.arg
				cancel()
				return
			}
			res.path = t.arg
			if !live || sending {
				return
			}
			data, err := p.probe(res.unameArch)
			if err != nil {
				res.probeErr = err
				cancel()
				return
			}
			sending = true
			req := p.request
			go func() {
				hdr := strconv.Itoa(len(data)) + "\n"
				if _, err := io.WriteString(pw, hdr); err != nil {
					return
				}
				if _, err := pw.Write(data); err != nil {
					return
				}
				select {
				case <-readyCh:
				case <-sctx.Done():
					return
				}
				if _, err := pw.Write(req); err != nil {
					return
				}
				pw.Close()
			}()
		case tokReady:
			res.ready = true
			if !readyClosed {
				readyClosed = true
				close(readyCh)
			}
		case tokPID:
			if _, err := strconv.Atoi(t.arg); err == nil {
				res.pid = t.arg
			}
		case tokExit:
			if rc, err := strconv.Atoi(strings.TrimSpace(t.arg)); err == nil {
				res.exitSeen = true
				res.exitCode = rc
			}
		}
	}

loop:
	for {
		select {
		case t := <-toks:
			handle(t, true)
		case err := <-execDone:
			res.execErr = err
			break loop
		}
	}
	res.tail = sw.finish()
	for {
		select {
		case t := <-toks:
			handle(t, false)
			continue
		default:
		}
		break
	}
	res.stdout, res.overflow = stdout.result()
	return res
}
