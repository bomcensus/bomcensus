// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

type ctxKey int

const (
	infoKey ctxKey = iota
	targetKey
)

// requestInfo carries the connection facts of a request and the agent
// record loaded while verifying its signature.
type requestInfo struct {
	remote     netip.Addr
	reverse    bool
	unenrolled bool
	target     *reverseTarget

	mu     sync.Mutex
	loaded *store.Agent
}

func withRequestInfo(ctx context.Context, i *requestInfo) context.Context {
	return context.WithValue(ctx, infoKey, i)
}

// requestInfoFrom never returns nil.
func requestInfoFrom(ctx context.Context) *requestInfo {
	if i, ok := ctx.Value(infoKey).(*requestInfo); ok {
		return i
	}
	return &requestInfo{}
}

func (i *requestInfo) setAgent(a store.Agent) {
	i.mu.Lock()
	i.loaded = &a
	i.mu.Unlock()
}

func (i *requestInfo) agent() (store.Agent, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.loaded == nil {
		return store.Agent{}, false
	}
	return *i.loaded, true
}

func withReverseTarget(ctx context.Context, t *reverseTarget) context.Context {
	return context.WithValue(ctx, targetKey, t)
}

func reverseTargetFrom(ctx context.Context) *reverseTarget {
	t, _ := ctx.Value(targetKey).(*reverseTarget)
	return t
}

// remoteAddr parses an http.Request RemoteAddr.
func remoteAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func jsonError(code, msg string) []byte {
	b, _ := json.Marshal(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, msg})
	return append(b, '\n')
}
