// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func mgTestAgent(t *testing.T, db *DB, mutate func(*store.Agent)) store.Agent {
	t.Helper()
	a := store.Agent{
		Kind:        store.AgentKindAgent,
		Hostname:    "host",
		IdentityKey: []byte(uuid.NewString()),
		State:       store.AgentApproved,
		EnrolledAt:  mgT0,
	}
	if mutate != nil {
		mutate(&a)
	}
	out, err := db.CreateAgent(scope.System(context.Background()), a)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	return out
}

func TestManageAgentLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	mgTestKey(t, db, "agentkey000", nil)
	a := mgTestAgent(t, db, func(a *store.Agent) {
		a.RegisterKeyID = "agentkey000"
		a.State = store.AgentPending
		a.Hostname = "web-1"
	})
	if a.ID == "" || a.ApprovedAt != nil || a.ConnectMode != store.ConnectModeConnect || a.TLSMode != store.TLSVerifyPinned {
		t.Fatalf("created %+v", a)
	}
	if _, err := db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: a.IdentityKey,
		State: store.AgentPending}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate identity key: %v", err)
	}
	got, err := db.GetAgentByIdentityKey(ctx, a.IdentityKey)
	if err != nil || got.ID != a.ID || got.RegisterKeyID != "agentkey000" {
		t.Fatalf("by key: %+v %v", got, err)
	}

	if err := db.ApproveAgent(ctx, a.ID, mgT0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveAgent(ctx, a.ID, mgT0.Add(2*time.Minute)); err != nil {
		t.Fatalf("approve twice: %v", err)
	}
	poll := store.AgentPollStatus{
		Hostname: "web-1", Version: "1.2.3", OS: "linux", Arch: "amd64",
		ConnectMode: store.ConnectModeListen, ListenAddress: "10.0.0.1:7443",
		TLSMode: store.TLSVerifySystem, ObservedIssuer: "CN=Proxy", Privilege: store.PrivilegeNonRoot,
		ExecHelper: true, Address: "10.0.0.1", TrustBundleVersion: 3, UpdateState: store.UpdateRolledBack,
		UpdateMessage: "version 0.3.0 was rolled back: no confirmation", SeenAt: mgT0.Add(5 * time.Minute),
	}
	if err := db.UpdateAgentPoll(ctx, a.ID, poll); err != nil {
		t.Fatal(err)
	}
	if err := db.TouchAgent(ctx, a.ID, mgT0); err != nil {
		t.Fatal(err)
	}
	asset := uuid.NewString()
	if err := db.SetAgentAsset(ctx, a.ID, asset); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetAgent(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != store.AgentApproved || got.ApprovedAt == nil || !got.ApprovedAt.Equal(mgT0.Add(time.Minute)) ||
		got.Version != "1.2.3" || got.ConnectMode != store.ConnectModeListen || got.TLSMode != store.TLSVerifySystem ||
		got.ObservedIssuer != "CN=Proxy" || got.Privilege != store.PrivilegeNonRoot || !got.ExecHelper ||
		got.TrustBundleVersion != 3 || got.UpdateState != store.UpdateRolledBack || got.AssetID != asset ||
		got.UpdateMessage != poll.UpdateMessage {
		t.Fatalf("after poll %+v", got)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(poll.SeenAt) {
		t.Fatalf("touch moved last seen back: %v", got.LastSeen)
	}
	if got.Status(mgT0) != store.AgentStatusOnline || got.Status(mgT0.Add(time.Hour)) != store.AgentStatusOffline {
		t.Fatal("status")
	}

	for i, serial := range []string{"01", "02"} {
		if err := db.InsertAgentCert(ctx, store.AgentCert{Serial: serial, AgentID: a.ID,
			NotBefore: mgT0.Add(time.Duration(i) * time.Hour), NotAfter: mgT0.Add(time.Duration(90+i) * 24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertAgentCert(ctx, store.AgentCert{Serial: "01", AgentID: a.ID, NotBefore: mgT0, NotAfter: mgT0}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate serial: %v", err)
	}
	if err := db.InsertAgentCert(ctx, store.AgentCert{Serial: "09", AgentID: uuid.NewString(), NotBefore: mgT0, NotAfter: mgT0}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
	certs, err := db.ListAgentCerts(ctx, a.ID)
	if err != nil || len(certs) != 2 || certs[0].Serial != "02" {
		t.Fatalf("certs %v %v", certs, err)
	}
	got, _ = db.GetAgent(ctx, a.ID)
	if got.CertNotAfter == nil || !got.CertNotAfter.Equal(certs[0].NotAfter) {
		t.Fatalf("cert not after %v", got.CertNotAfter)
	}
	if revoked, err := db.IsAgentCertRevoked(ctx, "01"); err != nil || revoked {
		t.Fatalf("revoked %v %v", revoked, err)
	}
	if revoked, err := db.IsAgentCertRevoked(ctx, "ff"); !errors.Is(err, store.ErrNotFound) || !revoked {
		t.Fatalf("unknown serial %v %v", revoked, err)
	}
	if n, err := db.RevokeAgentCerts(ctx, a.ID, mgT0); err != nil || n != 2 {
		t.Fatalf("revoke certs %d %v", n, err)
	}
	if revoked, _ := db.IsAgentCertRevoked(ctx, "01"); !revoked {
		t.Fatal("cert not revoked")
	}

	if err := db.InsertAgentCert(ctx, store.AgentCert{Serial: "03", AgentID: a.ID, NotBefore: mgT0, NotAfter: mgT0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeAgent(ctx, a.ID, mgT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if revoked, _ := db.IsAgentCertRevoked(ctx, "03"); !revoked {
		t.Fatal("certificate of revoked agent not revoked")
	}
	if err := db.ApproveAgent(ctx, a.ID, mgT0); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("approve revoked: %v", err)
	}
	if err := db.RevokeAgent(ctx, uuid.NewString(), mgT0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
	if _, err := db.GetAgent(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
}

func TestManageAgentCounterSequential(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	a := mgTestAgent(t, db, nil)
	steps := []struct {
		v  uint64
		ok bool
	}{{5, true}, {5, false}, {3, false}, {6, true}, {1 << 40, true}, {0, false}}
	for _, s := range steps {
		ok, err := db.AdvanceAgentCounter(ctx, a.ID, s.v)
		if err != nil || ok != s.ok {
			t.Fatalf("advance %d: %v %v", s.v, ok, err)
		}
	}
	if v, err := db.AgentCounter(ctx, a.ID); err != nil || v != 1<<40 {
		t.Fatalf("counter %d %v", v, err)
	}
	if _, err := db.AdvanceAgentCounter(ctx, uuid.NewString(), 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing agent: %v", err)
	}
	if _, err := db.AdvanceAgentCounter(ctx, a.ID, 1<<63); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("overflow: %v", err)
	}
}

func TestManageAgentCounterConcurrent(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	a := mgTestAgent(t, db, nil)
	const workers, values = 16, 200

	// Every worker offers every value. Each value may be accepted at most
	// once, and a value is accepted only while it exceeds the stored one.
	accepted := make([]int, values+1)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 1; i <= values; i++ {
				v := uint64(i)
				if w%2 == 1 {
					v = uint64(values + 1 - i) // half the workers go downward
				}
				ok, err := db.AdvanceAgentCounter(ctx, a.ID, v)
				if err != nil {
					t.Errorf("advance: %v", err)
					return
				}
				if ok {
					mu.Lock()
					accepted[v]++
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	for v, n := range accepted {
		if n > 1 {
			t.Fatalf("value %d accepted %d times", v, n)
		}
	}
	if accepted[values] != 1 {
		t.Fatal("highest value never accepted")
	}
	if v, _ := db.AgentCounter(ctx, a.ID); v != values {
		t.Fatalf("final counter %d", v)
	}
}

func TestManageAgentListFiltersAndPaging(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	online := mgT0.Add(-time.Minute)
	stale := mgT0.Add(-time.Hour)
	threshold := mgT0.Add(-5 * time.Minute)

	// 12 online agents, 5 offline agents, 3 pending agents, 2 revoked
	// agents, 4 scanners.
	for i := 0; i < 12; i++ {
		mgTestAgent(t, db, func(a *store.Agent) {
			a.Hostname = fmt.Sprintf("app-%02d", i)
			a.LastSeen = &online
			a.Address = fmt.Sprintf("10.0.0.%d", i)
			if i < 3 {
				a.TLSMode = store.TLSVerifyNone
			}
			if i == 4 {
				a.ConnectMode = store.ConnectModeListen
				a.ListenAddress = "edge.example:7443"
			}
		})
	}
	for i := 0; i < 5; i++ {
		mgTestAgent(t, db, func(a *store.Agent) {
			a.Hostname = fmt.Sprintf("dbhost-%02d", i)
			if i > 0 {
				a.LastSeen = &stale
			}
		})
	}
	for i := 0; i < 3; i++ {
		mgTestAgent(t, db, func(a *store.Agent) { a.Hostname = fmt.Sprintf("new-%d", i); a.State = store.AgentPending })
	}
	for i := 0; i < 2; i++ {
		a := mgTestAgent(t, db, func(a *store.Agent) {
			a.Hostname = fmt.Sprintf("old-%d", i)
			a.TLSMode = store.TLSVerifySystem
		})
		if err := db.RevokeAgent(ctx, a.ID, mgT0); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		mgTestAgent(t, db, func(a *store.Agent) {
			a.Kind = store.AgentKindScanner
			a.Hostname = fmt.Sprintf("scan-%d", i)
			a.LastSeen = &online
		})
	}

	count := func(f store.AgentFilter) int {
		t.Helper()
		f.OnlineAfter = threshold
		_, total, err := db.ListAgents(ctx, f, store.Page{})
		if err != nil {
			t.Fatal(err)
		}
		return total
	}
	cases := []struct {
		name string
		f    store.AgentFilter
		want int
	}{
		{"all", store.AgentFilter{}, 26},
		{"agents", store.AgentFilter{Kind: store.AgentKindAgent}, 22},
		{"scanners", store.AgentFilter{Kind: store.AgentKindScanner}, 4},
		{"online", store.AgentFilter{Kind: store.AgentKindAgent, Status: store.AgentStatusOnline}, 12},
		{"offline", store.AgentFilter{Status: store.AgentStatusOffline}, 5},
		{"pending", store.AgentFilter{Status: store.AgentStatusPendingApproval}, 3},
		{"revoked", store.AgentFilter{Status: store.AgentStatusRevoked}, 2},
		{"tls none", store.AgentFilter{TLSMode: store.TLSVerifyNone}, 3},
		{"listen", store.AgentFilter{ConnectMode: store.ConnectModeListen}, 1},
		{"q hostname", store.AgentFilter{Q: "DBHOST-"}, 5},
		{"q address", store.AgentFilter{Q: "10.0.0.1"}, 3}, // .1, .10, .11
		{"q listen address", store.AgentFilter{Q: "edge.example"}, 1},
		{"combined", store.AgentFilter{Status: store.AgentStatusOnline, TLSMode: store.TLSVerifyNone, Q: "app-0"}, 3},
		{"unknown status", store.AgentFilter{Status: "bogus"}, 0},
	}
	for _, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}

	f := store.AgentFilter{Kind: store.AgentKindAgent, Status: store.AgentStatusOnline, OnlineAfter: threshold}
	var seen []string
	for off := 0; off < 12; off += 5 {
		page, total, err := db.ListAgents(ctx, f, store.Page{Limit: 5, Offset: off})
		if err != nil || total != 12 {
			t.Fatalf("page %d: total %d %v", off, total, err)
		}
		for _, a := range page {
			seen = append(seen, a.Hostname)
		}
	}
	if len(seen) != 12 || seen[0] != "app-00" || seen[11] != "app-11" {
		t.Fatalf("pages %v", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i-1] >= seen[i] {
			t.Fatalf("not sorted: %v", seen)
		}
	}
	page, total, err := db.ListAgents(ctx, f, store.Page{Limit: 5, Offset: 100})
	if err != nil || total != 12 || len(page) != 0 {
		t.Fatalf("past end: %d %d %v", len(page), total, err)
	}
	f.Sort = "-hostname"
	page, _, err = db.ListAgents(ctx, f, store.Page{Limit: 1})
	if err != nil || page[0].Hostname != "app-11" {
		t.Fatalf("desc: %v %v", page, err)
	}
	f.Sort = "secret"
	if _, _, err := db.ListAgents(ctx, f, store.Page{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad sort: %v", err)
	}

	if _, err := db.BumpTrustBundleVersion(ctx); err != nil {
		t.Fatal(err)
	}
	c, err := db.CountAgents(ctx, threshold)
	if err != nil {
		t.Fatal(err)
	}
	want := store.AgentCounts{Online: 16, Offline: 5, PendingApproval: 3, Revoked: 2, NotPinned: 3, TrustBundleBehind: 21}
	if c != want {
		t.Fatalf("counts %+v, want %+v", c, want)
	}
}
