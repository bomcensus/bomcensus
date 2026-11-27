// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

func TestManageAgentListUpdateFilters(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	seen := mgT0
	mk := func(host, version string, us store.UpdateState, state store.AgentState) store.Agent {
		return mgTestAgent(t, db, func(a *store.Agent) {
			a.Hostname, a.Version, a.UpdateState, a.State = host, version, us, state
			if state == store.AgentApproved {
				a.LastSeen = &seen
			}
		})
	}
	mk("current", "2.0.0", store.UpdateUpToDate, store.AgentApproved)
	mk("behind", "1.0.0", store.UpdateUpToDate, store.AgentApproved)
	mk("updating", "2.0.0", store.UpdateUpdating, store.AgentApproved)
	mk("waiting", "", store.UpdateUpToDate, store.AgentPending)
	gone := mk("gone", "1.0.0", store.UpdateUpToDate, store.AgentApproved)
	if err := db.RevokeAgent(ctx, gone.ID, mgT0); err != nil {
		t.Fatal(err)
	}

	hosts := func(f store.AgentFilter) string {
		t.Helper()
		f.OnlineAfter = mgT0.Add(-time.Minute)
		page, total, err := db.ListAgents(ctx, f, store.Page{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range page {
			out = append(out, a.Hostname)
		}
		if total != len(out) {
			t.Fatalf("total %d for %d rows", total, len(out))
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		name string
		f    store.AgentFilter
		want string
	}{
		{"outdated without target", store.AgentFilter{Outdated: true}, "updating"},
		{"outdated with target", store.AgentFilter{Outdated: true, TargetVersion: "2.0.0"}, "behind,updating,waiting"},
		{"update state", store.AgentFilter{UpdateState: store.UpdateUpdating}, "updating"},
		{"version", store.AgentFilter{Version: "1.0.0"}, "behind,gone"},
		{"status sort", store.AgentFilter{Sort: "status"}, "behind,current,updating,waiting,gone"},
		{"status sort desc", store.AgentFilter{Sort: "-status"}, "gone,waiting,behind,current,updating"},
		{"update state sort", store.AgentFilter{Sort: "-update_state", Version: "2.0.0"}, "updating,current"},
	} {
		if got := hosts(c.f); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestManageRegisterKeyListState(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	soon := mgT0.Add(time.Hour)
	mgTestKey(t, db, "stateopen00", func(k *store.RegisterKey) { k.Name = "open" })
	mgTestKey(t, db, "stateshort0", func(k *store.RegisterKey) { k.Name = "short"; k.ExpiresAt = &soon })
	mgTestKey(t, db, "stateonce00", func(k *store.RegisterKey) { k.Name = "once"; k.MaxUses = 1 })
	mgTestKey(t, db, "stategone00", func(k *store.RegisterKey) { k.Name = "gone" })
	if _, err := db.ConsumeRegisterKey(ctx, "stateonce00", mgT0); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeRegisterKey(ctx, "stategone00", mgT0); err != nil {
		t.Fatal(err)
	}
	names := func(f store.RegisterKeyFilter) string {
		t.Helper()
		page, _, err := db.ListRegisterKeys(ctx, f, store.Page{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, k := range page {
			out = append(out, k.Name)
		}
		return strings.Join(out, ",")
	}
	later := mgT0.Add(2 * time.Hour)
	for _, c := range []struct {
		name string
		f    store.RegisterKeyFilter
		want string
	}{
		{"valid before expiry", store.RegisterKeyFilter{State: "valid", Now: mgT0, Sort: "name"}, "open,short"},
		{"valid after expiry", store.RegisterKeyFilter{State: "valid", Now: later}, "open"},
		{"expired", store.RegisterKeyFilter{State: "expired", Now: later}, "short"},
		{"exhausted", store.RegisterKeyFilter{State: "exhausted", Now: later}, "once"},
		{"state sort", store.RegisterKeyFilter{Sort: "state", Now: later}, "open,once,short,gone"},
		{"state sort desc", store.RegisterKeyFilter{Sort: "-state", Now: later}, "gone,short,once,open"},
		{"expires sort", store.RegisterKeyFilter{Sort: "-expiresAt"}, "short,gone,once,open"},
		{"expires sort asc", store.RegisterKeyFilter{Sort: "expiresAt", Q: "short"}, "short"},
	} {
		if got := names(c.f); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	if _, _, err := db.ListRegisterKeys(ctx, store.RegisterKeyFilter{State: "bogus"}, store.Page{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad state: %v", err)
	}
	if _, _, err := db.ListRegisterKeys(ctx, store.RegisterKeyFilter{Sort: "secret"}, store.Page{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad sort: %v", err)
	}
}

func TestManageListenTargetList(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	a := mgTestAgent(t, db, func(a *store.Agent) { a.Hostname = "Edge-Node" })
	b := mgTestAgent(t, db, func(a *store.Agent) { a.Hostname = "alpha" })
	var ids []string
	for _, addr := range []string{"c.example:1", "a.example:1", "b.example:1"} {
		lt, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: addr})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, lt.ID)
	}
	if err := db.BindListenTargetAgent(ctx, ids[0], a.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.BindListenTargetAgent(ctx, ids[2], b.ID); err != nil {
		t.Fatal(err)
	}
	list := func(f store.ListenTargetFilter, p store.Page) (string, int) {
		t.Helper()
		page, total, err := db.ListListenTargets(ctx, f, p)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, lt := range page {
			out = append(out, lt.Address+"="+lt.AgentHostname)
		}
		return strings.Join(out, ","), total
	}
	for _, c := range []struct {
		name  string
		f     store.ListenTargetFilter
		p     store.Page
		want  string
		total int
	}{
		{"default", store.ListenTargetFilter{}, store.Page{}, "a.example:1=,b.example:1=alpha,c.example:1=Edge-Node", 3},
		{"q hostname", store.ListenTargetFilter{Q: "edge"}, store.Page{}, "c.example:1=Edge-Node", 1},
		{"q address", store.ListenTargetFilter{Q: "B.EX"}, store.Page{}, "b.example:1=alpha", 1},
		{"agent sort", store.ListenTargetFilter{Sort: "-agent"}, store.Page{Limit: 2}, "c.example:1=Edge-Node,b.example:1=alpha", 3},
		{"agent ids", store.ListenTargetFilter{AgentIDs: []string{a.ID}}, store.Page{}, "c.example:1=Edge-Node", 1},
		{"no agent ids", store.ListenTargetFilter{AgentIDs: []string{}}, store.Page{}, "", 0},
		{"state", store.ListenTargetFilter{State: store.ListenNew}, store.Page{Offset: 2}, "c.example:1=Edge-Node", 3},
		{"other state", store.ListenTargetFilter{State: store.ListenConnected}, store.Page{}, "", 0},
	} {
		if got, total := list(c.f, c.p); got != c.want || total != c.total {
			t.Errorf("%s: got %s (%d), want %s (%d)", c.name, got, total, c.want, c.total)
		}
	}
}

func TestManageScanTargetListFilters(t *testing.T) {
	db := newTestDB(t)
	ctx := scope.System(context.Background())
	cred, err := db.CreateCredential(ctx, store.Credential{Name: "c", Kind: store.CredentialSSHPassword, Username: "u", Secret: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	scanner := mgTestAgent(t, db, func(a *store.Agent) { a.Kind = store.AgentKindScanner })
	mk := func(name string, scannerID string) store.ScanTarget {
		st, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: name, Address: name + ".example", Port: 22,
			CredentialID: cred.ID, ScannerID: scannerID})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	mk("never", "")
	ok := mk("ok", scanner.ID)
	bad := mk("bad", "")
	if err := db.RecordScanRun(ctx, ok.ID, store.ScanRun{At: mgT0, Result: store.ScanOK}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordScanRun(ctx, bad.ID, store.ScanRun{At: mgT0.Add(time.Minute), Result: store.ScanFailed}); err != nil {
		t.Fatal(err)
	}
	names := func(f store.ScanTargetFilter) string {
		t.Helper()
		page, _, err := db.ListScanTargets(ctx, f, store.Page{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, st := range page {
			out = append(out, st.Name)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		name string
		f    store.ScanTargetFilter
		want string
	}{
		{"default", store.ScanTargetFilter{}, "bad,never,ok"},
		{"scanner", store.ScanTargetFilter{ScannerID: scanner.ID}, "ok"},
		{"credential", store.ScanTargetFilter{CredentialID: cred.ID, Sort: "-name"}, "ok,never,bad"},
		{"last result", store.ScanTargetFilter{LastResult: store.ScanFailed}, "bad"},
		{"last run", store.ScanTargetFilter{Sort: "lastRun"}, "never,ok,bad"},
		{"last run desc", store.ScanTargetFilter{Sort: "-lastRun"}, "bad,ok,never"},
	} {
		if got := names(c.f); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
