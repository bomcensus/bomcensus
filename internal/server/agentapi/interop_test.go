// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/server/scope"
)

// TestAgentCoreInterop runs the agent runtime with the HTTP channel against
// the server's handler stack: enrollment, the recovery of an interrupted
// key change, polls, a report upload, a renewal and a trust bundle sync.
func TestAgentCoreInterop(t *testing.T) {
	e := newEnv(t, envOpts{pollTimeout: 300 * time.Millisecond})
	tok := e.newKey(t, nil)
	ctx, cancel := context.WithTimeout(scope.System(context.Background()), time.Minute)
	defer cancel()

	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enr, err := core.Enroll(ctx, core.EnrollOptions{
		State: dir, Version: "1.0.0", Token: tok.String(), ServerURL: e.url, ServerName: testServerName,
		Host: dto.HostFacts{Hostname: "interop-1", Arch: "amd64", Os: dto.OsRelease{Family: "linux"}},
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if enr.Status != state.StatusApproved || enr.AgentID == "" {
		t.Fatalf("enrollment %+v", enr)
	}

	// A key change the server never saw: the renewal signed with the new
	// key is refused as unauthenticated, and the key is dropped.
	nk, err := pki.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveNextKey(nk); err != nil {
		t.Fatal(err)
	}

	rt, err := core.New(core.Options{State: dir, Version: "1.0.0", PollTimeout: 5 * time.Second, MinPollInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	polled := make(chan struct{}, 16)
	rt.OnPoll(func(context.Context) {
		select {
		case polled <- struct{}{}:
		default:
		}
	})
	rctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- rt.Run(rctx) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()
	select {
	case <-polled:
	case <-ctx.Done():
		t.Fatal("no poll")
	}

	if k, err := dir.LoadNextKey(); err != nil || k != nil {
		t.Fatalf("next key after recovery: %v %v", k != nil, err)
	}

	a, err := e.db.GetAgent(ctx, enr.AgentID)
	if err != nil || a.Version != "1.0.0" || a.Hostname != "interop-1" {
		t.Fatalf("agent after poll: %+v %v", a, err)
	}

	raw := []byte("\x28\xb5\x2f\xfd interop report")
	if err := rt.SubmitReport(ctx, raw, core.ReportMeta{JobID: "j-1"}); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := e.ingest.all(); len(got) != 1 || got[0].sender.ID != enr.AgentID || got[0].jobID != "j-1" || !bytes.Equal(got[0].raw, raw) {
		t.Fatalf("ingest got %+v", got)
	}

	oldCert := rt.Certificate()
	if err := rt.RenewCert(ctx, false); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if rt.Certificate() == nil || rt.Certificate().Equal(oldCert) {
		t.Fatal("certificate not renewed")
	}
	if err := rt.SyncTrustBundle(ctx); err != nil {
		t.Fatalf("trust bundle: %v", err)
	}
	for range 2 {
		select {
		case <-polled:
		case <-ctx.Done():
			t.Fatal("no poll after the renewal")
		}
	}
}
