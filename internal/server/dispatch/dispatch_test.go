// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package dispatch

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestWaitNotify(t *testing.T) {
	s := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := s.Wait(ctx, "a"), s.Wait(ctx, "b")
	s.Notify("a")
	select {
	case <-a:
	case <-time.After(time.Second):
		t.Fatal("a not woken")
	}
	select {
	case <-b:
		t.Fatal("b woken")
	default:
	}

	// A cancelled wait is dropped.
	wctx, wcancel := context.WithCancel(context.Background())
	s.Wait(wctx, "c")
	wcancel()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.waiters["c"])
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled waiter kept")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	var d dto.Directive
	full := true
	if err := d.FromCollectDirective(dto.CollectDirective{Id: "ignored", Sections: []dto.SectionName{"host"}, Full: &full}); err != nil {
		t.Fatal(err)
	}
	p, err := Payload(d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil || m["id"] != nil || m["type"] != "collect" {
		t.Fatalf("payload %s", p)
	}
	out, err := Deliverable(store.Directive{ID: "d-1", Type: "collect", Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	c, err := out.AsCollectDirective()
	if err != nil || c.Id != "d-1" || c.Type != dto.Collect || len(c.Sections) != 1 || c.Full == nil || !*c.Full {
		t.Fatalf("deliverable %+v %v", c, err)
	}
}
