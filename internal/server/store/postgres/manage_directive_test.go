// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestManageDirectiveQueue(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := mgTestAgent(t, db, nil)
	b := mgTestAgent(t, db, nil)
	payload := json.RawMessage(`{"type":"collect","sections":[]}`)

	d1, created, err := db.EnqueueDirective(ctx, store.Directive{AgentID: a.ID, Type: "collect", Payload: payload,
		DedupeKey: "collect", CreatedAt: mgT0})
	if err != nil || !created || d1.ID == "" || d1.DedupeKey != "collect" {
		t.Fatalf("enqueue: %+v %v %v", d1, created, err)
	}
	// Same key while pending: deduplicated.
	d1b, created, err := db.EnqueueDirective(ctx, store.Directive{AgentID: a.ID, Type: "collect", Payload: payload,
		DedupeKey: "collect", CreatedAt: mgT0.Add(time.Second)})
	if err != nil || created || d1b.ID != d1.ID {
		t.Fatalf("dedupe: %+v %v %v", d1b, created, err)
	}
	// Same key for another agent is independent.
	if _, created, err := db.EnqueueDirective(ctx, store.Directive{AgentID: b.ID, Type: "collect", Payload: payload,
		DedupeKey: "collect", CreatedAt: mgT0}); err != nil || !created {
		t.Fatalf("other agent: %v %v", created, err)
	}
	exp := mgT0.Add(time.Hour)
	d2, _, err := db.EnqueueDirective(ctx, store.Directive{AgentID: a.ID, Type: "k8s_sync", Payload: payload,
		CreatedAt: mgT0.Add(2 * time.Second), ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.EnqueueDirective(ctx, store.Directive{AgentID: uuid.NewString(), Type: "collect", Payload: payload}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
	if _, _, err := db.EnqueueDirective(ctx, store.Directive{AgentID: a.ID, Type: "collect", Payload: json.RawMessage(`[]`)}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("non-object payload: %v", err)
	}

	pending, err := db.ListPendingDirectives(ctx, a.ID, mgT0.Add(time.Minute), 0)
	if err != nil || len(pending) != 2 || pending[0].ID != d1.ID || pending[1].ID != d2.ID {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	if pending[0].Type != "collect" || !json.Valid(pending[0].Payload) {
		t.Fatalf("pending[0]: %+v", pending[0])
	}
	if l, _ := db.ListPendingDirectives(ctx, a.ID, mgT0.Add(time.Minute), 1); len(l) != 1 {
		t.Fatalf("limit: %d", len(l))
	}

	// Delivered but unacknowledged directives are delivered again.
	if err := db.MarkDirectivesDelivered(ctx, a.ID, []string{d1.ID, d2.ID, "not-a-uuid"}, mgT0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	pending, _ = db.ListPendingDirectives(ctx, a.ID, mgT0.Add(time.Minute), 0)
	if len(pending) != 2 || pending[0].DeliveredAt == nil {
		t.Fatalf("redelivery: %+v", pending)
	}

	// Acknowledgements of other agents' directives are ignored.
	if n, err := db.AckDirectives(ctx, b.ID, []string{d1.ID}, mgT0.Add(2*time.Minute)); err != nil || n != 0 {
		t.Fatalf("foreign ack: %d %v", n, err)
	}
	if n, err := db.AckDirectives(ctx, a.ID, []string{d1.ID, "x", d1.ID}, mgT0.Add(2*time.Minute)); err != nil || n != 1 {
		t.Fatalf("ack: %d %v", n, err)
	}
	if n, _ := db.AckDirectives(ctx, a.ID, []string{d1.ID}, mgT0.Add(3*time.Minute)); n != 0 {
		t.Fatalf("second ack counted %d", n)
	}
	pending, _ = db.ListPendingDirectives(ctx, a.ID, mgT0.Add(time.Minute), 0)
	if len(pending) != 1 || pending[0].ID != d2.ID {
		t.Fatalf("after ack: %+v", pending)
	}
	// After the ack the dedupe key is free again.
	d3, created, err := db.EnqueueDirective(ctx, store.Directive{AgentID: a.ID, Type: "collect", Payload: payload,
		DedupeKey: "collect", CreatedAt: mgT0.Add(3 * time.Minute)})
	if err != nil || !created || d3.ID == d1.ID {
		t.Fatalf("enqueue after ack: %v %v", created, err)
	}

	// Expired directives are not pending and do not block their key.
	if l, _ := db.ListPendingDirectives(ctx, a.ID, exp, 0); len(l) != 1 || l[0].ID != d3.ID {
		t.Fatalf("expired still pending: %+v", l)
	}
	short := mgT0.Add(4 * time.Minute)
	d4, _, err := db.EnqueueDirective(ctx, store.Directive{AgentID: b.ID, Type: "k8s_exec", Payload: payload,
		DedupeKey: "exec", CreatedAt: mgT0, ExpiresAt: &short})
	if err != nil {
		t.Fatal(err)
	}
	d5, created, err := db.EnqueueDirective(ctx, store.Directive{AgentID: b.ID, Type: "k8s_exec", Payload: payload,
		DedupeKey: "exec", CreatedAt: short.Add(time.Second)})
	if err != nil || !created || d5.ID == d4.ID {
		t.Fatalf("key of expired directive: %v %v", created, err)
	}

	n, err := db.DeleteExpiredDirectives(ctx, exp, mgT0.Add(2*time.Minute))
	if err != nil || n != 2 { // d2 expired, d1 acknowledged
		t.Fatalf("delete expired: %d %v", n, err)
	}
	if l, _ := db.ListPendingDirectives(ctx, a.ID, mgT0, 0); len(l) != 1 || l[0].ID != d3.ID {
		t.Fatalf("after delete: %+v", l)
	}
}

func TestManageAgentEnrollment(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := mgTestAgent(t, db, nil)
	if _, err := db.GetAgentEnrollment(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	e := store.AgentEnrollment{AgentID: a.ID, CSR: []byte{1, 2, 3}, AllowRelaxedTLS: true,
		DefaultGroup: "web", DefaultTags: []string{"prod", "eu"}, CreatedAt: mgT0}
	if err := db.PutAgentEnrollment(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAgentEnrollment(ctx, a.ID)
	if err != nil || string(got.CSR) != "\x01\x02\x03" || !got.AllowRelaxedTLS || got.DefaultGroup != "web" ||
		len(got.DefaultTags) != 2 || !got.CreatedAt.Equal(mgT0) {
		t.Fatalf("get: %+v %v", got, err)
	}
	e.CSR, e.DefaultTags, e.AllowRelaxedTLS = []byte{4}, nil, false
	if err := db.PutAgentEnrollment(ctx, e); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetAgentEnrollment(ctx, a.ID); len(got.CSR) != 1 || got.AllowRelaxedTLS || got.DefaultTags == nil || len(got.DefaultTags) != 0 {
		t.Fatalf("replaced: %+v", got)
	}
	if err := db.PutAgentEnrollment(ctx, store.AgentEnrollment{AgentID: uuid.NewString(), CSR: []byte{1}}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
}
