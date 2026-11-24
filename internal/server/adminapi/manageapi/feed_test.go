// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"strings"
	"testing"

	"github.com/bomcensus/feed-protocol/instancekey"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
)

func TestFeedServers(t *testing.T) {
	e := newEnv(t, false)

	in := decode[gen.FeedInstance](t, e.do("GET", "/feed-instance", nil))
	if !strings.HasPrefix(in.InstanceId, "x25519 ") {
		t.Fatalf("instance %+v", in)
	}
	if again := decode[gen.FeedInstance](t, e.do("GET", "/feed-instance", nil)); again.InstanceId != in.InstanceId {
		t.Fatal("instance key changed")
	}

	list := decode[gen.FeedServerList](t, e.do("GET", "/feed-servers", nil))
	if list.Total != 1 {
		t.Fatalf("list %+v", list)
	}
	builtin := list.Items[0]
	if !builtin.Builtin || !builtin.Active || builtin.Url != "https://feed.bomcensus.com" || !builtin.Telemetry ||
		builtin.ServerKey != nil || builtin.Status != gen.FeedServerStatusNever {
		t.Fatalf("built-in %+v", builtin)
	}

	for _, body := range []gen.FeedServerCreate{
		{Name: "x", Url: "http://feed.corp.example"},
		{Name: "x", Url: "https://feed.corp.example/?a=b"},
		{Name: " ", Url: "https://feed.corp.example"},
	} {
		e.want(e.do("POST", "/feed-servers", body), 400, apierr.CodeInvalidArgument)
	}
	r := e.do("POST", "/feed-servers", gen.FeedServerCreate{Name: " mirror ", Url: "https://Feed.Corp.Example/"})
	e.want(r, 201, "")
	mirror := decode[gen.FeedServer](t, r)
	if mirror.Name != "mirror" || mirror.Url != "https://feed.corp.example" || mirror.Active || !mirror.Telemetry {
		t.Fatalf("created %+v", mirror)
	}
	e.want(e.do("POST", "/feed-servers", gen.FeedServerCreate{Name: "dup", Url: "https://feed.corp.example"}), 409, apierr.CodeConflict)

	// Activation moves to the mirror; the built-in can then be disabled
	// but never removed.
	e.want(e.do("PATCH", "/feed-servers/"+mirror.Id, map[string]any{"active": false}), 400, apierr.CodeInvalidArgument)
	up := decode[gen.FeedServer](t, e.do("PATCH", "/feed-servers/"+mirror.Id, map[string]any{"active": true, "telemetry": false}))
	if !up.Active || up.Telemetry {
		t.Fatalf("activated %+v", up)
	}
	e.want(e.do("PATCH", "/feed-servers/"+mirror.Id, map[string]any{"enabled": false}), 409, CodeFeedActive)
	e.want(e.do("DELETE", "/feed-servers/"+mirror.Id, nil), 409, CodeFeedActive)
	off := decode[gen.FeedServer](t, e.do("PATCH", "/feed-servers/"+builtin.Id, map[string]any{"enabled": false}))
	if off.Enabled || off.Active {
		t.Fatalf("built-in disabled %+v", off)
	}
	e.want(e.do("DELETE", "/feed-servers/"+builtin.Id, nil), 409, CodeFeedBuiltin)
	// Enabling and activating in one request works.
	if on := decode[gen.FeedServer](t, e.do("PATCH", "/feed-servers/"+builtin.Id, map[string]any{"enabled": true, "active": true})); !on.Active || !on.Enabled {
		t.Fatalf("built-in re-activated %+v", on)
	}
	e.want(e.do("PATCH", "/feed-servers/"+mirror.Id, map[string]any{"enabled": false}), 200, "")
	e.want(e.do("PATCH", "/feed-servers/"+mirror.Id, map[string]any{"active": true}), 409, CodeFeedDisabled)

	// A failed test is reported in the server's state.
	r = e.do("POST", "/feed-servers", gen.FeedServerCreate{Name: "down", Url: "http://127.0.0.1:1"})
	e.want(r, 201, "")
	down := decode[gen.FeedServer](t, r)
	tested := decode[gen.FeedServer](t, e.do("POST", "/feed-servers/"+down.Id+"/test", nil))
	if tested.Status != gen.FeedServerStatusError || deref(tested.LastError) == "" {
		t.Fatalf("tested %+v", tested)
	}
	e.want(e.do("POST", "/feed-servers/00000000-0000-0000-0000-000000000000/test", nil), 404, apierr.CodeNotFound)

	// Trusting a key needs the key the server presented.
	ctx := context.Background()
	k1, _ := instancekey.Generate(nil)
	k2, _ := instancekey.Generate(nil)
	if _, err := e.db.TrustFeedServerKey(ctx, mirror.Id, k1.Public().String()); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("POST", "/feed-servers/"+mirror.Id+"/trust-key", gen.FeedServerTrustKey{Key: k2.Public().String()}), 409, CodeFeedKeyMissing)
	if err := e.db.RecordFeedServerKeyChange(ctx, mirror.Id, k2.Public().String()); err != nil {
		t.Fatal(err)
	}
	changed := decode[gen.FeedServerList](t, e.do("GET", "/feed-servers", nil))
	for _, s := range changed.Items {
		if s.Id == mirror.Id && (s.Status != gen.FeedServerStatusKeyChanged || deref(s.PresentedKey) != k2.Public().String()) {
			t.Fatalf("key changed %+v", s)
		}
	}
	e.want(e.do("POST", "/feed-servers/"+mirror.Id+"/trust-key", gen.FeedServerTrustKey{Key: "x25519 nope"}), 400, apierr.CodeInvalidArgument)
	e.want(e.do("POST", "/feed-servers/"+mirror.Id+"/trust-key", gen.FeedServerTrustKey{Key: k1.Public().String()}), 409, CodeFeedKeyMissing)
	trusted := decode[gen.FeedServer](t, e.do("POST", "/feed-servers/"+mirror.Id+"/trust-key", gen.FeedServerTrustKey{Key: k2.Public().String()}))
	if deref(trusted.ServerKey) != k2.Public().String() || trusted.PresentedKey != nil || trusted.Status != gen.FeedServerStatusNever {
		t.Fatalf("trusted %+v", trusted)
	}

	e.want(e.do("DELETE", "/feed-servers/"+mirror.Id, nil), 204, "")
	e.want(e.do("DELETE", "/feed-servers/"+mirror.Id, nil), 404, apierr.CodeNotFound)
}

