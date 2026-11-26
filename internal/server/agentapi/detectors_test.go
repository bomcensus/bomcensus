// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/bomcensus/bomcensus/agentproto/dto"
	"github.com/bomcensus/bomcensus/server/scope"
)

type fakeDetectors struct {
	mu     sync.Mutex
	digest string
	table  []byte
}

func (f *fakeDetectors) Current(context.Context) (string, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.digest, f.table, nil
}

func (f *fakeDetectors) set(digest, table string) {
	f.mu.Lock()
	f.digest, f.table = digest, []byte(table)
	f.mu.Unlock()
}

// TestPollDetectorTable: the configuration announces the digest; the table
// goes only to agents that report another digest, never to agents that do
// not report one (older versions). The reported digest is stored.
func TestPollDetectorTable(t *testing.T) {
	d1, d2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	fd := &fakeDetectors{}
	fd.set(d1, `{"schema_version":1,"detectors":[]}`+"\n")
	e := newEnv(t, envOpts{detectors: fd})
	c := enrolledAgent(t, e)
	ctx := scope.System(context.Background())
	poll := func(held *string) dto.PollResult {
		t.Helper()
		var req dto.PollRequest
		if err := json.Unmarshal(c.pollBody(t, nil, 1), &req); err != nil {
			t.Fatal(err)
		}
		req.DetectorsDigest = held
		b, _ := json.Marshal(req)
		resp, body, err := c.do(t, http.MethodPost, "/agent/v1/poll", b)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("poll: %v %v %s", resp, err, body)
		}
		var res dto.PollResult
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	stored := func() *string {
		t.Helper()
		a, err := e.db.GetAgent(ctx, c.id)
		if err != nil {
			t.Fatal(err)
		}
		return a.DetectorsDigest
	}

	// An agent that does not take tables.
	res := poll(nil)
	if res.Config.DetectorsDigest == nil || *res.Config.DetectorsDigest != d1 || res.Detectors != nil || stored() != nil {
		t.Fatalf("old agent: %+v %+v", res.Config.DetectorsDigest, res.Detectors)
	}
	// An agent without a table gets it.
	empty := ""
	res = poll(&empty)
	if res.Detectors == nil || res.Detectors.Digest != d1 || !bytes.Equal(res.Detectors.Table, []byte(`{"schema_version":1,"detectors":[]}`+"\n")) {
		t.Fatalf("new agent: %+v", res.Detectors)
	}
	if s := stored(); s == nil || *s != "" {
		t.Fatalf("stored %v", s)
	}
	// Up to date: no table.
	if res = poll(&d1); res.Detectors != nil {
		t.Fatalf("up to date: %+v", res.Detectors)
	}
	if s := stored(); s == nil || *s != d1 {
		t.Fatalf("stored %v", s)
	}
	// The table changed.
	fd.set(d2, `{"schema_version":1,"detectors":[{"id":"x"}]}`+"\n")
	if res = poll(&d1); res.Detectors == nil || res.Detectors.Digest != d2 || *res.Config.DetectorsDigest != d2 {
		t.Fatalf("changed: %+v", res.Detectors)
	}
	// A malformed digest is stored as none.
	bad := "not a digest"
	poll(&bad)
	if s := stored(); s == nil || *s != "" {
		t.Fatalf("stored %v", s)
	}
}

// TestPollWithoutDetectorTables: a server without the service announces
// nothing, as before.
func TestPollWithoutDetectorTables(t *testing.T) {
	e := newEnv(t, envOpts{})
	c := enrolledAgent(t, e)
	res := c.poll(t, nil)
	if res.Config.DetectorsDigest != nil || res.Detectors != nil {
		t.Fatalf("detectors without the service: %+v %+v", res.Config.DetectorsDigest, res.Detectors)
	}
}
