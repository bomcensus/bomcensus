// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package detectorsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

type memStore struct {
	mu   sync.Mutex
	revs []store.DetectorTableRevision
	gets int
}

func (m *memStore) LatestDetectorTable(context.Context) (store.DetectorTableRevision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if len(m.revs) == 0 {
		return store.DetectorTableRevision{}, store.ErrNotFound
	}
	return m.revs[len(m.revs)-1], nil
}

func (m *memStore) GetDetectorTable(_ context.Context, id int64) (store.DetectorTableRevision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.revs {
		if r.ID == id {
			return r, nil
		}
	}
	return store.DetectorTableRevision{}, store.ErrNotFound
}

func (m *memStore) AddDetectorTable(_ context.Context, r store.DetectorTableRevision) (store.DetectorTableRevision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.ID = int64(len(m.revs) + 1)
	m.revs = append(m.revs, r)
	return r, nil
}

func (m *memStore) ListDetectorTables(context.Context, int) ([]store.DetectorTableRevision, error) {
	return nil, nil
}

func (m *memStore) DetectorTableUsage(context.Context) ([]store.DetectorTableUsage, error) {
	return nil, nil
}

const small = "schema_version: 1\ndetectors:\n  - id: acme\n    name: acme\n    names: [acmed]\n" +
	"    static:\n      - rules:\n          - pattern: 'acme (\\d+\\.\\d+)'\n"

func TestDefaults(t *testing.T) {
	st := &memStore{}
	s, err := New(Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	def, src := s.Default()
	if src != "built-in" || def.Digest != detectors.BuiltinDigest() {
		t.Fatalf("default %s %s", src, def.Digest)
	}

	// The chart's file.
	file := filepath.Join(t.TempDir(), "detectors.yaml")
	if err := os.WriteFile(file, []byte(small), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err = New(Config{Store: st, DefaultFile: file})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Effective(context.Background())
	if err != nil || e.Custom || len(e.Table.Table.Detectors) != 1 || e.YAML != small {
		t.Fatalf("file default %+v %v", e, err)
	}
	// A broken or missing file stops the server.
	if err := os.WriteFile(file, []byte(strings.Replace(small, "(\\d+", "\\d+", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Store: st, DefaultFile: file}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("broken file: %v", err)
	}
	if _, err := New(Config{Store: st, DefaultFile: file + ".missing"}); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestSaveResetAndCache(t *testing.T) {
	st := &memStore{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s, err := New(Config{Store: st, TTL: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, probs, err := s.Save(ctx, []byte(strings.Replace(small, "rules:", "file: '/etc/shadow'\n        rules:", 1)), "a"); !errors.Is(err, ErrInvalid) || len(probs) == 0 {
		t.Fatalf("invalid save: %v %+v", err, probs)
	}
	if len(st.revs) != 0 {
		t.Fatal("invalid table stored")
	}
	e, _, err := s.Save(ctx, []byte(small), "alice")
	if err != nil || !e.Custom || e.Revision != 1 || e.UpdatedBy != "alice" || len(e.Table.Table.Detectors) != 1 {
		t.Fatalf("save %+v %v", e, err)
	}
	digest, raw, err := s.Current(ctx)
	if err != nil || digest != e.Digest || len(raw) == 0 {
		t.Fatalf("current %s %v", digest, err)
	}
	if tb := s.ForProbe(); tb == nil || tb.Detectors[0].ID != "acme" {
		t.Fatalf("for probe %+v", tb)
	}

	// Another replica's edit is seen after the TTL.
	gets := st.gets
	st.AddDetectorTable(ctx, store.DetectorTableRevision{Reset: true})
	if e, _ := s.Effective(ctx); !e.Custom || st.gets != gets {
		t.Fatal("cache not used")
	}
	now = now.Add(2 * time.Minute)
	if e, _ := s.Effective(ctx); e.Custom || e.Digest != detectors.BuiltinDigest() {
		t.Fatalf("after TTL %+v", e)
	}

	// A stored table this server cannot use falls back to the default.
	st.AddDetectorTable(ctx, store.DetectorTableRevision{YAML: "schema_version: 9\n", Digest: "x"})
	now = now.Add(2 * time.Minute)
	if e, err := s.Effective(ctx); err != nil || e.Custom || e.Digest != detectors.BuiltinDigest() || e.Revision != 3 {
		t.Fatalf("unusable stored table %+v %v", e, err)
	}

	e, err = s.Reset(ctx, "bob")
	if err != nil || e.Custom || e.UpdatedBy != "" && e.UpdatedBy != "bob" {
		t.Fatalf("reset %+v %v", e, err)
	}
}
