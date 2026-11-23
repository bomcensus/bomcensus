// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestCache(clk *clock, raw json.RawMessage) *HashCache {
	c := NewHashCache()
	c.now = clk.now
	c.load(raw)
	return c
}

func tempFile(t *testing.T, name, data string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func hash(t *testing.T, c *HashCache, f *os.File) {
	t.Helper()
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SHA256File(f); err != nil {
		t.Fatal(err)
	}
}

func entries(t *testing.T, raw json.RawMessage) int {
	t.Helper()
	var doc cacheDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var files []json.RawMessage
	if err := json.Unmarshal(doc.Files, &files); err != nil {
		t.Fatal(err)
	}
	return len(files)
}

// A run that uses only some entries keeps the others until the retention
// has passed since their last use.
func TestHashCacheRetention(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	a, b := tempFile(t, "a", "a"), tempFile(t, "b", "b")

	c := newTestCache(clk, nil)
	hash(t, c, a)
	hash(t, c, b)
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Runs that use only a, until b's retention is over.
	for _, d := range []time.Duration{time.Hour, fileRetention} {
		clk.t = time.Unix(1_800_000_000, 0).Add(d)
		c = newTestCache(clk, raw)
		hash(t, c, a)
		if raw, err = c.Marshal(); err != nil {
			t.Fatal(err)
		}
		if n := entries(t, raw); n != 2 {
			t.Fatalf("after %s: %d entries, want 2", d, n)
		}
	}
	clk.t = clk.t.Add(time.Second)
	c = newTestCache(clk, raw)
	hash(t, c, a)
	if raw, err = c.Marshal(); err != nil {
		t.Fatal(err)
	}
	if n := entries(t, raw); n != 1 {
		t.Fatalf("after the retention: %d entries, want 1", n)
	}
}

// The list written by earlier probes is read, and its entries are kept.
func TestHashCacheFormat1(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	f := tempFile(t, "a", "a")
	key, ok := keyOfFile(f, mustStat(t, f))
	if !ok {
		t.Fatal("no key")
	}
	const fake = "f00d"
	old, _ := json.Marshal([]*cacheEntry{{Key: key, SHA256: fake}})
	c := newTestCache(clk, old)
	if got, err := c.SHA256File(f); err != nil || got != fake {
		t.Fatalf("hash = %q, %v; want the cached value", got, err)
	}
	c = newTestCache(clk, old)
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if n := entries(t, raw); n != 1 {
		t.Errorf("unused format 1 entry dropped: %s", raw)
	}
}

func mustStat(t *testing.T, f *os.File) os.FileInfo {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func TestHashCacheValues(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c := newTestCache(clk, nil)
	c.SetValue("k", map[string]int{"n": 1}, time.Hour)
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	clk.t = clk.t.Add(time.Hour - time.Second)
	c = newTestCache(clk, raw)
	var got map[string]int
	if !c.Value("k", &got) || got["n"] != 1 {
		t.Fatalf("value = %v", got)
	}
	// Values outlive runs that do not read them.
	if raw, err = c.Marshal(); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Second)
	c = newTestCache(clk, raw)
	if c.Value("k", &got) {
		t.Error("expired value returned")
	}
	if raw, _ = c.Marshal(); len(c.values) != 0 {
		t.Errorf("expired value kept: %s", raw)
	}
}

// Over the budget, the entries used longest ago are left out.
func TestHashCacheBudget(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	a, b := tempFile(t, "a", "a"), tempFile(t, "b", "b")
	c := newTestCache(clk, nil)
	hash(t, c, a)
	raw, _ := c.Marshal()
	clk.t = clk.t.Add(time.Hour)
	c = newTestCache(clk, raw)
	hash(t, c, b)

	full, err := c.marshal(1 << 20)
	if err != nil || entries(t, full) != 2 {
		t.Fatalf("full = %s, %v", full, err)
	}
	small, err := c.marshal(200)
	if err != nil {
		t.Fatal(err)
	}
	if entries(t, small) != 1 {
		t.Fatalf("budget not applied: %s", small)
	}
	c = newTestCache(clk, small)
	key, _ := keyOf(mustStat(t, b))
	if c.entries[key] == nil {
		t.Errorf("the recently used entry was dropped: %s", small)
	}
}
