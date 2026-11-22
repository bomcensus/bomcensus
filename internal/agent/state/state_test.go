// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomcensus/bomcensus/internal/pki"
)

func open(t *testing.T, dir string) *Dir {
	t.Helper()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestOpenLocksAndTightensMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	d := open(t, dir)
	checkPrivateDir(t, dir)
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v", err)
	}
	d.Close()
	d2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d2.Close()
}

func TestCounterNeverReuses(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	var seen []uint64
	for round := 0; round < 3; round++ {
		d := open(t, dir)
		c, err := d.Counter(4)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 6; i++ {
			n, err := c.Next(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(seen) > 0 && n <= seen[len(seen)-1] {
				t.Fatalf("counter %d after %d", n, seen[len(seen)-1])
			}
			if n > c.Reserved() {
				t.Fatalf("counter %d handed out above the reserved %d", n, c.Reserved())
			}
			seen = append(seen, n)
		}
		d.Close()
	}
}

func TestCounterObserve(t *testing.T) {
	d := open(t, t.TempDir())
	c, err := d.Counter(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Observe(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	n, err := c.Next(ctx)
	if err != nil || n != 1001 {
		t.Fatalf("Next = %d, %v", n, err)
	}
	b, err := d.ReadFile(counterName)
	if err != nil || string(bytes.TrimSpace(b)) != "1064" {
		t.Fatalf("stored %q, %v", b, err)
	}
	_ = c.Observe(ctx, 5)
	if n, _ := c.Next(ctx); n != 1002 {
		t.Fatalf("Observe lowered the counter: %d", n)
	}
}

func TestDamagedCounterRefused(t *testing.T) {
	d := open(t, t.TempDir())
	if err := d.WriteFile(counterName, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Counter(0); err == nil {
		t.Fatal("damaged counter accepted")
	}
}

func TestSpoolOrderAndLimit(t *testing.T) {
	d := open(t, t.TempDir())
	s, err := d.Spool(100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		dropped, err := s.Put(bytes.Repeat([]byte{byte('a' + i)}, 30), []byte{byte('0' + i)})
		if err != nil {
			t.Fatal(err)
		}
		if i < 3 && len(dropped) != 0 {
			t.Fatalf("entry %d dropped %v", i, dropped)
		}
		if i == 3 && len(dropped) != 1 {
			t.Fatalf("entry 3 dropped %v", dropped)
		}
	}
	if _, err := s.Put(make([]byte, 101), nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized entry: %v", err)
	}
	// Reopening continues the sequence.
	s2, err := d.Spool(100)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := s2.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || string(entries[0].Meta) != "1" || string(entries[2].Meta) != "3" {
		t.Fatalf("entries %+v", entries)
	}
	data, err := s2.Read(entries[0].Name)
	if err != nil || data[0] != 'b' {
		t.Fatalf("oldest = %q, %v", data, err)
	}
	if err := s2.Remove(entries[0].Name); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Put([]byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	entries, _ = s2.List()
	if len(entries) != 3 || entries[2].Name <= entries[1].Name {
		t.Fatalf("order after reopen: %+v", entries)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	d := open(t, t.TempDir())
	key, err := pki.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SaveIdentity(&Identity{Key: key}); err != nil {
		t.Fatal(err)
	}
	id, err := d.LoadIdentity()
	if err != nil || !id.Key.Equal(key) || id.Cert != nil {
		t.Fatalf("identity %+v, %v", id, err)
	}
	checkPrivateFile(t, filepath.Join(d.Path(), identityName))
	des, _ := os.ReadDir(d.Path())
	for _, de := range des {
		if de.Name()[0] == '.' {
			t.Fatalf("temporary file left: %s", de.Name())
		}
	}
	if _, err := d.LoadEnrollment(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("LoadEnrollment = %v", err)
	}
}
