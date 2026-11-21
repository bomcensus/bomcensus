// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package container

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/bomcensus/bomcensus/internal/collect"
	"github.com/bomcensus/bomcensus/internal/report"
)

// Fixtures under testdata/<name>/ hold a root tree (root/) and a proc tree
// (proc/) copied from real runtimes:
//
//	docker-overlay2     Docker 29.10.0, graph driver overlay2 (docker:dind)
//	docker-snapshotter  Docker 29.10.0, containerd image store, data-root /srv/docker
//	k3s                 k3s v1.34.1+k3s1, containerd v2.1.4-k3s2 with CRI
//
// bbolt databases are stored as JSON (*.bolt.json, nested objects are
// buckets, {"$hex": …} is a binary value) and rebuilt by the test.

const boltJSONSuffix = ".bolt.json"

// fixture lays out the named fixtures in one temporary root and proc tree.
func fixture(t *testing.T, names ...string) (root, proc string) {
	t.Helper()
	dir := t.TempDir()
	root = filepath.Join(dir, "root")
	proc = filepath.Join(dir, "proc")
	for _, d := range []string{root, proc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range names {
		copyTree(t, filepath.Join("testdata", name, "root"), root)
		copyTree(t, filepath.Join("testdata", name, "proc"), proc)
	}
	return root, proc
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		if strings.HasSuffix(p, boltJSONSuffix) {
			buildBolt(t, p, strings.TrimSuffix(out, boltJSONSuffix))
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func buildBolt(t *testing.T, jsonPath, dbPath string) {
	t.Helper()
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatalf("%s: %v", jsonPath, err)
	}
	db, err := bolt.Open(dbPath, 0o644, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		for name, v := range tree {
			b, err := tx.CreateBucket([]byte(name))
			if err != nil {
				return err
			}
			if err := fillBucket(b, v.(map[string]any)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%s: %v", jsonPath, err)
	}
}

func fillBucket(b *bolt.Bucket, m map[string]any) error {
	for k, v := range m {
		switch v := v.(type) {
		case string:
			if err := b.Put([]byte(k), []byte(v)); err != nil {
				return err
			}
		case map[string]any:
			if h, ok := v["$hex"].(string); ok && len(v) == 1 {
				raw, err := hex.DecodeString(h)
				if err != nil {
					return err
				}
				if err := b.Put([]byte(k), raw); err != nil {
					return err
				}
				continue
			}
			nb, err := b.CreateBucket([]byte(k))
			if err != nil {
				return err
			}
			if err := fillBucket(nb, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func testEnv(root, proc string) *collect.Env {
	return &collect.Env{
		Root:   root,
		Proc:   proc,
		Policy: report.DefaultPolicy(),
		Cache:  collect.NewHashCache(),
		Log:    slog.New(slog.DiscardHandler),
	}
}
