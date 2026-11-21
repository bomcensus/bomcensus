// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func mgTestRelease(t *testing.T, db *DB, version string, published time.Time) {
	t.Helper()
	if _, err := db.CreateRelease(context.Background(), store.Release{
		Version: version, Manifest: []byte(`{"version":"` + version + `"}`), Signature: []byte("sig"),
		PublishedAt: published, Source: store.ReleaseUpload, Verified: true, Notes: "notes",
	}); err != nil {
		t.Fatalf("create release: %v", err)
	}
}

func TestManageReleaseFileRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mgTestRelease(t, db, "1.0.0", mgT0)
	mgTestRelease(t, db, "1.1.0", mgT0.Add(time.Hour))

	content := make([]byte, 5*mgChunkSize+12345)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	f, err := db.PutReleaseFile(ctx, store.ReleaseFile{Version: "1.1.0", OS: "linux", Arch: "amd64",
		Name: "bomcensus-agent", SHA256: sum[:], Size: int64(len(content))}, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if f.Size != int64(len(content)) || !bytes.Equal(f.SHA256, sum[:]) {
		t.Fatalf("put result %+v", f)
	}

	got, rc, err := db.OpenReleaseFile(ctx, "1.1.0", "linux", "amd64", "bomcensus-agent")
	if err != nil {
		t.Fatal(err)
	}
	// Read through a small buffer so many reads span chunk boundaries.
	var out bytes.Buffer
	if _, err := io.CopyBuffer(&out, struct{ io.Reader }{rc}, make([]byte, 7919)); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = rc.Close()
	if got.Size != int64(len(content)) || !bytes.Equal(out.Bytes(), content) {
		t.Fatalf("content differs: %d bytes", out.Len())
	}

	// Empty file, size and hash computed by the store.
	if _, err := db.PutReleaseFile(ctx, store.ReleaseFile{Version: "1.1.0", OS: "linux", Arch: "arm64",
		Name: "empty"}, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	_, rc, err = db.OpenReleaseFile(ctx, "1.1.0", "linux", "arm64", "empty")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(rc); err != nil || len(b) != 0 {
		t.Fatalf("empty: %d %v", len(b), err)
	}

	if _, err := db.PutReleaseFile(ctx, store.ReleaseFile{Version: "1.1.0", OS: "linux", Arch: "amd64",
		Name: "bomcensus-agent"}, bytes.NewReader(content)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := db.PutReleaseFile(ctx, store.ReleaseFile{Version: "9.9.9", OS: "linux", Arch: "amd64",
		Name: "x"}, bytes.NewReader(content)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown release: %v", err)
	}
	bad := sha256.Sum256([]byte("other"))
	if _, err := db.PutReleaseFile(ctx, store.ReleaseFile{Version: "1.1.0", OS: "linux", Arch: "amd64",
		Name: "bomcensus-probe", SHA256: bad[:]}, bytes.NewReader(content)); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("hash mismatch: %v", err)
	}
	if _, _, err := db.OpenReleaseFile(ctx, "1.1.0", "linux", "amd64", "bomcensus-probe"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed write left a file: %v", err)
	}

	files, err := db.ListReleaseFiles(ctx, "1.1.0")
	if err != nil || len(files) != 2 || files[0].Name != "bomcensus-agent" || files[1].Arch != "arm64" {
		t.Fatalf("files %+v %v", files, err)
	}

	// Corrupted chunk: the reader must fail instead of returning io.EOF.
	if _, err := db.q.Exec(ctx, `UPDATE release_file_chunks SET data = set_byte(data, 0, (get_byte(data, 0) + 1) % 256)
		WHERE seq = 2 AND file_id = (SELECT id FROM release_files WHERE name = 'bomcensus-agent')`); err != nil {
		t.Fatal(err)
	}
	_, rc, err = db.OpenReleaseFile(ctx, "1.1.0", "linux", "amd64", "bomcensus-agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, rc); err == nil {
		t.Fatal("corruption not detected")
	}

	rels, err := db.ListReleases(ctx)
	if err != nil || len(rels) != 2 || rels[0].Version != "1.1.0" || !rels[0].Verified || rels[0].Source != store.ReleaseUpload {
		t.Fatalf("releases %+v %v", rels, err)
	}
	if _, err := db.CreateRelease(ctx, store.Release{Version: "1.0.0", Manifest: []byte("m"), Signature: []byte("s"),
		PublishedAt: mgT0, Source: store.ReleaseOnline}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate release: %v", err)
	}

	s, err := db.GetUpdateSettings(ctx)
	if err != nil || s.TargetVersion != "" || s.CheckIntervalMinutes != store.DefaultUpdateCheckIntervalMinutes {
		t.Fatalf("default settings %+v %v", s, err)
	}
	if err := db.PutUpdateSettings(ctx, store.UpdateSettings{TargetVersion: "2.0.0", CheckIntervalMinutes: 30}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
	if err := db.PutUpdateSettings(ctx, store.UpdateSettings{TargetVersion: "1.1.0", CheckIntervalMinutes: 0}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("zero interval: %v", err)
	}
	if err := db.PutUpdateSettings(ctx, store.UpdateSettings{TargetVersion: "1.1.0", CheckIntervalMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	if s, _ := db.GetUpdateSettings(ctx); s.TargetVersion != "1.1.0" || s.CheckIntervalMinutes != 30 {
		t.Fatalf("settings %+v", s)
	}
	if err := db.DeleteRelease(ctx, "1.1.0"); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("delete target release: %v", err)
	}
	if err := db.DeleteRelease(ctx, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteRelease(ctx, "1.0.0"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
