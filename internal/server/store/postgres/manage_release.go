// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Release file content is stored as rows of mgChunkSize bytes. pgx reads a
// bytea value whole, and large objects would need a transaction held open
// for the length of a download, so fixed-size rows keep both writing and
// reading within one chunk of memory and let a reader fetch one row per
// round trip without a transaction.
const mgChunkSize = 1 << 20

const mgReleaseColumns = `version, manifest, signature, published_at, source, verified, notes, created_at`

func mgScanRelease(r mgRow) (store.Release, error) {
	var rel store.Release
	if err := r.Scan(&rel.Version, &rel.Manifest, &rel.Signature, &rel.PublishedAt, &rel.Source,
		&rel.Verified, &rel.Notes, &rel.CreatedAt); err != nil {
		return store.Release{}, err
	}
	rel.PublishedAt, rel.CreatedAt = rel.PublishedAt.UTC(), rel.CreatedAt.UTC()
	return rel, nil
}

// CreateRelease implements store.Releases.
func (d *DB) CreateRelease(ctx context.Context, r store.Release) (store.Release, error) {
	out, err := mgScanRelease(d.q.QueryRow(ctx, `
		INSERT INTO releases (version, manifest, signature, published_at, source, verified, notes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+mgReleaseColumns,
		r.Version, r.Manifest, r.Signature, r.PublishedAt.UTC(), r.Source, r.Verified, r.Notes,
		mgOrNow(r.CreatedAt)))
	if err != nil {
		return store.Release{}, mgErr("create release", err)
	}
	return out, nil
}

// GetRelease implements store.Releases.
func (d *DB) GetRelease(ctx context.Context, version string) (store.Release, error) {
	r, err := mgScanRelease(d.q.QueryRow(ctx, `SELECT `+mgReleaseColumns+` FROM releases WHERE version = $1`, version))
	if err != nil {
		return store.Release{}, mgErr("get release", err)
	}
	return r, nil
}

// ListReleases implements store.Releases.
func (d *DB) ListReleases(ctx context.Context) ([]store.Release, error) {
	rows, err := d.q.Query(ctx, `SELECT `+mgReleaseColumns+` FROM releases ORDER BY published_at DESC, version DESC`)
	if err != nil {
		return nil, mgErr("list releases", err)
	}
	defer rows.Close()
	out := []store.Release{}
	for rows.Next() {
		r, err := mgScanRelease(rows)
		if err != nil {
			return nil, mgErr("list releases", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list releases", err)
	}
	return out, nil
}

// DeleteRelease implements store.Releases.
func (d *DB) DeleteRelease(ctx context.Context, version string) error {
	tag, err := d.q.Exec(ctx, `DELETE FROM releases WHERE version = $1`, version)
	if err != nil {
		return mgDeleteErr("delete release", err)
	}
	if tag.RowsAffected() == 0 {
		return mgNotFound("delete release")
	}
	return nil
}

// PutReleaseFile implements store.Releases.
func (d *DB) PutReleaseFile(ctx context.Context, f store.ReleaseFile, content io.Reader) (store.ReleaseFile, error) {
	if f.Version == "" || f.OS == "" || f.Arch == "" || f.Name == "" || f.Size < 0 ||
		(f.SHA256 != nil && len(f.SHA256) != sha256.Size) {
		return store.ReleaseFile{}, fmt.Errorf("postgres: put release file: %w", store.ErrInvalid)
	}
	id, err := mgNewID()
	if err != nil {
		return store.ReleaseFile{}, err
	}
	var out store.ReleaseFile
	err = d.mgInTx(ctx, func(tx *DB) error {
		if _, err := tx.q.Exec(ctx, `
			INSERT INTO release_files (id, version, os, arch, name, sha256, size, chunks, created_at)
			VALUES ($1, $2, $3, $4, $5, '', 0, 0, $6)`,
			id, f.Version, f.OS, f.Arch, f.Name, mgNow()); err != nil {
			return mgErr("put release file", err)
		}
		h := sha256.New()
		buf := make([]byte, mgChunkSize)
		var size int64
		seq := 0
		for {
			n, rerr := io.ReadFull(content, buf)
			if n > 0 {
				size += int64(n)
				if size > store.MaxReleaseFileSize {
					return fmt.Errorf("postgres: put release file: larger than %d bytes: %w",
						store.MaxReleaseFileSize, store.ErrInvalid)
				}
				h.Write(buf[:n])
				if _, err := tx.q.Exec(ctx,
					`INSERT INTO release_file_chunks (file_id, seq, data) VALUES ($1, $2, $3)`,
					id, seq, buf[:n]); err != nil {
					return mgErr("put release file chunk", err)
				}
				seq++
			}
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				break
			}
			if rerr != nil {
				return fmt.Errorf("postgres: put release file: read: %w", rerr)
			}
		}
		sum := h.Sum(nil)
		if f.SHA256 != nil && !bytes.Equal(f.SHA256, sum) {
			return fmt.Errorf("postgres: put release file: sha256 mismatch: %w", store.ErrInvalid)
		}
		if f.Size != 0 && f.Size != size {
			return fmt.Errorf("postgres: put release file: size %d, expected %d: %w", size, f.Size, store.ErrInvalid)
		}
		if _, err := tx.q.Exec(ctx,
			`UPDATE release_files SET sha256 = $2, size = $3, chunks = $4 WHERE id = $1`,
			id, sum, size, seq); err != nil {
			return mgErr("put release file", err)
		}
		out = store.ReleaseFile{Version: f.Version, OS: f.OS, Arch: f.Arch, Name: f.Name, SHA256: sum, Size: size}
		return nil
	})
	if err != nil {
		return store.ReleaseFile{}, err
	}
	return out, nil
}

// ListReleaseFiles implements store.Releases.
func (d *DB) ListReleaseFiles(ctx context.Context, version string) ([]store.ReleaseFile, error) {
	rows, err := d.q.Query(ctx, `
		SELECT version, os, arch, name, sha256, size FROM release_files
		WHERE version = $1 ORDER BY os, arch, name`, version)
	if err != nil {
		return nil, mgErr("list release files", err)
	}
	defer rows.Close()
	out := []store.ReleaseFile{}
	for rows.Next() {
		var f store.ReleaseFile
		if err := rows.Scan(&f.Version, &f.OS, &f.Arch, &f.Name, &f.SHA256, &f.Size); err != nil {
			return nil, mgErr("list release files", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list release files", err)
	}
	return out, nil
}

// OpenReleaseFile implements store.Releases.
func (d *DB) OpenReleaseFile(ctx context.Context, version, os, arch, name string) (store.ReleaseFile, io.ReadCloser, error) {
	f := store.ReleaseFile{Version: version, OS: os, Arch: arch, Name: name}
	r := &mgFileReader{ctx: ctx, q: d.q, h: sha256.New()}
	err := d.q.QueryRow(ctx, `
		SELECT id::text, sha256, size, chunks FROM release_files
		WHERE version = $1 AND os = $2 AND arch = $3 AND name = $4`,
		version, os, arch, name).Scan(&r.id, &f.SHA256, &f.Size, &r.chunks)
	if err != nil {
		return store.ReleaseFile{}, nil, mgErr("open release file", err)
	}
	r.size, r.want = f.Size, f.SHA256
	return f, r, nil
}

// mgFileReader reads release file chunks one row at a time. It keeps the
// context of OpenReleaseFile because io.Reader has no context parameter.
type mgFileReader struct {
	ctx    context.Context
	q      querier
	id     string
	chunks int
	size   int64
	want   []byte

	seq  int
	buf  []byte
	read int64
	h    hash.Hash
	err  error
}

func (r *mgFileReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.buf) == 0 {
		if r.seq >= r.chunks {
			r.err = r.finish()
			return 0, r.err
		}
		var data []byte
		err := r.q.QueryRow(r.ctx,
			`SELECT data FROM release_file_chunks WHERE file_id = $1 AND seq = $2`, r.id, r.seq).Scan(&data)
		if err != nil {
			r.err = mgErr("read release file", err)
			return 0, r.err
		}
		r.seq++
		r.read += int64(len(data))
		if r.read > r.size {
			r.err = fmt.Errorf("postgres: read release file: longer than %d bytes", r.size)
			return 0, r.err
		}
		r.h.Write(data)
		r.buf = data
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *mgFileReader) finish() error {
	if r.read != r.size {
		return fmt.Errorf("postgres: read release file: %d bytes, expected %d", r.read, r.size)
	}
	if !bytes.Equal(r.h.Sum(nil), r.want) {
		return errors.New("postgres: read release file: sha256 mismatch")
	}
	return io.EOF
}

// Close implements io.Closer.
func (r *mgFileReader) Close() error {
	if r.err == nil {
		r.err = errors.New("postgres: read release file: closed")
	}
	r.buf = nil
	return nil
}

// GetUpdateSettings implements store.Releases.
func (d *DB) GetUpdateSettings(ctx context.Context) (store.UpdateSettings, error) {
	var s store.UpdateSettings
	var target *string
	err := d.q.QueryRow(ctx, `SELECT target_version, check_interval_minutes FROM update_settings`).
		Scan(&target, &s.CheckIntervalMinutes)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.UpdateSettings{CheckIntervalMinutes: store.DefaultUpdateCheckIntervalMinutes}, nil
	}
	if err != nil {
		return store.UpdateSettings{}, mgErr("get update settings", err)
	}
	s.TargetVersion = mgDeref(target)
	return s, nil
}

// PutUpdateSettings implements store.Releases.
func (d *DB) PutUpdateSettings(ctx context.Context, s store.UpdateSettings) error {
	if s.CheckIntervalMinutes <= 0 {
		return fmt.Errorf("postgres: put update settings: interval %d: %w", s.CheckIntervalMinutes, store.ErrInvalid)
	}
	_, err := d.q.Exec(ctx, `
		INSERT INTO update_settings (id, target_version, check_interval_minutes, updated_at)
		VALUES (true, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET target_version = excluded.target_version,
			check_interval_minutes = excluded.check_interval_minutes, updated_at = excluded.updated_at`,
		mgText(s.TargetVersion), s.CheckIntervalMinutes, mgNow())
	return mgErr("put update settings", err)
}
