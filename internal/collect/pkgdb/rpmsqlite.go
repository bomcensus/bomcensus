// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"context"
	"database/sql"
	"encoding/binary"
	"io"
	"net/url"
	"os"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

var sqliteMagic = []byte("SQLite format 3\x00")

// eachSQLite reads the Packages table of rpmdb.sqlite. The database is opened
// read-only and immutable: SQLite then takes no locks and never creates or
// removes the -wal and -shm files next to it. The price is that changes still
// in the write-ahead log are not seen; walPending detects that case.
func eachSQLite(ctx context.Context, real string, fn func([]byte) bool) (skipped int, err error) {
	u := url.URL{Scheme: "file", Path: real, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.QueryContext(ctx,
		`SELECT CASE WHEN length(blob) <= ? THEN blob END FROM Packages`, maxBlob)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return skipped, err
		}
		if blob == nil {
			skipped++
			continue
		}
		if !fn(blob) {
			return skipped, nil
		}
	}
	return skipped, rows.Err()
}

// walPending reports whether the write-ahead log of an SQLite database holds
// frames that are not yet copied into the main file. It compares the last
// valid frame with the backfill mark in the shared-memory index; when the
// index is missing but the log is not empty the answer is "pending".
func walPending(real string) bool {
	fi, err := os.Stat(real + "-wal")
	if err != nil || fi.Size() <= 32 {
		return false
	}
	f, err := os.Open(real + "-shm")
	if err != nil {
		return true
	}
	defer f.Close()
	b := make([]byte, 136)
	if _, err := io.ReadFull(f, b); err != nil {
		return true
	}
	// The index is in native byte order; probes run on little-endian hosts.
	le := binary.LittleEndian
	if b[12] == 0 { // isInit
		return true
	}
	mxFrame := le.Uint32(b[16:20])
	nBackfill := le.Uint32(b[96:100])
	return mxFrame != nBackfill
}

func isSQLite(r io.ReaderAt) bool {
	b := make([]byte, len(sqliteMagic))
	if _, err := r.ReadAt(b, 0); err != nil {
		return false
	}
	return string(b) == string(sqliteMagic)
}
