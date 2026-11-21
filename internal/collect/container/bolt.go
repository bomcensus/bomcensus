// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package container

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// maxBoltSize bounds the size of a runtime database copied into memory.
const maxBoltSize = 256 << 20

// boltAttempts is how often a copy is taken when the database was committed
// to while it was being copied. Attempts are spaced by boltBackoff times the
// attempt number, so that a burst of commits can pass.
const (
	boltAttempts = 5
	boltBackoff  = 20 * time.Millisecond
)

const boltMagic = 0xED0CDAED

var errBoltChanged = errors.New("database changed during every copy attempt")

// openBoltCopy opens a consistent in-memory copy of a bbolt database.
//
// containerd holds an exclusive flock on its databases while it runs, so a
// read-only bbolt open of the file blocks until containerd exits. Instead the
// file is copied into an anonymous memory file (memfd) and bbolt opens that.
// Nothing is written to disk and the runtime is not disturbed.
//
// bbolt is copy-on-write and every commit rewrites one of the two meta pages
// last. The copy starts with the meta pages; if they still equal the file's
// meta pages after the copy, no commit completed in between, and the pages
// reachable from the newest meta page were not reused (a writer only reuses
// pages that the newest committed tree no longer references). Otherwise the
// copy is retried.
//
// The caller closes the returned database.
func openBoltCopy(path string) (*bolt.DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lastErr error = errBoltChanged
	for attempt := range boltAttempts {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * boltBackoff)
		}
		mf, err := copyToMemfd(f)
		if err != nil {
			return nil, err
		}
		ok, err := metaUnchanged(f, mf)
		if err != nil {
			mf.Close()
			return nil, err
		}
		if !ok {
			mf.Close()
			continue
		}
		db, err := bolt.Open(path, 0, &bolt.Options{
			ReadOnly: true,
			Timeout:  time.Second,
			OpenFile: func(string, int, os.FileMode) (*os.File, error) { return mf, nil },
		})
		if err != nil {
			// bolt.Open closes the file on failure.
			lastErr = err
			continue
		}
		return db, nil
	}
	return nil, lastErr
}

func copyToMemfd(f *os.File) (*os.File, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxBoltSize {
		return nil, fmt.Errorf("database is larger than %d MiB", maxBoltSize>>20)
	}
	fd, err := unix.MemfdCreate("bomcensus-bolt", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create memory file: %w", err)
	}
	mf := os.NewFile(uintptr(fd), f.Name())
	n, err := io.Copy(mf, io.NewSectionReader(f, 0, maxBoltSize+1))
	if err == nil && n > maxBoltSize {
		err = fmt.Errorf("database is larger than %d MiB", maxBoltSize>>20)
	}
	if err != nil {
		mf.Close()
		return nil, err
	}
	return mf, nil
}

// metaUnchanged compares the two meta pages of the copy with the file as it
// is now.
func metaUnchanged(f, copied *os.File) (bool, error) {
	hdr := make([]byte, 32)
	if _, err := copied.ReadAt(hdr, 0); err != nil {
		return false, fmt.Errorf("read meta page: %w", err)
	}
	// Page header (16 bytes), then the meta: magic, version, page size.
	if binary.LittleEndian.Uint32(hdr[16:]) != boltMagic {
		return false, errors.New("not a bbolt database")
	}
	pageSize := int(binary.LittleEndian.Uint32(hdr[24:]))
	if pageSize < 512 || pageSize > 1<<16 {
		return false, fmt.Errorf("invalid page size %d", pageSize)
	}
	a := make([]byte, 2*pageSize)
	b := make([]byte, 2*pageSize)
	if _, err := copied.ReadAt(a, 0); err != nil {
		return false, fmt.Errorf("read meta pages: %w", err)
	}
	if _, err := f.ReadAt(b, 0); err != nil {
		return false, fmt.Errorf("read meta pages: %w", err)
	}
	return bytes.Equal(a, b), nil
}

// boltView runs fn in a read transaction and turns a panic from a damaged
// database into an error.
func boltView(db *bolt.DB, fn func(tx *bolt.Tx) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("damaged database: %v", r)
		}
	}()
	return db.View(fn)
}

// bucketPath descends from the root through nested buckets.
func bucketPath(tx *bolt.Tx, names ...string) *bolt.Bucket {
	if len(names) == 0 {
		return nil
	}
	b := tx.Bucket([]byte(names[0]))
	for _, n := range names[1:] {
		if b == nil {
			return nil
		}
		b = b.Bucket([]byte(n))
	}
	return b
}

func bucketString(b *bolt.Bucket, key string) string {
	if b == nil {
		return ""
	}
	return string(b.Get([]byte(key)))
}

// bucketStrings returns the string values of a bucket, skipping nested
// buckets.
func bucketStrings(b *bolt.Bucket) map[string]string {
	if b == nil {
		return nil
	}
	m := map[string]string{}
	_ = b.ForEach(func(k, v []byte) error {
		if v != nil {
			m[string(k)] = string(v)
		}
		return nil
	})
	return m
}
