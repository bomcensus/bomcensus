// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package container

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestBoltCopyWhileWritten opens copies of a database that another handle
// holds open for writing (as containerd does) and commits to without pause.
// Every copy that opens must show one committed state: all values intact and
// the counter equal to the number of keys written with it. Without the meta
// page comparison in openBoltCopy this test finds torn copies.
func TestBoltCopyWhileWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	// NoSync makes commits fast, so that many land while a copy is taken.
	w, err := bolt.Open(path, 0o644, &bolt.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(stop)
		wg.Wait()
		w.Close()
	}()

	// A plain read-only open waits for the writer's exclusive lock.
	if _, err := bolt.Open(path, 0, &bolt.Options{ReadOnly: true, Timeout: 50 * time.Millisecond}); err == nil {
		t.Fatal("read-only open succeeded while the writer holds the lock")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := uint64(1); ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			err := w.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucketIfNotExists([]byte("v1"))
				if err != nil {
					return err
				}
				fill := bytes.Repeat([]byte{byte(n)}, 600)
				if err := b.Put([]byte(fmt.Sprintf("key-%08d", n)), fill); err != nil {
					return err
				}
				// Rewrite older keys so that freed pages get reused.
				for i := uint64(1); i <= 8 && i < n; i++ {
					if err := b.Put([]byte(fmt.Sprintf("key-%08d", (n*7919+i)%(n-1)+1)), fill); err != nil {
						return err
					}
				}
				return b.Put([]byte("count"), binary.BigEndian.AppendUint64(nil, n))
			})
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()

	opened, raced := 0, 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		db, err := openBoltCopy(path)
		if err != nil {
			// Every attempt raced with a commit. Allowed: the collector
			// then reports partial coverage.
			raced++
			continue
		}
		err = boltView(db, func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("v1"))
			if b == nil {
				return nil
			}
			want := binary.BigEndian.Uint64(b.Get([]byte("count")))
			keys := uint64(0)
			if err := b.ForEach(func(k, v []byte) error {
				if string(k) == "count" {
					return nil
				}
				keys++
				if len(v) != 600 || bytes.Count(v, v[:1]) != len(v) {
					return fmt.Errorf("torn value under %s", k)
				}
				return nil
			}); err != nil {
				return err
			}
			if keys != want {
				return fmt.Errorf("count %d, keys %d", want, keys)
			}
			return nil
		})
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		opened++
	}
	if opened == 0 {
		t.Fatalf("no copy could be opened (%d raced)", raced)
	}
	t.Logf("%d copies opened, %d gave up after %d attempts", opened, raced, boltAttempts)
}

func TestBoltCopyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	if err := os.WriteFile(path, make([]byte, 8192), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openBoltCopy(path); err == nil {
		t.Fatal("opened a file that is not a database")
	}
}
