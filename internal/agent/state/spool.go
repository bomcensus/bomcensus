// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DefaultSpoolMax bounds the total size of spooled reports.
const DefaultSpoolMax = 256 << 20

// ErrTooLarge is returned by Spool.Put for an entry larger than the spool.
var ErrTooLarge = errors.New("state: entry is larger than the spool limit")

const (
	spoolDataExt = ".report"
	spoolMetaExt = ".meta"
)

// Spool holds encoded reports that could not be uploaded yet, oldest
// first. Each entry has opaque metadata stored next to it.
type Spool struct {
	dir string
	max int64

	mu  sync.Mutex
	seq uint64
}

// SpoolEntry is one spooled report.
type SpoolEntry struct {
	Name string
	Size int64
	Meta []byte
}

// Spool opens the report spool. max <= 0 selects DefaultSpoolMax.
func (d *Dir) Spool(max int64) (*Spool, error) {
	if max <= 0 {
		max = DefaultSpoolMax
	}
	dir := filepath.Join(d.path, spoolName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: create spool: %w", err)
	}
	s := &Spool{dir: dir, max: max}
	entries, err := s.list()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if n, _ := parseSeq(e.Name); n > s.seq {
			s.seq = n
		}
	}
	return s, nil
}

func parseSeq(name string) (uint64, bool) {
	base, ok := strings.CutSuffix(name, spoolDataExt)
	if !ok || len(base) != 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(base, 10, 64)
	return n, err == nil
}

// Put adds an entry, dropping the oldest entries while the total would
// exceed the limit. It returns the names of dropped entries.
func (s *Spool) Put(data, meta []byte) (dropped []string, err error) {
	if int64(len(data)+len(meta)) > s.max {
		return nil, ErrTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.list()
	if err != nil {
		return nil, err
	}
	var total int64
	for _, e := range entries {
		total += e.Size + int64(len(e.Meta))
	}
	for len(entries) > 0 && total+int64(len(data)+len(meta)) > s.max {
		e := entries[0]
		entries = entries[1:]
		if err := s.remove(e.Name); err != nil {
			return dropped, err
		}
		total -= e.Size + int64(len(e.Meta))
		dropped = append(dropped, e.Name)
	}
	s.seq++
	base := fmt.Sprintf("%020d", s.seq)
	// The metadata goes first: a report without metadata is still sent,
	// metadata without a report is ignored and cleaned up.
	if err := WriteFileAtomic(filepath.Join(s.dir, base+spoolMetaExt), meta, 0o600); err != nil {
		return dropped, err
	}
	if err := WriteFileAtomic(filepath.Join(s.dir, base+spoolDataExt), data, 0o600); err != nil {
		os.Remove(filepath.Join(s.dir, base+spoolMetaExt))
		return dropped, err
	}
	return dropped, nil
}

// List returns the entries, oldest first.
func (s *Spool) List() ([]SpoolEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list()
}

func (s *Spool) list() ([]SpoolEntry, error) {
	des, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("state: read spool: %w", err)
	}
	have := map[string]bool{}
	var out []SpoolEntry
	for _, de := range des {
		name := de.Name()
		if _, ok := parseSeq(name); ok && de.Type().IsRegular() {
			fi, err := de.Info()
			if err != nil {
				continue
			}
			e := SpoolEntry{Name: name, Size: fi.Size()}
			if m, err := os.ReadFile(filepath.Join(s.dir, strings.TrimSuffix(name, spoolDataExt)+spoolMetaExt)); err == nil {
				e.Meta = m
			}
			have[strings.TrimSuffix(name, spoolDataExt)] = true
			out = append(out, e)
		}
	}
	for _, de := range des {
		if base, ok := strings.CutSuffix(de.Name(), spoolMetaExt); ok && !have[base] {
			os.Remove(filepath.Join(s.dir, de.Name()))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Read returns the data of an entry.
func (s *Spool) Read(name string) ([]byte, error) {
	if _, ok := parseSeq(name); !ok {
		return nil, fmt.Errorf("state: invalid spool entry %q", name)
	}
	return os.ReadFile(filepath.Join(s.dir, name))
}

// Remove deletes an entry and its metadata.
func (s *Spool) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remove(name)
}

func (s *Spool) remove(name string) error {
	if _, ok := parseSeq(name); !ok {
		return fmt.Errorf("state: invalid spool entry %q", name)
	}
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: remove spool entry: %w", err)
	}
	if err := os.Remove(filepath.Join(s.dir, strings.TrimSuffix(name, spoolDataExt)+spoolMetaExt)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: remove spool entry: %w", err)
	}
	return syncDir(s.dir)
}
