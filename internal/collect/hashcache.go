// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// MaxHashSize is the largest file the collectors hash.
const MaxHashSize = 1 << 30

// fileKey identifies file contents without reading them.
type fileKey struct {
	Dev   uint64 `json:"d"`
	Ino   uint64 `json:"i"`
	Size  int64  `json:"s"`
	Mtime int64  `json:"m"`
	Ctime int64  `json:"c"`
}

type cacheEntry struct {
	Key    fileKey `json:"k"`
	SHA256 string  `json:"h"`
	// Extra holds collector-specific results keyed by name, for example the
	// output of a version command for this exact file.
	Extra map[string]json.RawMessage `json:"x,omitempty"`
}

// HashCache remembers the SHA-256 of files by (dev, inode, size, mtime, ctime).
// The probe cannot write to disk, so the cache travels in the report and comes
// back in the next request.
type HashCache struct {
	mu      sync.Mutex
	entries map[fileKey]*cacheEntry
	touched map[fileKey]bool
}

func NewHashCache() *HashCache {
	return &HashCache{entries: map[fileKey]*cacheEntry{}, touched: map[fileKey]bool{}}
}

// LoadHashCache restores a cache produced by Marshal. A nil or malformed
// input yields an empty cache.
func LoadHashCache(raw json.RawMessage) *HashCache {
	c := NewHashCache()
	var list []*cacheEntry
	if len(raw) == 0 || json.Unmarshal(raw, &list) != nil {
		return c
	}
	for _, e := range list {
		if e != nil {
			c.entries[e.Key] = e
		}
	}
	return c
}

// Marshal returns the entries that were used during this run, so that entries
// for files that no longer exist are dropped.
func (c *HashCache) Marshal() (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := make([]*cacheEntry, 0, len(c.touched))
	for k := range c.touched {
		if e := c.entries[k]; e != nil {
			list = append(list, e)
		}
	}
	return json.Marshal(list)
}

// SHA256File returns the hex SHA-256 of an open file, using the cache when the
// file is unchanged. The file is read from its current offset.
func (c *HashCache) SHA256File(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("collect: %s is not a regular file", f.Name())
	}
	if fi.Size() > MaxHashSize {
		return "", fmt.Errorf("collect: %s is larger than %d bytes", f.Name(), int64(MaxHashSize))
	}
	key, keyed := keyOfFile(f, fi)
	if keyed {
		c.mu.Lock()
		e := c.entries[key]
		if e != nil {
			c.touched[key] = true
		}
		c.mu.Unlock()
		if e != nil && e.SHA256 != "" {
			return e.SHA256, nil
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxHashSize)); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if keyed {
		c.mu.Lock()
		e := c.entries[key]
		if e == nil {
			e = &cacheEntry{Key: key}
			c.entries[key] = e
		}
		e.SHA256 = sum
		c.touched[key] = true
		c.mu.Unlock()
	}
	return sum, nil
}

// Extra returns a collector-specific value stored for this exact file.
func (c *HashCache) Extra(fi os.FileInfo, name string, out any) bool {
	key, ok := keyOf(fi)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return false
	}
	raw, ok := e.Extra[name]
	if !ok {
		return false
	}
	c.touched[key] = true
	return json.Unmarshal(raw, out) == nil
}

// SetExtra stores a collector-specific value for this exact file.
func (c *HashCache) SetExtra(fi os.FileInfo, name string, value any) {
	key, ok := keyOf(fi)
	if !ok {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		e = &cacheEntry{Key: key}
		c.entries[key] = e
	}
	if e.Extra == nil {
		e.Extra = map[string]json.RawMessage{}
	}
	e.Extra[name] = raw
	c.touched[key] = true
}
