// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package collect

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// MaxHashSize is the largest file the collectors hash.
const MaxHashSize = 1 << 30

const (
	// cacheFormat is the version of the marshaled cache. Format 1 was a bare
	// list of file entries without use times; it is still read.
	cacheFormat = 2
	// fileRetention is how long a file entry that no run used is kept. Runs
	// that collect only some sections use only some entries: the processes
	// section runs every few minutes and touches the running executables,
	// the artifacts section runs daily and touches every executable and
	// archive. The retention must outlast the longest section interval.
	fileRetention = 14 * 24 * time.Hour
	// maxCacheBytes bounds the marshaled cache. The cache comes back in the
	// next request, which the probe limits to 64 MiB.
	maxCacheBytes = 32 << 20
	// maxValueBytes bounds one value stored with SetValue.
	maxValueBytes = 8 << 20
)

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
	// Used is the time of the last run that used the entry, in Unix seconds.
	Used int64 `json:"u,omitempty"`
}

// valueEntry is a value that belongs to no single file.
type valueEntry struct {
	Key string `json:"k"`
	// Expires is the end of the value's lifetime, in Unix seconds.
	Expires int64           `json:"e"`
	Value   json.RawMessage `json:"v"`
}

type cacheDoc struct {
	Version int             `json:"v"`
	Files   json.RawMessage `json:"files"`
	Values  []*valueEntry   `json:"values,omitempty"`
}

// HashCache remembers the SHA-256 of files by (dev, inode, size, mtime, ctime),
// and collector results for those files and for keys of their own. The probe
// cannot write to disk, so the cache travels in the report and comes back in
// the next request.
type HashCache struct {
	mu      sync.Mutex
	entries map[fileKey]*cacheEntry
	touched map[fileKey]bool
	values  map[string]*valueEntry
	now     func() time.Time
}

func NewHashCache() *HashCache {
	return &HashCache{
		entries: map[fileKey]*cacheEntry{},
		touched: map[fileKey]bool{},
		values:  map[string]*valueEntry{},
		now:     time.Now,
	}
}

// LoadHashCache restores a cache produced by Marshal. A nil or malformed
// input yields an empty cache.
func LoadHashCache(raw json.RawMessage) *HashCache {
	c := NewHashCache()
	c.load(raw)
	return c
}

func (c *HashCache) load(raw json.RawMessage) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	var files []*cacheEntry
	var values []*valueEntry
	switch raw[0] {
	case '[':
		if json.Unmarshal(raw, &files) != nil {
			return
		}
	case '{':
		var doc cacheDoc
		if json.Unmarshal(raw, &doc) != nil || doc.Version != cacheFormat {
			return
		}
		if len(doc.Files) > 0 && json.Unmarshal(doc.Files, &files) != nil {
			return
		}
		values = doc.Values
	default:
		return
	}
	now := c.now().Unix()
	for _, e := range files {
		if e == nil {
			continue
		}
		if e.Used == 0 {
			// Format 1 has no use times; the retention starts now.
			e.Used = now
		}
		c.entries[e.Key] = e
	}
	for _, v := range values {
		if v != nil && v.Expires > now {
			c.values[v.Key] = v
		}
	}
}

// Marshal returns the cache for the next run. File entries used during this
// run are kept, and so are the others for fileRetention after their last
// use, so that a run of a few sections does not discard what the other
// sections need. Values are kept until they expire. When the result would
// exceed maxCacheBytes, the entries used longest ago are left out.
func (c *HashCache) Marshal() (json.RawMessage, error) { return c.marshal(maxCacheBytes) }

func (c *HashCache) marshal(budget int) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	cutoff := now - int64(fileRetention/time.Second)
	files := make([]*cacheEntry, 0, len(c.entries))
	for k, e := range c.entries {
		if c.touched[k] {
			e.Used = now
		} else if e.Used < cutoff {
			continue
		}
		files = append(files, e)
	}
	// Most recently used first, so that the budget drops the oldest.
	slices.SortFunc(files, func(a, b *cacheEntry) int {
		return cmp.Or(cmp.Compare(b.Used, a.Used), compareKeys(a.Key, b.Key))
	})
	values := make([]*valueEntry, 0, len(c.values))
	for _, v := range c.values {
		if v.Expires > now {
			values = append(values, v)
		}
	}
	slices.SortFunc(values, func(a, b *valueEntry) int { return strings.Compare(a.Key, b.Key) })

	var vals []*valueEntry
	for _, v := range values {
		if n := len(v.Key) + len(v.Value) + 32; n <= budget {
			budget -= n
			vals = append(vals, v)
		}
	}
	var fb bytes.Buffer
	fb.WriteByte('[')
	for _, e := range files {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		if len(b)+1 > budget {
			break
		}
		budget -= len(b) + 1
		if fb.Len() > 1 {
			fb.WriteByte(',')
		}
		fb.Write(b)
	}
	fb.WriteByte(']')
	return json.Marshal(cacheDoc{Version: cacheFormat, Files: fb.Bytes(), Values: vals})
}

func compareKeys(a, b fileKey) int {
	return cmp.Or(cmp.Compare(a.Dev, b.Dev), cmp.Compare(a.Ino, b.Ino), cmp.Compare(a.Size, b.Size),
		cmp.Compare(a.Mtime, b.Mtime), cmp.Compare(a.Ctime, b.Ctime))
}

// Value reads a value stored under key with SetValue that has not expired.
func (c *HashCache) Value(key string, out any) bool {
	c.mu.Lock()
	v := c.values[key]
	c.mu.Unlock()
	if v == nil || v.Expires <= c.now().Unix() {
		return false
	}
	return json.Unmarshal(v.Value, out) == nil
}

// SetValue stores a value that belongs to no single file, such as the
// result of scanning a container image, for ttl. Values larger than
// maxValueBytes are not stored.
func (c *HashCache) SetValue(key string, value any, ttl time.Duration) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxValueBytes {
		return
	}
	v := &valueEntry{Key: key, Expires: c.now().Add(ttl).Unix(), Value: raw}
	c.mu.Lock()
	c.values[key] = v
	c.mu.Unlock()
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
