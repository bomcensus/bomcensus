// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"time"
)

// The cache remembers the digest of files that matched their package
// database, keyed by everything stat tells about the file: device, inode,
// size, mtime and ctime. A file whose metadata changed in any way is read
// again. ctime cannot be set from user space, and replacing a file changes
// its inode, so a changed file is not taken for the cached one; a full
// rehash every few days covers the remaining ways (clock changes, writes
// to the block device).
//
// Format: base64 of fixed records, key (16 bytes, a hash of the stat
// fields and the algorithm) | day of last use (uint16, days since the Unix
// epoch) | algorithm code (1 byte) | digest.

const (
	cacheFormat = "i1:"
	keySize     = 16
	// cacheRetentionDays drops entries no chunk used for that long.
	cacheRetentionDays = 21
	// maxCacheEntries bounds the cache. A record with a SHA-256 digest is
	// 51 bytes, so the encoded cache stays near 27 MiB, well inside the
	// probe's request limit. Files beyond it are hashed on every pass.
	maxCacheEntries = 400_000
)

var algoCodes = map[string]byte{"md5": 1, "sha1": 2, "sha256": 3, "sha384": 4, "sha512": 5}

var algoSizes = map[byte]int{1: 16, 2: 20, 3: 32, 4: 48, 5: 64}

type statKey struct {
	Dev, Ino     uint64
	Size         int64
	Mtime, Ctime int64
}

type cacheKey [keySize]byte

type cacheEntry struct {
	day    uint16
	algo   byte
	digest []byte
}

type cache struct {
	entries map[cacheKey]*cacheEntry
	today   uint16
}

func cacheKeyOf(k statKey, algo byte) cacheKey {
	var b [8*5 + 1]byte
	binary.LittleEndian.PutUint64(b[0:], k.Dev)
	binary.LittleEndian.PutUint64(b[8:], k.Ino)
	binary.LittleEndian.PutUint64(b[16:], uint64(k.Size))
	binary.LittleEndian.PutUint64(b[24:], uint64(k.Mtime))
	binary.LittleEndian.PutUint64(b[32:], uint64(k.Ctime))
	b[40] = algo
	sum := sha256.Sum256(b[:])
	var out cacheKey
	copy(out[:], sum[:keySize])
	return out
}

func dayOf(t time.Time) uint16 { return uint16(t.Unix() / 86400) }

// loadCache reads a cache produced by marshal. Anything malformed yields an
// empty cache.
func loadCache(raw json.RawMessage, now time.Time) *cache {
	c := &cache{entries: map[cacheKey]*cacheEntry{}, today: dayOf(now)}
	var s string
	if len(bytes.TrimSpace(raw)) == 0 || json.Unmarshal(raw, &s) != nil || len(s) < len(cacheFormat) || s[:len(cacheFormat)] != cacheFormat {
		return c
	}
	b, err := base64.StdEncoding.DecodeString(s[len(cacheFormat):])
	if err != nil {
		return c
	}
	for len(b) >= keySize+3 && len(c.entries) < maxCacheEntries {
		var k cacheKey
		copy(k[:], b[:keySize])
		day := binary.LittleEndian.Uint16(b[keySize:])
		algo := b[keySize+2]
		n, ok := algoSizes[algo]
		if !ok || len(b) < keySize+3+n {
			break
		}
		if c.today-day <= cacheRetentionDays {
			c.entries[k] = &cacheEntry{day: day, algo: algo, digest: bytes.Clone(b[keySize+3 : keySize+3+n])}
		}
		b = b[keySize+3+n:]
	}
	return c
}

// get returns the digest stored for the file and marks the entry used.
func (c *cache) get(k statKey, algo string) ([]byte, bool) {
	code, ok := algoCodes[algo]
	if !ok {
		return nil, false
	}
	e := c.entries[cacheKeyOf(k, code)]
	if e == nil {
		return nil, false
	}
	e.day = c.today
	return e.digest, true
}

func (c *cache) put(k statKey, algo string, digest []byte) {
	code, ok := algoCodes[algo]
	if !ok || len(digest) != algoSizes[code] {
		return
	}
	key := cacheKeyOf(k, code)
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		return
	}
	c.entries[key] = &cacheEntry{day: c.today, algo: code, digest: bytes.Clone(digest)}
}

func (c *cache) marshal() json.RawMessage {
	var buf bytes.Buffer
	var hdr [keySize + 3]byte
	for k, e := range c.entries {
		copy(hdr[:], k[:])
		binary.LittleEndian.PutUint16(hdr[keySize:], e.day)
		hdr[keySize+2] = e.algo
		buf.Write(hdr[:])
		buf.Write(e.digest)
	}
	raw, _ := json.Marshal(cacheFormat + base64.StdEncoding.EncodeToString(buf.Bytes()))
	return raw
}
