// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package msgsig

import (
	"container/list"
	"sync"
	"time"
)

// nonceCache remembers recently accepted nonces. Entries expire after ttl;
// when the cache is full the oldest entry is dropped.
type nonceCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	ll  *list.List // front is newest
	m   map[string]*list.Element
}

type nonceEntry struct {
	key string
	at  time.Time
}

func newNonceCache(max int, ttl time.Duration) *nonceCache {
	return &nonceCache{ttl: ttl, max: max, ll: list.New(), m: make(map[string]*list.Element)}
}

// add records key and reports whether it was not seen within ttl.
func (c *nonceCache) add(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := c.ll.Back(); e != nil; e = c.ll.Back() {
		ent := e.Value.(*nonceEntry)
		if now.Sub(ent.at) <= c.ttl && c.ll.Len() < c.max {
			break
		}
		c.ll.Remove(e)
		delete(c.m, ent.key)
	}
	if _, ok := c.m[key]; ok {
		return false
	}
	c.m[key] = c.ll.PushFront(&nonceEntry{key: key, at: now})
	return true
}
