// Package cache provides an in-memory cache for inventory resources.
package cache

import (
	"fmt"
	"sync"
	"time"
)

// Cache provides thread-safe in-memory caching with TTL.
type Cache struct {
	mu       sync.RWMutex
	items    map[string]cacheEntry
	ttl      time.Duration
	hits     int64
	misses   int64
}

type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

// New creates a new cache with the specified TTL.
func New(ttl time.Duration) *Cache {
	c := &Cache{
		items: make(map[string]cacheEntry),
		ttl:   ttl,
	}
	go c.cleanupLoop()
	return c
}

// Get retrieves a value from the cache.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, false
	}

	if time.Now().After(entry.expiration) {
		c.misses++
		return nil, false
	}

	c.hits++
	return entry.value, true
}

// Set stores a value in the cache.
func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheEntry{
		value:      value,
		expiration: time.Now().Add(c.ttl),
	}
}

// Delete removes a key from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// Clear removes all items from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]cacheEntry)
}

// ClearPrefix removes all items with the given prefix.
func (c *Cache) ClearPrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key := range c.items {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(c.items, key)
		}
	}
}

// Stats returns cache statistics.
func (c *Cache) Stats() (hits, misses int64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, len(c.items)
}

// Key generates a cache key from components.
func Key(provider, service, resourceType string, id ...string) string {
	key := fmt.Sprintf("%s:%s:%s", provider, service, resourceType)
	for _, s := range id {
		key += ":" + s
	}
	return key
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.items {
			if now.After(entry.expiration) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}
