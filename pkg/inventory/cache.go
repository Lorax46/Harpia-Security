package inventory

import (
	"sync"
	"time"
)

// Cache provides a simple in-memory cache for inventory queries
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	value      []Resource
	expiration time.Time
}

// NewCache creates a new cache
func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     5 * time.Minute,
	}
	go c.cleanup()
	return c
}

// Get gets a value from the cache
func (c *Cache) Get(key string) ([]Resource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	
	if time.Now().After(entry.expiration) {
		return nil, false
	}
	
	return entry.value, true
}

// Set sets a value in the cache
func (c *Cache) Set(key string, value []Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.entries[key] = cacheEntry{
		value:      value,
		expiration: time.Now().Add(c.ttl),
	}
}

// Invalidate invalidates a cache entry
func (c *Cache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear clears the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// cleanup periodically removes expired entries
func (c *Cache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiration) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}
