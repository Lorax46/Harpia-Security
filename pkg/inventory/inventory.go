package inventory

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Resource represents a discovered cloud resource
type Resource struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Service    string                 `json:"service"`
	Region     string                 `json:"region"`
	Properties map[string]interface{} `json:"properties"`
	Tags       map[string]string      `json:"tags"`
	Discovered time.Time              `json:"discovered"`
}

// Filter represents query filters
type Filter struct {
	Provider string            `json:"provider"`
	Service  string            `json:"service"`
	Type     string            `json:"type"`
	Region   string            `json:"region"`
	Tags     map[string]string `json:"tags"`
	Limit    int               `json:"limit"`
}

// ListFunc lists resources for a table
type ListFunc func(ctx context.Context, provider interface{}, filter Filter) ([]Resource, error)

// TableDef defines a resource table
type TableDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	List        ListFunc `json:"-"`
}

// ProviderDef defines a provider plugin
type ProviderDef struct {
	Name   string               `json:"name"`
	Tables map[string]*TableDef `json:"-"`
}

// NewProvider creates a provider
func NewProvider(name string) *ProviderDef {
	return &ProviderDef{
		Name:   name,
		Tables: make(map[string]*TableDef),
	}
}

// RegisterTable registers a table
func (p *ProviderDef) RegisterTable(t *TableDef) {
	p.Tables[t.Name] = t
}

// ListTables lists tables
func (p *ProviderDef) ListTables() []string {
	names := []string{}
	for n := range p.Tables {
		names = append(names, n)
	}
	return names
}

type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	resources  []Resource
	expiration time.Time
}

func newCache(ttl time.Duration) *cache {
	c := &cache{entries: make(map[string]cacheEntry), ttl: ttl}
	go c.cleanup()
	return c
}

func (c *cache) Get(key string) ([]Resource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiration) {
		return nil, false
	}
	return e.resources, true
}

func (c *cache) Set(key string, r []Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{r, time.Now().Add(c.ttl)}
}

func (c *cache) cleanup() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		c.mu.Lock()
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expiration) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}

// Manager manages inventory providers
type Manager struct {
	mu        sync.RWMutex
	providers map[string]*ProviderDef
	cache     *cache
}

// NewManager creates a manager
func NewManager() *Manager {
	return &Manager{
		providers: make(map[string]*ProviderDef),
		cache:     newCache(5 * time.Minute),
	}
}

// Register registers a provider
func (m *Manager) Register(p *ProviderDef) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[p.Name] = p
}

// Get gets a provider
func (m *Manager) Get(name string) (*ProviderDef, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[name]
	return p, ok
}

// ListProviders lists providers
func (m *Manager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := []string{}
	for n := range m.providers {
		names = append(names, n)
	}
	return names
}

// ListTables lists tables for a provider
func (m *Manager) ListTables(provider string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[provider]
	if !ok {
		return nil
	}
	return p.ListTables()
}

// ListResources lists resources
func (m *Manager) ListResources(filter Filter) ([]Resource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []Resource
	providers := []string{filter.Provider}
	if filter.Provider == "" {
		providers = m.ListProviders()
	}
	for _, name := range providers {
		p, ok := m.providers[name]
		if !ok {
			continue
		}
		for tname, t := range p.Tables {
			key := name + ":" + tname
			if cached, hit := m.cache.Get(key); hit {
				all = append(all, cached...)
				continue
			}
			if t.List != nil {
				r, err := t.List(context.Background(), nil, filter)
				if err != nil {
					continue
				}
				m.cache.Set(key, r)
				for i := range r {
					r[i].Provider = name
				}
				all = append(all, r...)
			}
		}
	}
	return all, nil
}

func initManager() *Manager {
	m := NewManager()

	aws := NewProvider("aws")
	aws.RegisterTable(&TableDef{
		Name:        "ec2_instances",
		Description: "EC2 instances",
		List: func(ctx context.Context, p interface{}, f Filter) ([]Resource, error) {
			return []Resource{}, nil
		},
	})
	aws.RegisterTable(&TableDef{
		Name:        "s3_buckets",
		Description: "S3 buckets",
		List: func(ctx context.Context, p interface{}, f Filter) ([]Resource, error) {
			return []Resource{}, nil
		},
	})
	m.Register(aws)

	oci := NewProvider("oci")
	oci.RegisterTable(&TableDef{
		Name:        "instances",
		Description: "Compute instances",
		List: func(ctx context.Context, p interface{}, f Filter) ([]Resource, error) {
			return []Resource{}, nil
		},
	})
	oci.RegisterTable(&TableDef{
		Name:        "vcns",
		Description: "VCNs",
		List: func(ctx context.Context, p interface{}, f Filter) ([]Resource, error) {
			return []Resource{}, nil
		},
	})
	m.Register(oci)

	return m
}

var defaultManager = initManager()

// Default returns the default manager
func Default() *Manager {
	return defaultManager
}

// Service provides inventory operations
type Service struct {
	manager *Manager
}

// NewService creates a new service
func NewService() *Service {
	return &Service{manager: Default()}
}

// ListResources lists resources
func (s *Service) ListResources(provider, service string, filter Filter) ([]Resource, error) {
	if provider != "" {
		filter.Provider = provider
	}
	if service != "" {
		filter.Service = service
	}
	return s.manager.ListResources(filter)
}

// GetResource gets a resource by ID
func (s *Service) GetResource(provider, service, id string) (*Resource, error) {
	resources, err := s.ListResources(provider, service, Filter{})
	if err != nil {
		return nil, err
	}
	for i, r := range resources {
		if r.ID == id {
			return &resources[i], nil
		}
	}
	return nil, fmt.Errorf("resource not found: %s", id)
}

// SyncResources syncs resources
func (s *Service) SyncResources(provider string) error {
	return nil
}

// ListProviders lists providers
func (s *Service) ListProviders() []string {
	return s.manager.ListProviders()
}

// ListTables lists tables
func (s *Service) ListTables(provider string) []string {
	return s.manager.ListTables(provider)
}
