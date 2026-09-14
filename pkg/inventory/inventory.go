// Package inventory provides resource discovery and querying for cloud providers.
// Based on Steampipe's architecture: per-provider plugins, per-service tables, query engine with caching.
package inventory

import (
	"fmt"
	"sync"
	"time"
)

// Resource represents a cloud resource discovered by the inventory scanner
type Resource struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Service    string                 `json:"service"`
	Region     string                 `json:"region"`
	Name       string                 `json:"name"`
	ARN        string                 `json:"arn"`
	Tags       map[string]string      `json:"tags"`
	Properties map[string]interface{} `json:"properties"`
	Discovered time.Time              `json:"discovered"`
}

// Filter represents a query filter for resources
type Filter struct {
	Provider string            `json:"provider"`
	Service  string            `json:"service"`
	Type     string            `json:"type"`
	Region   string            `json:"region"`
	Tags     map[string]string `json:"tags"`
	Limit    int               `json:"limit"`
}

// Query represents a resource query
type Query struct {
	Provider string            `json:"provider"`
	Table    string            `json:"table"`
	Filters  map[string]string `json:"filters"`
	Columns  []string          `json:"columns"`
	Limit    int               `json:"limit"`
}

// QueryResult represents the result of a query
type QueryResult struct {
	Query   Query     `json:"query"`
	Rows    []Resource `json:"rows"`
	Total   int        `json:"total"`
	Cached  bool       `json:"cached"`
	Elapsed int64      `json:"elapsed_ms"`
}

// TableDefinition defines a resource table
type TableDefinition struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Columns     []ColumnDefinition  `json:"columns"`
	List        ListResourcesFunc   `json:"-"`
}

// ColumnDefinition defines a column
type ColumnDefinition struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// ListResourcesFunc lists resources for a table
type ListResourcesFunc func(provider interface{}, region string) ([]Resource, error)

// Plugin represents an inventory plugin (per provider)
type Plugin struct {
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Version     string                       `json:"version"`
	Tables      map[string]*TableDefinition   `json:"-"`
}

// NewPlugin creates a new plugin
func NewPlugin(name, description string) *Plugin {
	return &Plugin{
		Name:        name,
		Description: description,
		Version:     "1.0.0",
		Tables:      make(map[string]*TableDefinition),
	}
}

// RegisterTable registers a table
func (p *Plugin) RegisterTable(table *TableDefinition) {
	p.Tables[table.Name] = table
}

// TableExists checks if a table exists
func (p *Plugin) TableExists(name string) bool {
	_, ok := p.Tables[name]
	return ok
}

// GetTable gets a table definition
func (p *Plugin) GetTable(name string) (*TableDefinition, bool) {
	t, ok := p.Tables[name]
	return t, ok
}

// ListTables lists all tables
func (p *Plugin) ListTables() []string {
	tables := []string{}
	for name := range p.Tables {
		tables = append(tables, name)
	}
	return tables
}

// Registry manages all inventory plugins
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*Plugin
	cache   *Cache
}

// NewRegistry creates a new registry
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]*Plugin),
		cache:   NewCache(),
	}
}

// RegisterPlugin registers a plugin
func (r *Registry) RegisterPlugin(plugin *Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[plugin.Name] = plugin
}

// GetPlugin gets a plugin
func (r *Registry) GetPlugin(name string) (*Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[name]
	return p, ok
}

// ListPlugins lists all plugins
func (r *Registry) ListPlugins() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := []string{}
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// GetTable gets a table from any plugin
func (r *Registry) GetTable(pluginName, tableName string) (*TableDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	plugin, ok := r.plugins[pluginName]
	if !ok {
		return nil, false
	}
	return plugin.GetTable(tableName)
}

// ListTables lists all tables across plugins
func (r *Registry) ListTables() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	tables := make(map[string][]string)
	for pluginName, plugin := range r.plugins {
		tables[pluginName] = plugin.ListTables()
	}
	return tables
}

// ListResources lists resources with filters
func (r *Registry) ListResources(filter Filter) ([]Resource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var allResources []Resource
	
	providers := []string{filter.Provider}
	if filter.Provider == "" {
		providers = r.ListPlugins()
	}
	
	for _, pluginName := range providers {
		plugin, ok := r.plugins[pluginName]
		if !ok {
			continue
		}
		
		for _, table := range plugin.Tables {
			provider := getProviderInstance(pluginName)
			resources, err := table.List(provider, filter.Region)
			if err != nil {
				continue
			}
			allResources = append(allResources, resources...)
		}
	}
	
	return allResources, nil
}

// getProviderInstance returns a provider instance
func getProviderInstance(provider string) interface{} {
	return nil // TODO: Return actual provider SDK clients
}

// Global registry instance
var globalRegistry = NewRegistry()

// GetRegistry returns the global registry
func GetRegistry() *Registry {
	return globalRegistry
}

// RegisterPlugin registers a plugin in the global registry
func RegisterPlugin(plugin *Plugin) {
	globalRegistry.RegisterPlugin(plugin)
}

// RegisterTable registers a table in a plugin
func RegisterTable(pluginName string, table *TableDefinition) error {
	plugin, ok := globalRegistry.GetPlugin(pluginName)
	if !ok {
		return fmt.Errorf("plugin not found: %s", pluginName)
	}
	plugin.RegisterTable(table)
	return nil
}
