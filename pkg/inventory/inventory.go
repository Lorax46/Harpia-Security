// Package inventory provides a type-safe, SQL-free inventory engine for cloud resources.
package inventory

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/pkg/inventory/cache"
	"github.com/Lorax46/Harpia-Security/pkg/inventory/plugins/aws"
	"github.com/Lorax46/Harpia-Security/pkg/inventory/plugins/azure"
	"github.com/Lorax46/Harpia-Security/pkg/inventory/plugins/gcp"
	"github.com/Lorax46/Harpia-Security/pkg/inventory/plugins/oci"
)

// Resource is the base interface for all cloud resources.
type Resource interface {
	GetID() string
	GetType() string
	GetProvider() string
	GetService() string
	GetRegion() string
	GetTags() map[string]string
}

// Filter is the base interface for resource filters.
type Filter interface {
	GetRegion() string
	GetTags() map[string]string
}

// BaseResource provides a default implementation of Resource.
type BaseResource struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Provider string            `json:"provider"`
	Service  string            `json:"service"`
	Region   string            `json:"region"`
	Tags     map[string]string `json:"tags"`
}

func (r BaseResource) GetID() string       { return r.ID }
func (r BaseResource) GetType() string     { return r.Type }
func (r BaseResource) GetProvider() string { return r.Provider }
func (r BaseResource) GetService() string  { return r.Service }
func (r BaseResource) GetRegion() string   { return r.Region }
func (r BaseResource) GetTags() map[string]string {
	if r.Tags == nil {
		return map[string]string{}
	}
	return r.Tags
}

// BaseFilter provides a default implementation of Filter.
type BaseFilter struct {
	Region string            `json:"region"`
	Tags   map[string]string `json:"tags"`
}

func (f BaseFilter) GetRegion() string { return f.Region }
func (f BaseFilter) GetTags() map[string]string {
	if f.Tags == nil {
		return map[string]string{}
	}
	return f.Tags
}

// Config configures the Inventory engine.
type Config struct {
	CacheTTL     time.Duration
	DisableCache bool
	AWSConfig    aws.PluginConfig
	GCPConfig    gcp.PluginConfig
	AzureConfig  azure.PluginConfig
	OCIConfig    oci.PluginConfig
}

// Option is a functional option for configuring Inventory.
type Option func(*Config)

// WithCacheTTL sets the cache TTL.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) { c.CacheTTL = ttl }
}

// DisableCache disables caching.
func DisableCache() Option {
	return func(c *Config) { c.DisableCache = true }
}

// WithAWSConfig sets AWS plugin configuration.
func WithAWSConfig(cfg aws.PluginConfig) Option {
	return func(c *Config) { c.AWSConfig = cfg }
}

// WithGCPConfig sets GCP plugin configuration.
func WithGCPConfig(cfg gcp.PluginConfig) Option {
	return func(c *Config) { c.GCPConfig = cfg }
}

// WithAzureConfig sets Azure plugin configuration.
func WithAzureConfig(cfg azure.PluginConfig) Option {
	return func(c *Config) { c.AzureConfig = cfg }
}

// WithOCIConfig sets OCI plugin configuration.
func WithOCIConfig(cfg oci.PluginConfig) Option {
	return func(c *Config) { c.OCIConfig = cfg }
}

// Inventory is the main entry point for the inventory engine.
type Inventory struct {
	aws   *aws.Plugin
	gcp   *gcp.Plugin
	azure *azure.Plugin
	oci   *oci.Plugin
	cache *cache.Cache
}

// New creates a new Inventory engine.
func New(ctx context.Context, opts ...Option) *Inventory {
	cfg := Config{
		CacheTTL: 5 * time.Minute,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	inv := &Inventory{
		cache: cache.New(cfg.CacheTTL),
	}

	// Initialize plugins with config
	inv.aws = aws.New(cfg.AWSConfig)
	inv.gcp = gcp.New(cfg.GCPConfig)
	inv.azure = azure.New(cfg.AzureConfig)
	inv.oci = oci.New(cfg.OCIConfig)

	return inv
}

// AWS returns the AWS plugin.
func (inv *Inventory) AWS() *aws.Plugin {
	return inv.aws
}

// GCP returns the GCP plugin.
func (inv *Inventory) GCP() *gcp.Plugin {
	return inv.gcp
}

// Azure returns the Azure plugin.
func (inv *Inventory) Azure() *azure.Plugin {
	return inv.azure
}

// OCI returns the OCI plugin.
func (inv *Inventory) OCI() *oci.Plugin {
	return inv.oci
}

// Cache returns the cache instance.
func (inv *Inventory) Cache() *cache.Cache {
	return inv.cache
}

// InvalidateCache clears all cached resources.
func (inv *Inventory) InvalidateCache() {
	inv.cache.Clear()
}

// InvalidateCacheFor invalidates cache for a specific provider/service.
func (inv *Inventory) InvalidateCacheFor(provider, service string) {
	inv.cache.ClearPrefix(provider + ":" + service)
}
