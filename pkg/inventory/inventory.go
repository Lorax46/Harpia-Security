// Package inventory provides resource discovery and querying.
// Based on Steampipe's architecture: per-provider plugins, per-service tables, query engine with caching.
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
	Category   string                 `json:"category"`
	Region     string                 `json:"region"`
	Properties map[string]interface{} `json:"properties"`
	Tags       map[string]string      `json:"tags"`
	Discovered time.Time              `json:"discovered"`
}

// Filter represents query filters
type Filter struct {
	Provider string            `json:"provider"`
	Service  string            `json:"service"`
	Category string            `json:"category"`
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
	Category    string   `json:"category"`
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

// Cache provides in-memory caching
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	resources  []Resource
	expiration time.Time
}

func NewCache() *Cache {
	c := &Cache{entries: make(map[string]cacheEntry), ttl: 5 * time.Minute}
	go c.cleanup()
	return c
}

func (c *Cache) Get(key string) ([]Resource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiration) { return nil, false }
	return e.resources, true
}

func (c *Cache) Set(key string, r []Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{r, time.Now().Add(c.ttl)}
}

func (c *Cache) cleanup() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		c.mu.Lock(); now := time.Now()
		for k, e := range c.entries { if now.After(e.expiration) { delete(c.entries, k) } }
		c.mu.Unlock()
	}
}

// Manager manages inventory providers
type Manager struct {
	mu        sync.RWMutex
	providers map[string]*ProviderDef
	cache     *Cache
}

// NewManager creates a manager with all providers pre-registered
func NewManager() *Manager {
	m := &Manager{providers: make(map[string]*ProviderDef), cache: NewCache()}
	m.registerAllProviders()
	return m
}

// registerAllProviders registers all cloud providers with their resource tables
func (m *Manager) registerAllProviders() {
	// AWS Provider
	aws := NewProvider("aws")
	aws.RegisterTable(&TableDef{Name: "ec2_instances", Category: "compute", Description: "EC2 instances"})
	aws.RegisterTable(&TableDef{Name: "lambda_functions", Category: "compute", Description: "Lambda functions"})
	aws.RegisterTable(&TableDef{Name: "ecs_tasks", Category: "compute", Description: "ECS tasks"})
	aws.RegisterTable(&TableDef{Name: "s3_buckets", Category: "storage", Description: "S3 buckets"})
	aws.RegisterTable(&TableDef{Name: "ebs_volumes", Category: "storage", Description: "EBS volumes"})
	aws.RegisterTable(&TableDef{Name: "rds_instances", Category: "database", Description: "RDS instances"})
	aws.RegisterTable(&TableDef{Name: "dynamodb_tables", Category: "database", Description: "DynamoDB tables"})
	aws.RegisterTable(&TableDef{Name: "vpcs", Category: "network", Description: "VPCs"})
	aws.RegisterTable(&TableDef{Name: "security_groups", Category: "network", Description: "Security groups"})
	aws.RegisterTable(&TableDef{Name: "route53_zones", Category: "network", Description: "Route53 zones"})
	aws.RegisterTable(&TableDef{Name: "iam_users", Category: "iam", Description: "IAM users"})
	aws.RegisterTable(&TableDef{Name: "iam_roles", Category: "iam", Description: "IAM roles"})
	aws.RegisterTable(&TableDef{Name: "iam_policies", Category: "iam", Description: "IAM policies"})
	aws.RegisterTable(&TableDef{Name: "kms_keys", Category: "security", Description: "KMS keys"})
	aws.RegisterTable(&TableDef{Name: "cloudtrail_trails", Category: "security", Description: "CloudTrail trails"})
	aws.RegisterTable(&TableDef{Name: "cloudwatch_alarms", Category: "security", Description: "CloudWatch alarms"})
	m.providers["aws"] = aws

	// OCI Provider
	oci := NewProvider("oci")
	oci.RegisterTable(&TableDef{Name: "instances", Category: "compute", Description: "Compute instances"})
	oci.RegisterTable(&TableDef{Name: "vcns", Category: "network", Description: "VCNs"})
	oci.RegisterTable(&TableDef{Name: "subnets", Category: "network", Description: "Subnets"})
	oci.RegisterTable(&TableDef{Name: "security_lists", Category: "network", Description: "Security lists"})
	oci.RegisterTable(&TableDef{Name: "buckets", Category: "storage", Description: "Object Storage buckets"})
	oci.RegisterTable(&TableDef{Name: "volumes", Category: "storage", Description: "Block volumes"})
	oci.RegisterTable(&TableDef{Name: "users", Category: "iam", Description: "Users"})
	oci.RegisterTable(&TableDef{Name: "groups", Category: "iam", Description: "Groups"})
	oci.RegisterTable(&TableDef{Name: "policies", Category: "iam", Description: "Policies"})
	oci.RegisterTable(&TableDef{Name: "cloudguard_rules", Category: "security", Description: "Cloud Guard rules"})
	oci.RegisterTable(&TableDef{Name: "events_rules", Category: "security", Description: "Events rules"})
	oci.RegisterTable(&TableDef{Name: "kms_keys", Category: "security", Description: "KMS keys"})
	m.providers["oci"] = oci

	// Azure Provider
	azure := NewProvider("azure")
	azure.RegisterTable(&TableDef{Name: "virtual_machines", Category: "compute", Description: "Virtual machines"})
	azure.RegisterTable(&TableDef{Name: "storage_accounts", Category: "storage", Description: "Storage accounts"})
	azure.RegisterTable(&TableDef{Name: "virtual_networks", Category: "network", Description: "Virtual networks"})
	azure.RegisterTable(&TableDef{Name: "network_security_groups", Category: "network", Description: "Network security groups"})
	azure.RegisterTable(&TableDef{Name: "sql_databases", Category: "database", Description: "SQL databases"})
	azure.RegisterTable(&TableDef{Name: "key_vaults", Category: "security", Description: "Key Vaults"})
	m.providers["azure"] = azure

	// GCP Provider
	gcp := NewProvider("gcp")
	gcp.RegisterTable(&TableDef{Name: "compute_instances", Category: "compute", Description: "Compute instances"})
	gcp.RegisterTable(&TableDef{Name: "cloud_storage_buckets", Category: "storage", Description: "Cloud Storage buckets"})
	gcp.RegisterTable(&TableDef{Name: "vpc_networks", Category: "network", Description: "VPC networks"})
	gcp.RegisterTable(&TableDef{Name: "cloud_firewalls", Category: "network", Description: "Cloud Firewall rules"})
	gcp.RegisterTable(&TableDef{Name: "cloudsql_instances", Category: "database", Description: "Cloud SQL instances"})
	gcp.RegisterTable(&TableDef{Name: "iam_service_accounts", Category: "iam", Description: "Service accounts"})
	gcp.RegisterTable(&TableDef{Name: "kms_keys", Category: "security", Description: "KMS keys"})
	m.providers["gcp"] = gcp

	// Cloudflare Provider
	cf := NewProvider("cloudflare")
	cf.RegisterTable(&TableDef{Name: "zones", Category: "network", Description: "DNS zones"})
	cf.RegisterTable(&TableDef{Name: "waf_rules", Category: "security", Description: "WAF rules"})
	cf.RegisterTable(&TableDef{Name: "dns_records", Category: "network", Description: "DNS records"})
	cf.RegisterTable(&TableDef{Name: "ssl_certificates", Category: "security", Description: "SSL certificates"})
	m.providers["cloudflare"] = cf
}

// ListProviders lists providers
func (m *Manager) ListProviders() []string {
	m.mu.RLock(); defer m.mu.RUnlock()
	names := []string{}
	for n := range m.providers { names = append(names, n) }
	return names
}

// ListTables lists tables for a provider
func (m *Manager) ListTables(provider string) []string {
	m.mu.RLock(); defer m.mu.RUnlock()
	p, ok := m.providers[provider]
	if !ok { return nil }
	return p.ListTables()
}

// ListResources lists resources with filters
func (m *Manager) ListResources(filter Filter) ([]Resource, error) {
	m.mu.RLock(); defer m.mu.RUnlock()
	var all []Resource
	providers := []string{filter.Provider}
	if filter.Provider == "" { providers = m.ListProviders() }
	for _, name := range providers {
		p, ok := m.providers[name]; if !ok { continue }
		for _, t := range p.Tables {
			if filter.Category != "" && t.Category != filter.Category { continue }
			key := name + ":" + t.Name
			if cached, hit := m.cache.Get(key); hit { all = append(all, cached...); continue }
			if t.List != nil {
				r, err := t.List(context.Background(), nil, filter)
				if err != nil { continue }
				m.cache.Set(key, r)
				for i := range r { r[i].Provider = name }
				all = append(all, r...)
			}
		}
	}
	return all, nil
}

var defaultManager = NewManager()

// Default returns the default manager
func Default() *Manager { return defaultManager }

// Service provides inventory operations
type Service struct { manager *Manager }

// NewService creates a new service
func NewService() *Service { return &Service{manager: Default()} }

// ListResources lists resources
func (s *Service) ListResources(provider, service string, filter Filter) ([]Resource, error) {
	if provider != "" { filter.Provider = provider }
	if service != "" { filter.Service = service }
	return s.manager.ListResources(filter)
}

// GetResource gets a resource by ID
func (s *Service) GetResource(provider, service, id string) (*Resource, error) {
	resources, err := s.ListResources(provider, service, Filter{})
	if err != nil { return nil, err }
	for i, r := range resources {
		if r.ID == id { return &resources[i], nil }
	}
	return nil, fmt.Errorf("resource not found: %s", id)
}

// SyncResources syncs resources for a provider
func (s *Service) SyncResources(provider string) error { return nil }

// ListProviders lists providers
func (s *Service) ListProviders() []string { return s.manager.ListProviders() }

// ListTables lists tables
func (s *Service) ListTables(provider string) []string { return s.manager.ListTables(provider) }

// GetResourcesByCategory returns resources grouped by category
func (s *Service) GetResourcesByCategory(provider string) (map[string][]Resource, error) {
	resources, err := s.ListResources(provider, "", Filter{})
	if err != nil { return nil, err }
	categories := make(map[string][]Resource)
	for _, r := range resources {
		categories[r.Category] = append(categories[r.Category], r)
	}
	return categories, nil
}
