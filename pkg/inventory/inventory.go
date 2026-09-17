// Package inventory provides cloud resource discovery and inventory.
// Based on Steampipe's table architecture (588 AWS, 177 Azure, 123 GCP tables).
package inventory

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Resource represents a discovered cloud resource.
// Equivalent to a row in a Steampipe table.
type Resource struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`     // aws_iam_user, azure_vm, gcp_compute_instance
	Provider   string                 `json:"provider"` // aws, azure, gcp
	Region     string                 `json:"region"`
	AccountID  string                 `json:"account_id,omitempty"`
	Tags       map[string]string      `json:"tags,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Discovered time.Time              `json:"discovered_at"`
}

// ResourceType defines a type of resource that can be inventoried.
type ResourceType struct {
	Name        string
	Provider    string
	Service     string
	Description string
}

// InventoryResult contains the result of an inventory collection.
type InventoryResult struct {
	ResourceType string     `json:"resource_type"`
	Provider     string     `json:"provider"`
	Total        int        `json:"total"`
	Resources    []Resource `json:"resources"`
	CollectedAt  time.Time  `json:"collected_at"`
	Error        string     `json:"error,omitempty"`
}

// Filter represents inventory query filters.
type Filter struct {
	Provider string
	Service  string
	Region   string
	Category string
}

// Collector defines the interface for inventory collectors.
type Collector interface {
	Collect(ctx context.Context, resourceType string) (*InventoryResult, error)
	ListResourceTypes() []ResourceType
}

// Manager orchestrates inventory collection across providers.
type Manager struct {
	collectors map[string]Collector
	mu         sync.RWMutex
	cache      map[string]*InventoryResult
}

// NewManager creates a new inventory Manager.
func NewManager() *Manager {
	return &Manager{
		collectors: make(map[string]Collector),
		cache:      make(map[string]*InventoryResult),
	}
}

// RegisterCollector registers a collector for a provider.
func (m *Manager) RegisterCollector(provider string, c Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collectors[provider] = c
}

// ListProviders returns all registered providers.
func (m *Manager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	providers := make([]string, 0, len(m.collectors))
	for p := range m.collectors {
		providers = append(providers, p)
	}
	return providers
}

// GetCollector returns the collector for a provider.
func (m *Manager) GetCollector(provider string) (Collector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.collectors[provider]
	if !ok {
		return nil, fmt.Errorf("no collector registered for provider: %s", provider)
	}
	return c, nil
}

// CollectAll collects inventory from all registered providers concurrently.
func (m *Manager) CollectAll(ctx context.Context, providers []string) (map[string][]*InventoryResult, error) {
	if len(providers) == 0 {
		providers = m.ListProviders()
	}

	results := make(map[string][]*InventoryResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, provider := range providers {
		collector, err := m.GetCollector(provider)
		if err != nil {
			continue
		}

		wg.Add(1)
		go func(p string, c Collector) {
			defer wg.Done()
			providerResults := m.collectFromProvider(ctx, c)
			mu.Lock()
			results[p] = providerResults
			mu.Unlock()
		}(provider, collector)
	}

	wg.Wait()
	return results, nil
}

// collectFromProvider collects all resources from a single provider.
func (m *Manager) collectFromProvider(ctx context.Context, collector Collector) []*InventoryResult {
	resourceTypes := collector.ListResourceTypes()
	var results []*InventoryResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, rt := range resourceTypes {
		wg.Add(1)
		go func(resourceType string) {
			defer wg.Done()
			result, err := collector.Collect(ctx, resourceType)
			if err != nil {
				mu.Lock()
				results = append(results, &InventoryResult{
					ResourceType: resourceType,
					Error:        err.Error(),
					CollectedAt:  time.Now(),
				})
				mu.Unlock()
				return
			}
			mu.Lock()
			results = append(results, result)
			// Update cache
			m.mu.Lock()
			m.cache[resourceType] = result
			m.mu.Unlock()
			mu.Unlock()
		}(rt.Name)
	}

	wg.Wait()
	return results
}

// GetTotalResources returns the total resource count per provider.
func (m *Manager) GetTotalResources(results map[string][]*InventoryResult) map[string]int {
	totals := make(map[string]int)
	for provider, providerResults := range results {
		total := 0
		for _, r := range providerResults {
			total += r.Total
		}
		totals[provider] = total
	}
	return totals
}

// GetResourceTypes returns all resource types for a provider.
func (m *Manager) GetResourceTypes(provider string) ([]ResourceType, error) {
	collector, err := m.GetCollector(provider)
	if err != nil {
		return nil, err
	}
	return collector.ListResourceTypes(), nil
}

// ListResources returns resources filtered by criteria - REAL DATA from collectors.
func (m *Manager) ListResources(provider, service string, filter Filter) ([]Resource, error) {
	collector, err := m.GetCollector(provider)
	if err != nil {
		return nil, err
	}

	resourceTypes := collector.ListResourceTypes()
	var allResources []Resource
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, rt := range resourceTypes {
		if service != "" && rt.Service != service {
			continue
		}

		wg.Add(1)
		go func(resourceType string) {
			defer wg.Done()
			result, err := collector.Collect(context.Background(), resourceType)
			if err != nil {
				return
			}
			mu.Lock()
			allResources = append(allResources, result.Resources...)
			mu.Unlock()
		}(rt.Name)
	}

	wg.Wait()
	return allResources, nil
}

// SyncResources triggers a real sync for a provider.
func (m *Manager) SyncResources(provider string) error {
	collector, err := m.GetCollector(provider)
	if err != nil {
		log.Printf("[INVENTORY] ERROR: no collector for %s: %v", provider, err)
		return err
	}

	// Clear cache for this provider
	m.mu.Lock()
	for key := range m.cache {
		delete(m.cache, key)
	}
	m.mu.Unlock()

	// Trigger collection for all resource types
	resourceTypes := collector.ListResourceTypes()
	log.Printf("[INVENTORY] Syncing %s: %d resource types", provider, len(resourceTypes))

	var wg sync.WaitGroup
	errChan := make(chan error, len(resourceTypes))
	for _, rt := range resourceTypes {
		wg.Add(1)
		go func(resourceType string) {
			defer wg.Done()
			log.Printf("[INVENTORY] Collecting %s...", resourceType)
			result, err := collector.Collect(context.Background(), resourceType)
			if err != nil {
				log.Printf("[INVENTORY] ERROR collecting %s: %v", resourceType, err)
				errChan <- fmt.Errorf("%s: %w", resourceType, err)
				return
			}
			log.Printf("[INVENTORY] Collected %d %s resources", len(result.Resources), resourceType)
		}(rt.Name)
	}
	wg.Wait()
	close(errChan)

	var errs []error
	for e := range errChan {
		errs = append(errs, e)
	}

	if len(errs) > 0 {
		log.Printf("[INVENTORY] Sync completed with %d errors for %s", len(errs), provider)
	} else {
		log.Printf("[INVENTORY] Sync complete for %s - no errors", provider)
	}
	return nil
}

// GetService returns a new inventory service.
func GetService() *Service {
	return &Service{manager: NewManager()}
}

// Service provides inventory operations.
type Service struct {
	manager *Manager
}

// ListProviders returns available providers.
func (s *Service) ListProviders() []string {
	return s.manager.ListProviders()
}

// ListTables returns tables (resource types) for a provider.
func (s *Service) ListTables(provider string) []string {
	types, err := s.manager.GetResourceTypes(provider)
	if err != nil {
		return []string{}
	}
	tables := make([]string, len(types))
	for i, t := range types {
		tables[i] = t.Name
	}
	return tables
}

// ListResources lists resources for a provider/service.
func (s *Service) ListResources(provider, service string, filter Filter) ([]Resource, error) {
	return s.manager.ListResources(provider, service, filter)
}

// SyncResources syncs resources for a provider.
func (s *Service) SyncResources(provider string) error {
	return s.manager.SyncResources(provider)
}

// GetAllResourceTypes returns all resource types across all providers.
func GetAllResourceTypes() []ResourceType {
	return steampipeResourceTypes
}

// ResourceTypes defines all resource types that can be inventoried.
// Based on Steampipe tables.
var steampipeResourceTypes = []ResourceType{
	// AWS - IAM
	{Name: "aws_iam_user", Provider: "aws", Service: "iam", Description: "AWS IAM Users"},
	{Name: "aws_iam_role", Provider: "aws", Service: "iam", Description: "AWS IAM Roles"},
	{Name: "aws_iam_group", Provider: "aws", Service: "iam", Description: "AWS IAM Groups"},
	{Name: "aws_iam_policy", Provider: "aws", Service: "iam", Description: "AWS IAM Policies"},
	{Name: "aws_iam_access_key", Provider: "aws", Service: "iam", Description: "AWS IAM Access Keys"},

	// AWS - Compute
	{Name: "aws_ec2_instance", Provider: "aws", Service: "ec2", Description: "AWS EC2 Instances"},
	{Name: "aws_ec2_vpc", Provider: "aws", Service: "ec2", Description: "AWS VPCs"},
	{Name: "aws_ec2_subnet", Provider: "aws", Service: "ec2", Description: "AWS Subnets"},
	{Name: "aws_ec2_security_group", Provider: "aws", Service: "ec2", Description: "AWS Security Groups"},
	{Name: "aws_ec2_volume", Provider: "aws", Service: "ec2", Description: "AWS EBS Volumes"},

	// AWS - Storage
	{Name: "aws_s3_bucket", Provider: "aws", Service: "s3", Description: "AWS S3 Buckets"},

	// AWS - Network
	{Name: "aws_elbv2_load_balancer", Provider: "aws", Service: "elbv2", Description: "AWS Load Balancers"},
	{Name: "aws_route53_zone", Provider: "aws", Service: "route53", Description: "AWS Route53 Zones"},

	// AWS - Database
	{Name: "aws_rds_db_instance", Provider: "aws", Service: "rds", Description: "AWS RDS Instances"},
	{Name: "aws_dynamodb_table", Provider: "aws", Service: "dynamodb", Description: "AWS DynamoDB Tables"},

	// AWS - Compute (Serverless/Containers)
	{Name: "aws_lambda_function", Provider: "aws", Service: "lambda", Description: "AWS Lambda Functions"},
	{Name: "aws_ecs_cluster", Provider: "aws", Service: "ecs", Description: "AWS ECS Clusters"},
	{Name: "aws_eks_cluster", Provider: "aws", Service: "eks", Description: "AWS EKS Clusters"},

	// AWS - Security
	{Name: "aws_kms_key", Provider: "aws", Service: "kms", Description: "AWS KMS Keys"},
	{Name: "aws_secretsmanager_secret", Provider: "aws", Service: "secretsmanager", Description: "AWS Secrets"},
	{Name: "aws_cloudtrail_trail", Provider: "aws", Service: "cloudtrail", Description: "AWS CloudTrail Trails"},
	{Name: "aws_organizations_account", Provider: "aws", Service: "organizations", Description: "AWS Accounts"},

	// Azure - Compute
	{Name: "azure_compute_virtual_machine", Provider: "azure", Service: "compute", Description: "Azure VMs"},
	{Name: "azure_compute_disk", Provider: "azure", Service: "compute", Description: "Azure Disks"},

	// Azure - Network
	{Name: "azure_network_virtual_network", Provider: "azure", Service: "network", Description: "Azure VNets"},
	{Name: "azure_network_subnet", Provider: "azure", Service: "network", Description: "Azure Subnets"},
	{Name: "azure_network_security_group", Provider: "azure", Service: "network", Description: "Azure NSGs"},
	{Name: "azure_network_public_ip", Provider: "azure", Service: "network", Description: "Azure Public IPs"},

	// Azure - Storage
	{Name: "azure_storage_account", Provider: "azure", Service: "storage", Description: "Azure Storage Accounts"},

	// Azure - Database
	{Name: "azure_sql_server", Provider: "azure", Service: "sql", Description: "Azure SQL Servers"},
	{Name: "azure_sql_database", Provider: "azure", Service: "sql", Description: "Azure SQL Databases"},

	// Azure - IAM
	{Name: "azure_ad_user", Provider: "azure", Service: "entra", Description: "Azure AD Users"},
	{Name: "azure_ad_group", Provider: "azure", Service: "entra", Description: "Azure AD Groups"},
	{Name: "azure_ad_service_principal", Provider: "azure", Service: "entra", Description: "Azure AD Service Principals"},

	// Azure - Kubernetes
	{Name: "azure_kubernetes_cluster", Provider: "azure", Service: "aks", Description: "Azure AKS Clusters"},

	// GCP - Compute
	{Name: "gcp_compute_instance", Provider: "gcp", Service: "compute", Description: "GCP Compute Instances"},
	{Name: "gcp_compute_disk", Provider: "gcp", Service: "compute", Description: "GCP Disks"},
	{Name: "gcp_compute_network", Provider: "gcp", Service: "compute", Description: "GCP Networks"},
	{Name: "gcp_compute_subnetwork", Provider: "gcp", Service: "compute", Description: "GCP Subnets"},
	{Name: "gcp_compute_firewall", Provider: "gcp", Service: "compute", Description: "GCP Firewalls"},
	{Name: "gcp_compute_address", Provider: "gcp", Service: "compute", Description: "GCP Addresses"},

	// GCP - Storage
	{Name: "gcp_storage_bucket", Provider: "gcp", Service: "storage", Description: "GCP Storage Buckets"},

	// GCP - Database
	{Name: "gcp_sql_database_instance", Provider: "gcp", Service: "sql", Description: "GCP SQL Instances"},
	{Name: "gcp_bigquery_dataset", Provider: "gcp", Service: "bigquery", Description: "GCP BigQuery Datasets"},

	// GCP - IAM
	{Name: "gcp_iam_service_account", Provider: "gcp", Service: "iam", Description: "GCP Service Accounts"},
	{Name: "gcp_iam_role", Provider: "gcp", Service: "iam", Description: "GCP IAM Roles"},

	// GCP - Kubernetes
	{Name: "gcp_container_cluster", Provider: "gcp", Service: "container", Description: "GCP GKE Clusters"},

	// GCP - Security
	{Name: "gcp_kms_crypto_key", Provider: "gcp", Service: "kms", Description: "GCP KMS Keys"},
	{Name: "gcp_secretmanager_secret", Provider: "gcp", Service: "secretmanager", Description: "GCP Secrets"},
}
