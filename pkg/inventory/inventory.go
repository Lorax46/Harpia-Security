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
	Provider   string                 `json:"provider"` // aws, azure, gcp, kubernetes
	Region     string                 `json:"region"`
	Namespace  string                 `json:"namespace,omitempty"`
	AccountID  string                 `json:"account_id,omitempty"`
	Tags       map[string]string      `json:"tags,omitempty"`
	Service    string                 `json:"service,omitempty"`
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

	// GCP - Compute Engine
	{Name: "gcp_compute_instance", Provider: "gcp", Service: "compute", Description: "GCP Compute Instances"},
	{Name: "gcp_compute_disk", Provider: "gcp", Service: "compute", Description: "GCP Disks"},
	{Name: "gcp_compute_network", Provider: "gcp", Service: "compute", Description: "GCP Networks"},
	{Name: "gcp_compute_subnetwork", Provider: "gcp", Service: "compute", Description: "GCP Subnets"},
	{Name: "gcp_compute_firewall", Provider: "gcp", Service: "compute", Description: "GCP Firewalls"},
	{Name: "gcp_compute_address", Provider: "gcp", Service: "compute", Description: "GCP Addresses"},
	{Name: "gcp_compute_global_address", Provider: "gcp", Service: "compute", Description: "GCP Global Addresses"},
	{Name: "gcp_compute_health_check", Provider: "gcp", Service: "compute", Description: "GCP Health Checks"},
	{Name: "gcp_compute_instance_group", Provider: "gcp", Service: "compute", Description: "GCP Instance Groups"},
	{Name: "gcp_compute_ssl_certificate", Provider: "gcp", Service: "compute", Description: "GCP SSL Certificates"},
	{Name: "gcp_compute_target_pool", Provider: "gcp", Service: "compute", Description: "GCP Target Pools"},
	{Name: "gcp_compute_url_map", Provider: "gcp", Service: "compute", Description: "GCP URL Maps"},
	{Name: "gcp_compute_backend_service", Provider: "gcp", Service: "compute", Description: "GCP Backend Services"},
	{Name: "gcp_compute_forwarding_rule", Provider: "gcp", Service: "compute", Description: "GCP Forwarding Rules"},
	{Name: "gcp_compute_snapshot", Provider: "gcp", Service: "compute", Description: "GCP Snapshots"},
	{Name: "gcp_compute_image", Provider: "gcp", Service: "compute", Description: "GCP Images"},
	{Name: "gcp_compute_machine_image", Provider: "gcp", Service: "compute", Description: "GCP Machine Images"},
	{Name: "gcp_compute_region", Provider: "gcp", Service: "compute", Description: "GCP Regions"},
	{Name: "gcp_compute_zone", Provider: "gcp", Service: "compute", Description: "GCP Zones"},
	{Name: "gcp_compute_router", Provider: "gcp", Service: "compute", Description: "GCP Routers"},
	{Name: "gcp_compute_interconnect_attachment", Provider: "gcp", Service: "compute", Description: "GCP Interconnect Attachments"},
	{Name: "gcp_compute_global_forwarding_rule", Provider: "gcp", Service: "compute", Description: "GCP Global Forwarding Rules"},
	{Name: "gcp_compute_vpn_tunnel", Provider: "gcp", Service: "compute", Description: "GCP VPN Tunnels"},
	{Name: "gcp_compute_backend_bucket", Provider: "gcp", Service: "compute", Description: "GCP Backend Buckets"},
	{Name: "gcp_compute_target_http_proxy", Provider: "gcp", Service: "compute", Description: "GCP Target HTTP Proxies"},
	{Name: "gcp_compute_target_ssl_proxy", Provider: "gcp", Service: "compute", Description: "GCP Target SSL Proxies"},

	// GCP - Storage
	{Name: "gcp_storage_bucket", Provider: "gcp", Service: "storage", Description: "GCP Storage Buckets"},
	{Name: "gcp_storage_object", Provider: "gcp", Service: "storage", Description: "GCP Storage Objects"},

	// GCP - Database
	{Name: "gcp_sql_database_instance", Provider: "gcp", Service: "sql", Description: "GCP SQL Instances"},
	{Name: "gcp_sql_database", Provider: "gcp", Service: "sql", Description: "GCP SQL Databases"},
	{Name: "gcp_sql_user", Provider: "gcp", Service: "sql", Description: "GCP SQL Users"},
	{Name: "gcp_bigquery_dataset", Provider: "gcp", Service: "bigquery", Description: "GCP BigQuery Datasets"},
	{Name: "gcp_bigquery_table", Provider: "gcp", Service: "bigquery", Description: "GCP BigQuery Tables"},
	{Name: "gcp_bigquery_job", Provider: "gcp", Service: "bigquery", Description: "GCP BigQuery Jobs"},

	// GCP - IAM
	{Name: "gcp_iam_service_account", Provider: "gcp", Service: "iam", Description: "GCP Service Accounts"},
	{Name: "gcp_iam_role", Provider: "gcp", Service: "iam", Description: "GCP IAM Roles"},
	{Name: "gcp_iam_policy", Provider: "gcp", Service: "iam", Description: "GCP IAM Policies"},

	// GCP - Kubernetes
	{Name: "gcp_container_cluster", Provider: "gcp", Service: "container", Description: "GCP GKE Clusters"},
	{Name: "gcp_container_node_pool", Provider: "gcp", Service: "container", Description: "GCP GKE Node Pools"},

	// GCP - Security
	{Name: "gcp_kms_crypto_key", Provider: "gcp", Service: "kms", Description: "GCP KMS Keys"},
	{Name: "gcp_kms_key_ring", Provider: "gcp", Service: "kms", Description: "GCP KMS Key Rings"},
	{Name: "gcp_secretmanager_secret", Provider: "gcp", Service: "secretmanager", Description: "GCP Secrets"},

	// GCP - DNS
	{Name: "gcp_dns_managed_zone", Provider: "gcp", Service: "dns", Description: "GCP DNS Zones"},
	{Name: "gcp_dns_record_set", Provider: "gcp", Service: "dns", Description: "GCP DNS Record Sets"},
	{Name: "gcp_dns_policy", Provider: "gcp", Service: "dns", Description: "GCP DNS Policies"},

	// GCP - Monitoring & Logging
	{Name: "gcp_monitoring_alert_policy", Provider: "gcp", Service: "monitoring", Description: "GCP Monitoring Alert Policies"},
	{Name: "gcp_monitoring_notification_channel", Provider: "gcp", Service: "monitoring", Description: "GCP Notification Channels"},
	{Name: "gcp_logging_sink", Provider: "gcp", Service: "logging", Description: "GCP Logging Sinks"},
	{Name: "gcp_logging_metric", Provider: "gcp", Service: "logging", Description: "GCP Logging Metrics"},

	// GCP - Pub/Sub, Cloud Functions, Cloud Run
	{Name: "gcp_pubsub_topic", Provider: "gcp", Service: "pubsub", Description: "GCP Pub/Sub Topics"},
	{Name: "gcp_pubsub_subscription", Provider: "gcp", Service: "pubsub", Description: "GCP Pub/Sub Subscriptions"},
	{Name: "gcp_cloudfunctions_function", Provider: "gcp", Service: "cloudfunctions", Description: "GCP Cloud Functions"},
	{Name: "gcp_cloud_run_service", Provider: "gcp", Service: "cloud_run", Description: "GCP Cloud Run Services"},
	{Name: "gcp_cloud_run_job", Provider: "gcp", Service: "cloud_run", Description: "GCP Cloud Run Jobs"},

	// GCP - Spanner, Redis, Artifact Registry, Others
	{Name: "gcp_spanner_instance", Provider: "gcp", Service: "spanner", Description: "GCP Spanner Instances"},
	{Name: "gcp_spanner_database", Provider: "gcp", Service: "spanner", Description: "GCP Spanner Databases"},
	{Name: "gcp_redis_instance", Provider: "gcp", Service: "redis", Description: "GCP Redis Instances"},
	{Name: "gcp_artifact_registry_repository", Provider: "gcp", Service: "artifactregistry", Description: "GCP Artifact Registry Repos"},
	{Name: "gcp_cloudbuild_trigger", Provider: "gcp", Service: "cloudbuild", Description: "GCP Cloud Build Triggers"},
	{Name: "gcp_source_repository", Provider: "gcp", Service: "sourcerepo", Description: "GCP Source Repositories"},
	{Name: "gcp_cloudscheduler_job", Provider: "gcp", Service: "cloudscheduler", Description: "GCP Cloud Scheduler Jobs"},

	// GitHub - Repository
	{Name: "github_repository", Provider: "github", Service: "repository", Description: "GitHub Repositories"},
	{Name: "github_branch", Provider: "github", Service: "repository", Description: "GitHub Repository Branches"},
	{Name: "github_branch_protection", Provider: "github", Service: "repository", Description: "GitHub Branch Protection Rules"},
	{Name: "github_release", Provider: "github", Service: "repository", Description: "GitHub Releases"},
	{Name: "github_release_asset", Provider: "github", Service: "repository", Description: "GitHub Release Assets"},
	{Name: "github_tag", Provider: "github", Service: "repository", Description: "Repository Tags"},
	{Name: "github_repo_milestone", Provider: "github", Service: "repository", Description: "Repository Milestones"},
	{Name: "github_gitignore", Provider: "github", Service: "repository", Description: "Gitignore Templates"},

	// GitHub - Collaboration
	{Name: "github_user", Provider: "github", Service: "collaboration", Description: "GitHub Users"},
	{Name: "github_organization", Provider: "github", Service: "collaboration", Description: "GitHub Organizations"},
	{Name: "github_team", Provider: "github", Service: "collaboration", Description: "GitHub Teams"},
	{Name: "github_collaborator", Provider: "github", Service: "collaboration", Description: "Repository Collaborators"},
	{Name: "github_repository_collaborator", Provider: "github", Service: "collaboration", Description: "Repository Collaborators"},
	{Name: "github_membership", Provider: "github", Service: "collaboration", Description: "GitHub Memberships"},
	{Name: "github_team_membership", Provider: "github", Service: "collaboration", Description: "GitHub Team Memberships"},
	{Name: "github_team_repository", Provider: "github", Service: "collaboration", Description: "GitHub Team Repositories"},

	// GitHub - Issues and PRs
	{Name: "github_issue", Provider: "github", Service: "issues", Description: "GitHub Issues"},
	{Name: "github_issue_label", Provider: "github", Service: "issues", Description: "GitHub Issue Labels"},
	{Name: "github_pull_request", Provider: "github", Service: "pull_request", Description: "GitHub Pull Requests"},
	{Name: "github_pull_request_review", Provider: "github", Service: "pull_request", Description: "GitHub Pull Request Reviews"},

	// GitHub - Actions and Security
	{Name: "github_actions_repository_permissions", Provider: "github", Service: "actions", Description: "GitHub Actions Repository Permissions"},
	{Name: "github_actions_secret", Provider: "github", Service: "actions", Description: "GitHub Actions Secrets"},
	{Name: "github_actions_repository_oidc_subject_claim_customization_template", Provider: "github", Service: "actions", Description: "GitHub Actions OIDC Templates"},
	{Name: "github_actions_variable", Provider: "github", Service: "actions", Description: "GitHub Actions Variables"},
	{Name: "github_actions_workflow", Provider: "github", Service: "actions", Description: "GitHub Actions Workflows"},
	{Name: "github_code_scanning_alert", Provider: "github", Service: "security", Description: "Code Scanning Alerts"},
	{Name: "github_dependabot_alert", Provider: "github", Service: "security", Description: "Dependabot Alerts"},
	{Name: "github_dependabot_secret", Provider: "github", Service: "security", Description: "Dependabot Secrets"},
	{Name: "github_dependency_graph_dependency", Provider: "github", Service: "security", Description: "Dependency Graph Dependencies"},
	{Name: "github_secret_scanning_alert", Provider: "github", Service: "security", Description: "Secret Scanning Alerts"},

	// GitHub - Advanced Features
	{Name: "github_deployment", Provider: "github", Service: "deployment", Description: "GitHub Deployments"},
	{Name: "github_domain", Provider: "github", Service: "domain", Description: "GitHub Domains"},
	{Name: "github_enterprise", Provider: "github", Service: "enterprise", Description: "GitHub Enterprises"},
	{Name: "github_environment", Provider: "github", Service: "environment", Description: "GitHub Environments"},
	{Name: "github_ip_allow_rules", Provider: "github", Service: "security", Description: "GitHub IP Allow List Rules"},
	{Name: "github_organization_default_repository_permission", Provider: "github", Service: "collaboration", Description: "Org Default Repository Permissions"},
	{Name: "github_organization_mfa_status", Provider: "github", Service: "collaboration", Description: "Org MFA Status"},
	{Name: "github_organization_security_contact", Provider: "github", Service: "collaboration", Description: "Org Security Contacts"},
	{Name: "github_organization_webhook", Provider: "github", Service: "collaboration", Description: "Organization Webhooks"},
	{Name: "github_public_key", Provider: "github", Service: "security", Description: "GitHub Public Keys"},
	{Name: "github_ruleset", Provider: "github", Service: "repository", Description: "GitHub Repository Rulesets"},
	{Name: "github_ssh_key", Provider: "github", Service: "security", Description: "GitHub SSH Keys"},
	{Name: "github_webhook", Provider: "github", Service: "webhook", Description: "GitHub Repository Webhooks"},

	// Kubernetes
	{Name: "kubernetes_pod", Provider: "kubernetes", Service: "core", Description: "Kubernetes Pods"},
	{Name: "kubernetes_deployment", Provider: "kubernetes", Service: "apps", Description: "Kubernetes Deployments"},
	{Name: "kubernetes_stateful_set", Provider: "kubernetes", Service: "apps", Description: "Kubernetes StatefulSets"},
	{Name: "kubernetes_daemon_set", Provider: "kubernetes", Service: "apps", Description: "Kubernetes DaemonSets"},
	{Name: "kubernetes_replica_set", Provider: "kubernetes", Service: "apps", Description: "Kubernetes ReplicaSets"},
	{Name: "kubernetes_job", Provider: "kubernetes", Service: "batch", Description: "Kubernetes Jobs"},
	{Name: "kubernetes_cron_job", Provider: "kubernetes", Service: "batch", Description: "Kubernetes CronJobs"},
	{Name: "kubernetes_service", Provider: "kubernetes", Service: "core", Description: "Kubernetes Services"},
	{Name: "kubernetes_ingress", Provider: "kubernetes", Service: "networking", Description: "Kubernetes Ingresses"},
	{Name: "kubernetes_config_map", Provider: "kubernetes", Service: "core", Description: "Kubernetes ConfigMaps"},
	{Name: "kubernetes_secret", Provider: "kubernetes", Service: "core", Description: "Kubernetes Secrets"},
	{Name: "kubernetes_persistent_volume", Provider: "kubernetes", Service: "core", Description: "Kubernetes PersistentVolumes"},
	{Name: "kubernetes_persistent_volume_claim", Provider: "kubernetes", Service: "core", Description: "Kubernetes PersistentVolumeClaims"},
	{Name: "kubernetes_storage_class", Provider: "kubernetes", Service: "storage", Description: "Kubernetes StorageClasses"},
	{Name: "kubernetes_namespace", Provider: "kubernetes", Service: "core", Description: "Kubernetes Namespaces"},
	{Name: "kubernetes_node", Provider: "kubernetes", Service: "core", Description: "Kubernetes Nodes"},
	{Name: "kubernetes_service_account", Provider: "kubernetes", Service: "core", Description: "Kubernetes ServiceAccounts"},
	{Name: "kubernetes_role", Provider: "kubernetes", Service: "rbac", Description: "Kubernetes Roles"},
	{Name: "kubernetes_cluster_role", Provider: "kubernetes", Service: "rbac", Description: "Kubernetes ClusterRoles"},
	{Name: "kubernetes_role_binding", Provider: "kubernetes", Service: "rbac", Description: "Kubernetes RoleBindings"},
	{Name: "kubernetes_cluster_role_binding", Provider: "kubernetes", Service: "rbac", Description: "Kubernetes ClusterRoleBindings"},
	{Name: "kubernetes_network_policy", Provider: "kubernetes", Service: "networking", Description: "Kubernetes NetworkPolicies"},
	{Name: "kubernetes_resource_quota", Provider: "kubernetes", Service: "core", Description: "Kubernetes ResourceQuotas"},
	{Name: "kubernetes_limit_range", Provider: "kubernetes", Service: "core", Description: "Kubernetes LimitRanges"},
	{Name: "kubernetes_horizontal_pod_autoscaler", Provider: "kubernetes", Service: "autoscaling", Description: "Kubernetes HPAs"},
	{Name: "kubernetes_pod_disruption_budget", Provider: "kubernetes", Service: "policy", Description: "Kubernetes PodDisruptionBudgets"},
	{Name: "kubernetes_priority_class", Provider: "kubernetes", Service: "scheduling", Description: "Kubernetes PriorityClasses"},

	// Google Workspace
	{Name: "googleworkspace_user", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace Users"},
	{Name: "googleworkspace_group", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace Groups"},
	{Name: "googleworkspace_domain", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace Domains"},
	{Name: "googleworkspace_org_unit", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace Org Units"},
	{Name: "googleworkspace_role", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace Roles"},
	{Name: "googleworkspace_role_assignment", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace Role Assignments"},
	{Name: "googleworkspace_mobile_device", Provider: "googleworkspace", Service: "devices", Description: "Google Workspace Mobile Devices"},
	{Name: "googleworkspace_token", Provider: "googleworkspace", Service: "security", Description: "Google Workspace Tokens"},

	// Cloudflare
	{Name: "cloudflare_zone", Provider: "cloudflare", Service: "zone", Description: "Cloudflare Zones"},
	{Name: "cloudflare_dns_record", Provider: "cloudflare", Service: "dns", Description: "DNS Records"},
	{Name: "cloudflare_firewall_rule", Provider: "cloudflare", Service: "firewall", Description: "Firewall Rules"},
	{Name: "cloudflare_waf_package", Provider: "cloudflare", Service: "waf", Description: "WAF Packages"},
	{Name: "cloudflare_waf_rule", Provider: "cloudflare", Service: "waf", Description: "WAF Rules"},
	{Name: "cloudflare_load_balancer", Provider: "cloudflare", Service: "lb", Description: "Load Balancers"},
	{Name: "cloudflare_load_balancer_pool", Provider: "cloudflare", Service: "lb", Description: "Load Balancer Pools"},
	{Name: "cloudflare_load_balancer_monitor", Provider: "cloudflare", Service: "lb", Description: "Load Balancer Monitors"},
	{Name: "cloudflare_page_rule", Provider: "cloudflare", Service: "pagerule", Description: "Page Rules"},
	{Name: "cloudflare_certificate", Provider: "cloudflare", Service: "certificate", Description: "Certificates"},
	{Name: "cloudflare_account", Provider: "cloudflare", Service: "account", Description: "Accounts"},
	{Name: "cloudflare_account_member", Provider: "cloudflare", Service: "account", Description: "Account Members"},
	{Name: "cloudflare_account_role", Provider: "cloudflare", Service: "account", Description: "Account Roles"},
	{Name: "cloudflare_user", Provider: "cloudflare", Service: "user", Description: "Users"},
	{Name: "cloudflare_worker_route", Provider: "cloudflare", Service: "workers", Description: "Worker Routes"},
	{Name: "cloudflare_worker_script", Provider: "cloudflare", Service: "workers", Description: "Worker Scripts"},
	{Name: "cloudflare_worker_secret", Provider: "cloudflare", Service: "workers", Description: "Worker Secrets"},
	{Name: "cloudflare_kv_namespace", Provider: "cloudflare", Service: "kv", Description: "KV Namespaces"},
	{Name: "cloudflare_kv_key", Provider: "cloudflare", Service: "kv", Description: "KV Keys"},
	{Name: "cloudflare_r2_bucket", Provider: "cloudflare", Service: "r2", Description: "R2 Buckets"},
	{Name: "cloudflare_d1_database", Provider: "cloudflare", Service: "d1", Description: "D1 Databases"},
	{Name: "cloudflare_access_application", Provider: "cloudflare", Service: "access", Description: "Access Applications"},
	{Name: "cloudflare_tunnel", Provider: "cloudflare", Service: "tunnel", Description: "Tunnels"},
	{Name: "cloudflare_tunnel_route", Provider: "cloudflare", Service: "tunnel", Description: "Tunnel Routes"},
	{Name: "cloudflare_tunnel_virtual_network", Provider: "cloudflare", Service: "tunnel", Description: "Tunnel Virtual Networks"},
	{Name: "cloudflare_teams_list", Provider: "cloudflare", Service: "teams", Description: "Teams Lists"},
	{Name: "cloudflare_teams_rule", Provider: "cloudflare", Service: "teams", Description: "Teams Rules"},
	{Name: "cloudflare_ip_list", Provider: "cloudflare", Service: "ip", Description: "IP Lists"},
	{Name: "cloudflare_rate_limit", Provider: "cloudflare", Service: "rate-limit", Description: "Rate Limits"},
	{Name: "cloudflare_waiting_room", Provider: "cloudflare", Service: "waiting-room", Description: "Waiting Rooms"},
	{Name: "cloudflare_custom_hostname", Provider: "cloudflare", Service: "custom-hostname", Description: "Custom Hostnames"},
	{Name: "cloudflare_custom_ssl", Provider: "cloudflare", Service: "custom-ssl", Description: "Custom SSL"},
}
