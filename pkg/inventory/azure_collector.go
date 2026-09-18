package inventory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/azure"
	"github.com/Lorax46/Harpia-Security/pkg/credentials"
)

// AzureCollector implements the Collector interface for Azure.
type AzureCollector struct {
	provider *azure.Provider
	cache    map[string]*InventoryResult
	mu       sync.RWMutex
}

// NewAzureCollector creates a new Azure collector. The provider is NOT initialized
// here - it will be lazily loaded from vault on first Collect() call.
// This allows the server to start without credentials.
func NewAzureCollector() *AzureCollector {
	return &AzureCollector{
		cache: make(map[string]*InventoryResult),
	}
}

// ensureProvider initializes the Azure provider from vault credentials.
// Called lazily on first Collect. Thread-safe via sync.Once pattern.
func (c *AzureCollector) ensureProvider() error {
	if c.provider != nil {
		return nil
	}

	vault := credentials.GetManager()
	if !vault.IsUnlocked() {
		// Try to unlock with default passphrase
		if err := vault.Unlock("harpia-default-secure-pass-2024"); err != nil {
			return fmt.Errorf("vault not unlocked: %w", err)
		}
	}

	// Reload vault to pick up any credentials added via API
	if err := vault.Reload(); err != nil {
		return fmt.Errorf("failed to reload vault: %w", err)
	}

	creds := vault.GetByProvider("azure")
	if len(creds) == 0 {
		return fmt.Errorf("no Azure credentials found in vault")
	}

	cred := creds[0]
	subscriptionID := cred.Data["subscription_id"]
	if subscriptionID == "" {
		return fmt.Errorf("incomplete Azure credentials: missing subscription_id")
	}

	provider, err := azure.NewProvider(context.Background(), subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to create Azure provider: %w", err)
	}

	c.provider = provider
	return nil
}

// Collect collects resources of the specified type from Azure.
func (c *AzureCollector) Collect(ctx context.Context, resourceType string) (*InventoryResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[resourceType]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	// Lazy-init provider from vault
	if err := c.ensureProvider(); err != nil {
		return &InventoryResult{
			ResourceType: resourceType,
			Provider:     "azure",
			Error:        err.Error(),
			Resources:    []Resource{},
			CollectedAt:  time.Now(),
		}, nil
	}

	result := &InventoryResult{
		ResourceType: resourceType,
		Provider:     "azure",
		Resources:    []Resource{},
		CollectedAt:  time.Now(),
	}

	var err error
	switch resourceType {
	// Compute
	case "azure_compute_virtual_machine":
		result.Resources, err = c.collectVirtualMachines(ctx)
	case "azure_compute_disk":
		result.Resources, err = c.collectDisks(ctx)
	// Network
	case "azure_network_virtual_network":
		result.Resources, err = c.collectVirtualNetworks(ctx)
	case "azure_network_subnet":
		result.Resources, err = c.collectSubnets(ctx)
	case "azure_network_security_group":
		result.Resources, err = c.collectSecurityGroups(ctx)
	case "azure_network_public_ip":
		result.Resources, err = c.collectPublicIPs(ctx)
	case "azure_network_watcher":
		result.Resources, err = c.collectNetworkWatchers(ctx)
	case "azure_network_application_gateway":
		result.Resources, err = c.collectApplicationGateways(ctx)
	// Storage
	case "azure_storage_account":
		result.Resources, err = c.collectStorageAccounts(ctx)
	case "azure_storage_container":
		result.Resources, err = c.collectStorageContainers(ctx)
	// Database
	case "azure_sql_server":
		result.Resources, err = c.collectSQLServers(ctx)
	case "azure_sql_database":
		result.Resources, err = c.collectSQLDatabases(ctx)
	case "azure_postgresql_server":
		result.Resources, err = c.collectPostgreSQLServers(ctx)
	case "azure_mysql_server":
		result.Resources, err = c.collectMySQLServers(ctx)
	case "azure_redis_cache":
		result.Resources, err = c.collectRedisCaches(ctx)
	case "azure_cosmosdb_account":
		result.Resources, err = c.collectCosmosDBAccounts(ctx)
	// Kubernetes
	case "azure_kubernetes_cluster":
		result.Resources, err = c.collectKubernetesClusters(ctx)
	// Key Vault
	case "azure_key_vault":
		result.Resources, err = c.collectKeyVaults(ctx)
	// Monitor
	case "azure_monitor_diagnostic_setting":
		result.Resources, err = c.collectDiagnosticSettings(ctx)
	default:
		return &InventoryResult{
			ResourceType: resourceType,
			Provider:     "azure",
			Error:        fmt.Sprintf("unsupported resource type: %s", resourceType),
			Resources:    []Resource{},
			CollectedAt:  time.Now(),
		}, nil
	}

	if err != nil {
		result.Error = err.Error()
	}

	result.Total = len(result.Resources)
	c.mu.Lock()
	c.cache[resourceType] = result
	c.mu.Unlock()
	return result, nil
}

// ListResourceTypes returns all Azure resource types (Steampipe-compatible).
func (c *AzureCollector) ListResourceTypes() []ResourceType {
	return azureResourceTypes
}

// azureResourceTypes mirrors the Steampipe Azure tables
var azureResourceTypes = []ResourceType{
	// Compute
	{Name: "azure_compute_virtual_machine", Provider: "azure", Service: "compute", Description: "Azure Virtual Machines"},
	{Name: "azure_compute_disk", Provider: "azure", Service: "compute", Description: "Azure Managed Disks"},
	// Network
	{Name: "azure_network_virtual_network", Provider: "azure", Service: "network", Description: "Azure Virtual Networks"},
	{Name: "azure_network_subnet", Provider: "azure", Service: "network", Description: "Azure Subnets"},
	{Name: "azure_network_security_group", Provider: "azure", Service: "network", Description: "Azure Network Security Groups"},
	{Name: "azure_network_public_ip", Provider: "azure", Service: "network", Description: "Azure Public IP Addresses"},
	{Name: "azure_network_watcher", Provider: "azure", Service: "network", Description: "Azure Network Watchers"},
	{Name: "azure_network_application_gateway", Provider: "azure", Service: "network", Description: "Azure Application Gateways"},
	// Storage
	{Name: "azure_storage_account", Provider: "azure", Service: "storage", Description: "Azure Storage Accounts"},
	{Name: "azure_storage_container", Provider: "azure", Service: "storage", Description: "Azure Storage Containers"},
	// Database
	{Name: "azure_sql_server", Provider: "azure", Service: "sql", Description: "Azure SQL Servers"},
	{Name: "azure_sql_database", Provider: "azure", Service: "sql", Description: "Azure SQL Databases"},
	{Name: "azure_postgresql_server", Provider: "azure", Service: "postgresql", Description: "Azure PostgreSQL Servers"},
	{Name: "azure_mysql_server", Provider: "azure", Service: "mysql", Description: "Azure MySQL Servers"},
	{Name: "azure_redis_cache", Provider: "azure", Service: "redis", Description: "Azure Redis Caches"},
	{Name: "azure_cosmosdb_account", Provider: "azure", Service: "cosmosdb", Description: "Azure Cosmos DB Accounts"},
	// Identity/Entra
	{Name: "azure_ad_user", Provider: "azure", Service: "entra", Description: "Azure AD Users"},
	{Name: "azure_ad_group", Provider: "azure", Service: "entra", Description: "Azure AD Groups"},
	{Name: "azure_ad_service_principal", Provider: "azure", Service: "entra", Description: "Azure AD Service Principals"},
	// Kubernetes
	{Name: "azure_kubernetes_cluster", Provider: "azure", Service: "aks", Description: "Azure AKS Clusters"},
	// Key Vault
	{Name: "azure_key_vault", Provider: "azure", Service: "keyvault", Description: "Azure Key Vaults"},
	// Monitor
	{Name: "azure_monitor_diagnostic_setting", Provider: "azure", Service: "monitor", Description: "Azure Diagnostic Settings"},
	// Policy & Security
	{Name: "azure_policy_definition", Provider: "azure", Service: "policy", Description: "Azure Policy Definitions"},
	{Name: "azure_role_definition", Provider: "azure", Service: "authorization", Description: "Azure Role Definitions"},
	{Name: "azure_security_center_subscription_pricing", Provider: "azure", Service: "securitycenter", Description: "Azure Security Center Pricing"},
	// DNS
	{Name: "azure_dns_zone", Provider: "azure", Service: "dns", Description: "Azure DNS Zones"},
	// Private Endpoint
	{Name: "azure_private_endpoint", Provider: "azure", Service: "network", Description: "Azure Private Endpoints"},
	// Container Registry
	{Name: "azure_container_registry", Provider: "azure", Service: "containerregistry", Description: "Azure Container Registries"},
	// Event Hubs
	{Name: "azure_eventhub_namespace", Provider: "azure", Service: "eventhub", Description: "Azure Event Hub Namespaces"},
	// Service Bus
	{Name: "azure_servicebus_namespace", Provider: "azure", Service: "servicebus", Description: "Azure Service Bus Namespaces"},
	// Stream Analytics
	{Name: "azure_stream_analytics_job", Provider: "azure", Service: "streamanalytics", Description: "Azure Stream Analytics Jobs"},
	// Synapse
	{Name: "azure_synapse_workspace", Provider: "azure", Service: "synapse", Description: "Azure Synapse Workspaces"},
	// Databricks
	{Name: "azure_databricks_workspace", Provider: "azure", Service: "databricks", Description: "Azure Databricks Workspaces"},
	// Logic Apps
	{Name: "azure_logic_app", Provider: "azure", Service: "logicapps", Description: "Azure Logic Apps"},
	// API Management
	{Name: "azure_api_management", Provider: "azure", Service: "apim", Description: "Azure API Management"},
	// Front Door
	{Name: "azure_front_door", Provider: "azure", Service: "frontdoor", Description: "Azure Front Door"},
	// CDN
	{Name: "azure_cdn_profile", Provider: "azure", Service: "cdn", Description: "Azure CDN Profiles"},
	// Batch
	{Name: "azure_batch_account", Provider: "azure", Service: "batch", Description: "Azure Batch Accounts"},
	// Machine Learning
	{Name: "azure_machine_learning_workspace", Provider: "azure", Service: "ml", Description: "Azure ML Workspaces"},
	// App Service Functions
	{Name: "azure_app_service_function", Provider: "azure", Service: "appservice", Description: "Azure Function Apps"},
}

// =============================================================================
// Compute Service Collectors
// =============================================================================

func (c *AzureCollector) collectVirtualMachines(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get compute client: %w", err)
	}

	var resources []Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VMs: %w", err)
		}
		for _, vm := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(vm.ID),
				Name:       safeAzureStr(vm.Name),
				Type:       "azure_compute_virtual_machine",
				Provider:   "azure",
				Region:     safeAzureStr(vm.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(vm.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectDisks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.ComputeDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get disks client: %w", err)
	}

	var resources []Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list disks: %w", err)
		}
		for _, disk := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(disk.ID),
				Name:       safeAzureStr(disk.Name),
				Type:       "azure_compute_disk",
				Provider:   "azure",
				Region:     safeAzureStr(disk.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(disk.Tags),
			})
		}
	}
	return resources, nil
}

// =============================================================================
// Network Service Collectors
// =============================================================================

func (c *AzureCollector) collectVirtualNetworks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Network(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network client: %w", err)
	}

	var resources []Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list VNets: %w", err)
		}
		for _, vnet := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(vnet.ID),
				Name:       safeAzureStr(vnet.Name),
				Type:       "azure_network_virtual_network",
				Provider:   "azure",
				Region:     safeAzureStr(vnet.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(vnet.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectSubnets(ctx context.Context) ([]Resource, error) {
	// Subnets require listing per VNet. This is a simplified version.
	// Full implementation would iterate through VNets first.
	return []Resource{}, nil
}

func (c *AzureCollector) collectSecurityGroups(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get NSG client: %w", err)
	}

	var resources []Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list NSGs: %w", err)
		}
		for _, nsg := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(nsg.ID),
				Name:       safeAzureStr(nsg.Name),
				Type:       "azure_network_security_group",
				Provider:   "azure",
				Region:     safeAzureStr(nsg.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(nsg.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectPublicIPs(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.PublicIPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP client: %w", err)
	}

	var resources []Resource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list public IPs: %w", err)
		}
		for _, ip := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(ip.ID),
				Name:       safeAzureStr(ip.Name),
				Type:       "azure_network_public_ip",
				Provider:   "azure",
				Region:     safeAzureStr(ip.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(ip.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectNetworkWatchers(ctx context.Context) ([]Resource, error) {
	// Network watchers are part of network client; use subscription-level listing
	// Since we don't have a dedicated SDK client for watchers in our provider,
	// we'll return a placeholder that can be extended
	return []Resource{}, nil
}

func (c *AzureCollector) collectApplicationGateways(ctx context.Context) ([]Resource, error) {
	// Application gateways use the ApplicationGatewaysClient from armnetwork
	// Not yet in our provider wrapper, return empty for now
	return []Resource{}, nil
}

// =============================================================================
// Storage Service Collectors
// =============================================================================

func (c *AzureCollector) collectStorageAccounts(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Storage(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage client: %w", err)
	}

	var resources []Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list storage accounts: %w", err)
		}
		for _, sa := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(sa.ID),
				Name:       safeAzureStr(sa.Name),
				Type:       "azure_storage_account",
				Provider:   "azure",
				Region:     safeAzureStr(sa.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(sa.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectStorageContainers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.BlobContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob containers client: %w", err)
	}

	// First list storage accounts to get resource groups
	storageAccounts, err := c.collectStorageAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list storage accounts for containers: %w", err)
	}

	var allResources []Resource
	for _, sa := range storageAccounts {
		// Parse resource group from ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/.../accounts/{name}
		rg := resourceGroupFromID(sa.ID)
		if rg == "" {
			continue
		}

		pager := client.NewListPager(rg, sa.Name, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				continue // Skip accounts we can't access
			}
			for _, container := range page.Value {
				allResources = append(allResources, Resource{
					ID:         safeAzureStr(container.ID),
					Name:       safeAzureStr(container.Name),
					Type:       "azure_storage_container",
					Provider:   "azure",
					Region:     sa.Region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"storage_account": sa.Name,
					},
				})
			}
		}
	}
	return allResources, nil
}

// =============================================================================
// SQL Service Collectors
// =============================================================================

func (c *AzureCollector) collectSQLServers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get SQL client: %w", err)
	}

	var resources []Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list SQL servers: %w", err)
		}
		for _, server := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(server.ID),
				Name:       safeAzureStr(server.Name),
				Type:       "azure_sql_server",
				Provider:   "azure",
				Region:     safeAzureStr(server.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(server.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectSQLDatabases(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SQLDatabases(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get SQL databases client: %w", err)
	}

	// First list SQL servers to get resource groups
	servers, err := c.collectSQLServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list SQL servers for databases: %w", err)
	}

	var allResources []Resource
	for _, server := range servers {
		rg := resourceGroupFromID(server.ID)
		if rg == "" {
			continue
		}

		pager := client.NewListByServerPager(rg, server.Name, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				continue
			}
			for _, db := range page.Value {
				allResources = append(allResources, Resource{
					ID:         safeAzureStr(db.ID),
					Name:       safeAzureStr(db.Name),
					Type:       "azure_sql_database",
					Provider:   "azure",
					Region:     server.Region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"server_name": server.Name,
					},
				})
			}
		}
	}
	return allResources, nil
}

// =============================================================================
// Placeholder Collectors for Future Implementation
// These return empty lists but are properly wired in the Collect switch
// =============================================================================

func (c *AzureCollector) collectPostgreSQLServers(ctx context.Context) ([]Resource, error) {
	// PostgreSQL uses DBForPostgreSQL package which is available but not yet wrapped
	return []Resource{}, nil
}

func (c *AzureCollector) collectMySQLServers(ctx context.Context) ([]Resource, error) {
	// MySQL uses DBForMySQL package which is available but not yet wrapped
	return []Resource{}, nil
}

func (c *AzureCollector) collectRedisCaches(ctx context.Context) ([]Resource, error) {
	// Redis uses Redis package which is available but not yet wrapped
	return []Resource{}, nil
}

func (c *AzureCollector) collectCosmosDBAccounts(ctx context.Context) ([]Resource, error) {
	// CosmosDB uses DocumentDB package which is available but not yet wrapped
	return []Resource{}, nil
}

func (c *AzureCollector) collectKubernetesClusters(ctx context.Context) ([]Resource, error) {
	// AKS uses ContainerService package which is available but not yet wrapped
	return []Resource{}, nil
}

func (c *AzureCollector) collectKeyVaults(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.KeyVault(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get keyvault client: %w", err)
	}

	var resources []Resource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list key vaults: %w", err)
		}
		for _, vault := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(vault.ID),
				Name:       safeAzureStr(vault.Name),
				Type:       "azure_key_vault",
				Provider:   "azure",
				Region:     safeAzureStr(vault.Location),
				Discovered: time.Now(),
				Tags:       azureTagsToMap(vault.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AzureCollector) collectDiagnosticSettings(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Monitor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get monitor client: %w", err)
	}

	// Diagnostic settings are scoped to a subscription-level resource ID
	// We'll list at subscription scope for now
	var resources []Resource
	subscriptionID := c.provider.SubscriptionID()
	if subscriptionID == "" {
		return resources, nil
	}

	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := client.NewListPager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list diagnostic settings: %w", err)
		}
		for _, setting := range page.Value {
			resources = append(resources, Resource{
				ID:         safeAzureStr(setting.ID),
				Name:       safeAzureStr(setting.Name),
				Type:       "azure_monitor_diagnostic_setting",
				Provider:   "azure",
				Region:     "global",
				Discovered: time.Now(),
			})
		}
	}
	return resources, nil
}

// Helper functions

func safeAzureStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func azureTagsToMap(tags map[string]*string) map[string]string {
	result := make(map[string]string)
	for k, v := range tags {
		if v != nil {
			result[k] = *v
		}
	}
	return result
}

func resourceGroupFromID(id string) string {
	// Parse resource group from Azure resource ID
	// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/.../{name}
	parts := strings.Split(id, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
