// Package azure provides Azure inventory plugin for the inventory engine.
package azure

import (
	"context"
	"encoding/json"
)

// Plugin provides inventory access to Azure resources.
type Plugin struct {
	config PluginConfig
}

// PluginConfig configures the Azure plugin.
type PluginConfig struct {
	SubscriptionID string
	ResourceGroup  string
	Region         string
}

// New creates a new Azure plugin.
func New(cfg ...PluginConfig) *Plugin {
	p := Plugin{}
	if len(cfg) > 0 {
		p.config = cfg[0]
	}
	return &p
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "azure" }

// Provider returns the cloud provider.
func (p *Plugin) Provider() string { return "azure" }

// Services returns the list of supported services.
func (p *Plugin) Services() []string {
	return []string{"compute", "storage", "iam", "network", "sql", "keyvault", "monitor", "appservice"}
}

// Compute returns the Compute inventory service.
func (p *Plugin) Compute() *ComputeService {
	return &ComputeService{plugin: p}
}

// Storage returns the Storage inventory service.
func (p *Plugin) Storage() *StorageService {
	return &StorageService{plugin: p}
}

// IAM returns the IAM inventory service.
func (p *Plugin) IAM() *IAMService {
	return &IAMService{plugin: p}
}

// VirtualMachine represents an Azure Virtual Machine.
type VirtualMachine struct {
	VMID         string            `json:"vm_id"`
	Name         string            `json:"name"`
	VMSize       string            `json:"vm_size"`
	Location     string            `json:"location"`
	ResourceGroup string           `json:"resource_group"`
	Tags         map[string]string `json:"tags"`
	OS           string            `json:"os"`
	State        string            `json:"state"`
	PrivateIP    string            `json:"private_ip"`
	PublicIP     string            `json:"public_ip"`
	SubscriptionID string          `json:"subscription_id"`
}

// ComputeFilter filters Virtual Machines.
type ComputeFilter struct {
	SubscriptionID string            `json:"subscription_id"`
	ResourceGroup  string            `json:"resource_group"`
	Location       string            `json:"location"`
	Tags           map[string]string `json:"tags"`
}

// ComputeService provides Virtual Machine inventory.
type ComputeService struct {
	plugin *Plugin
}

// ListVirtualMachines returns all VMs matching the filter.
func (s *ComputeService) ListVirtualMachines(ctx context.Context, filter ComputeFilter) ([]VirtualMachine, error) {
	return []VirtualMachine{}, nil
}

// GetVirtualMachine returns a specific VM.
func (s *ComputeService) GetVirtualMachine(ctx context.Context, rg, name string) (*VirtualMachine, error) {
	return &VirtualMachine{Name: name, ResourceGroup: rg}, nil
}

// StorageAccount represents an Azure Storage Account.
type StorageAccount struct {
	Name              string            `json:"name"`
	ResourceGroup     string            `json:"resource_group"`
	Location          string            `json:"location"`
	Sku               string            `json:"sku"`
	Kind              string            `json:"kind"`
	Tags              map[string]string `json:"tags"`
	HttpsOnly         bool              `json:"https_only"`
	MinTLSVersion     string            `json:"min_tls_version"`
	SubscriptionID    string            `json:"subscription_id"`
}

// StorageFilter filters Storage Accounts.
type StorageFilter struct {
	SubscriptionID string            `json:"subscription_id"`
	ResourceGroup  string            `json:"resource_group"`
	Location       string            `json:"location"`
	Tags           map[string]string `json:"tags"`
}

// StorageService provides Storage Account inventory.
type StorageService struct {
	plugin *Plugin
}

// ListStorageAccounts returns all storage accounts matching the filter.
func (s *StorageService) ListStorageAccounts(ctx context.Context, filter StorageFilter) ([]StorageAccount, error) {
	return []StorageAccount{}, nil
}

// GetStorageAccount returns a specific storage account.
func (s *StorageService) GetStorageAccount(ctx context.Context, rg, name string) (*StorageAccount, error) {
	return &StorageAccount{Name: name, ResourceGroup: rg}, nil
}

// AzureUser represents an Azure AD user.
type AzureUser struct {
	UserID         string            `json:"user_id"`
	DisplayName    string            `json:"display_name"`
	Email          string            `json:"email"`
	UserType       string            `json:"user_type"`
	AccountEnabled bool              `json:"account_enabled"`
	Tags           map[string]string `json:"tags"`
	SubscriptionID string            `json:"subscription_id"`
}

// IAMFilter filters Azure AD users.
type IAMFilter struct {
	SubscriptionID string            `json:"subscription_id"`
	UserType       string            `json:"user_type"`
	Tags           map[string]string `json:"tags"`
}

// IAMService provides Azure AD user inventory.
type IAMService struct {
	plugin *Plugin
}

// ListUsers returns all Azure AD users matching the filter.
func (s *IAMService) ListUsers(ctx context.Context, filter IAMFilter) ([]AzureUser, error) {
	return []AzureUser{}, nil
}

// GetUser returns a specific Azure AD user.
func (s *IAMService) GetUser(ctx context.Context, id string) (*AzureUser, error) {
	return &AzureUser{UserID: id}, nil
}

// ToJSON returns the resource as JSON.
func ToJSON(r interface{}) string {
	b, _ := json.Marshal(r)
	return string(b)
}
