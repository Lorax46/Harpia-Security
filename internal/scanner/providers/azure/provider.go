package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// Provider representa um cliente Azure autenticado.
type Provider struct {
	subscriptionID string
	credential     *azidentity.DefaultAzureCredential
}

// NewProvider cria um novo provider Azure.
func NewProvider(ctx context.Context, subscriptionID string) (*Provider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar credencial Azure: %w", err)
	}

	return &Provider{
		subscriptionID: subscriptionID,
		credential:     cred,
	}, nil
}

// SubscriptionID retorna o ID da subscription configurada.
func (p *Provider) SubscriptionID() string {
	return p.subscriptionID
}

// Compute retorna o cliente de Compute (VMs, Disks).
func (p *Provider) Compute(ctx context.Context) (*armcompute.VirtualMachinesClient, error) {
	return armcompute.NewVirtualMachinesClient(p.subscriptionID, p.credential, nil)
}

// ComputeDisks retorna o cliente de Disks.
func (p *Provider) ComputeDisks(ctx context.Context) (*armcompute.DisksClient, error) {
	return armcompute.NewDisksClient(p.subscriptionID, p.credential, nil)
}

// Network retorna o cliente de Network (VNets, Subnets, NSGs, Public IPs).
func (p *Provider) Network(ctx context.Context) (*armnetwork.VirtualNetworksClient, error) {
	return armnetwork.NewVirtualNetworksClient(p.subscriptionID, p.credential, nil)
}

// Subnets retorna o cliente de Subnets.
func (p *Provider) Subnets(ctx context.Context) (*armnetwork.SubnetsClient, error) {
	return armnetwork.NewSubnetsClient(p.subscriptionID, p.credential, nil)
}

// SecurityGroups retorna o cliente de NSGs.
func (p *Provider) SecurityGroups(ctx context.Context) (*armnetwork.SecurityGroupsClient, error) {
	return armnetwork.NewSecurityGroupsClient(p.subscriptionID, p.credential, nil)
}

// PublicIPs retorna o cliente de Public IPs.
func (p *Provider) PublicIPs(ctx context.Context) (*armnetwork.PublicIPAddressesClient, error) {
	return armnetwork.NewPublicIPAddressesClient(p.subscriptionID, p.credential, nil)
}

// Storage retorna o cliente de Storage Accounts.
func (p *Provider) Storage(ctx context.Context) (*armstorage.AccountsClient, error) {
	return armstorage.NewAccountsClient(p.subscriptionID, p.credential, nil)
}

// BlobContainers retorna o cliente de Blob Containers.
func (p *Provider) BlobContainers(ctx context.Context) (*armstorage.BlobContainersClient, error) {
	return armstorage.NewBlobContainersClient(p.subscriptionID, p.credential, nil)
}

// SQL retorna o cliente de SQL Servers.
func (p *Provider) SQL(ctx context.Context) (*armsql.ServersClient, error) {
	return armsql.NewServersClient(p.subscriptionID, p.credential, nil)
}

// SQLDatabases retorna o cliente de SQL Databases.
func (p *Provider) SQLDatabases(ctx context.Context) (*armsql.DatabasesClient, error) {
	return armsql.NewDatabasesClient(p.subscriptionID, p.credential, nil)
}

// KeyVault retorna o cliente de Key Vaults.
func (p *Provider) KeyVault(ctx context.Context) (*armkeyvault.VaultsClient, error) {
	return armkeyvault.NewVaultsClient(p.subscriptionID, p.credential, nil)
}

// Monitor retorna o cliente de Diagnostic Settings.
func (p *Provider) Monitor(ctx context.Context) (*armmonitor.DiagnosticSettingsClient, error) {
	return armmonitor.NewDiagnosticSettingsClient(p.credential, nil)
}
