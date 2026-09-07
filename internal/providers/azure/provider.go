package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// Provider é o provider Azure
type Provider struct {
	subscriptionID string
	credential     *azidentity.DefaultAzureCredential
}

// NewProvider cria um novo provider Azure
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

// SubscriptionID retorna o ID da subscription
func (p *Provider) SubscriptionID() string {
	return p.subscriptionID
}

// ComputeClient retorna o cliente de Compute (Virtual Machines)
func (p *Provider) ComputeClient(ctx context.Context) (*armcompute.VirtualMachinesClient, error) {
	return armcompute.NewVirtualMachinesClient(p.subscriptionID, p.credential, nil)
}

// DisksClient retorna o cliente de Discos
func (p *Provider) DisksClient(ctx context.Context) (*armcompute.DisksClient, error) {
	return armcompute.NewDisksClient(p.subscriptionID, p.credential, nil)
}

// NetworkInterfacesClient retorna o cliente de Interfaces de Rede
func (p *Provider) NetworkInterfacesClient(ctx context.Context) (*armnetwork.InterfacesClient, error) {
	return armnetwork.NewInterfacesClient(p.subscriptionID, p.credential, nil)
}

// SecurityGroupsClient retorna o cliente de Security Groups
func (p *Provider) SecurityGroupsClient(ctx context.Context) (*armnetwork.SecurityGroupsClient, error) {
	return armnetwork.NewSecurityGroupsClient(p.subscriptionID, p.credential, nil)
}

// PublicIPAddressesClient retorna o cliente de IPs Públicos
func (p *Provider) PublicIPAddressesClient(ctx context.Context) (*armnetwork.PublicIPAddressesClient, error) {
	return armnetwork.NewPublicIPAddressesClient(p.subscriptionID, p.credential, nil)
}

// StorageAccountsClient retorna o cliente de Storage Accounts
func (p *Provider) StorageAccountsClient(ctx context.Context) (*armstorage.AccountsClient, error) {
	return armstorage.NewAccountsClient(p.subscriptionID, p.credential, nil)
}

// SQLDatabasesClient retorna o cliente de SQL Databases
func (p *Provider) SQLDatabasesClient(ctx context.Context) (*armsql.DatabasesClient, error) {
	return armsql.NewDatabasesClient(p.subscriptionID, p.credential, nil)
}

// KeyVaultsClient retorna o cliente de Key Vaults
func (p *Provider) KeyVaultsClient(ctx context.Context) (*armkeyvault.VaultsClient, error) {
	return armkeyvault.NewVaultsClient(p.subscriptionID, p.credential, nil)
}

// DiagnosticSettingsClient retorna o cliente de Diagnostic Settings
func (p *Provider) DiagnosticSettingsClient(ctx context.Context) (*armmonitor.DiagnosticSettingsClient, error) {
	return armmonitor.NewDiagnosticSettingsClient(p.credential, nil)
}

// WebAppsClient retorna o cliente de Web Apps (App Service)
func (p *Provider) WebAppsClient(ctx context.Context) (*armappservice.WebAppsClient, error) {
	return armappservice.NewWebAppsClient(p.subscriptionID, p.credential, nil)
}
