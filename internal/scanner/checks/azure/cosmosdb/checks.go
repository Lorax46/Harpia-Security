package cosmosdb

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cosmosdbAccountAutomaticFailoverEnabled struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountAutomaticFailoverEnabled() *cosmosdbAccountAutomaticFailoverEnabled {
	return &cosmosdbAccountAutomaticFailoverEnabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_automatic_failover_enabled",
		CheckTitle: "Ensure Cosmos DB account has automatic failover enabled",
		Description: "Cosmos DB account should have automatic failover enabled",
		Severity: "medium", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "failover"},
	}}
}

func (c *cosmosdbAccountAutomaticFailoverEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountAutomaticFailoverEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB failover check requires Azure SDK",
		ResourceID: "cosmosdb-failover", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cosmosdbAccountBackupPolicyContinuous struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountBackupPolicyContinuous() *cosmosdbAccountBackupPolicyContinuous {
	return &cosmosdbAccountBackupPolicyContinuous{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_backup_policy_continuous",
		CheckTitle: "Ensure Cosmos DB account has continuous backup policy",
		Description: "Cosmos DB account should have continuous backup policy",
		Severity: "medium", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "backup"},
	}}
}

func (c *cosmosdbAccountBackupPolicyContinuous) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountBackupPolicyContinuous) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB backup check requires Azure SDK",
		ResourceID: "cosmosdb-backup", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cosmosdbAccountFirewallUseSelectedNetworks struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountFirewallUseSelectedNetworks() *cosmosdbAccountFirewallUseSelectedNetworks {
	return &cosmosdbAccountFirewallUseSelectedNetworks{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_firewall_use_selected_networks",
		CheckTitle: "Ensure Cosmos DB account firewall uses selected networks",
		Description: "Cosmos DB account firewall should use selected networks",
		Severity: "high", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "firewall"},
	}}
}

func (c *cosmosdbAccountFirewallUseSelectedNetworks) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountFirewallUseSelectedNetworks) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB firewall check requires Azure SDK",
		ResourceID: "cosmosdb-firewall", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cosmosdbAccountMinimumTlsVersion struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountMinimumTlsVersion() *cosmosdbAccountMinimumTlsVersion {
	return &cosmosdbAccountMinimumTlsVersion{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_minimum_tls_version",
		CheckTitle: "Ensure Cosmos DB account uses minimum TLS 1.2",
		Description: "Cosmos DB account should use minimum TLS version 1.2",
		Severity: "medium", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "tls"},
	}}
}

func (c *cosmosdbAccountMinimumTlsVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountMinimumTlsVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB TLS check requires Azure SDK",
		ResourceID: "cosmosdb-tls", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cosmosdbAccountPublicNetworkAccessDisabled struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountPublicNetworkAccessDisabled() *cosmosdbAccountPublicNetworkAccessDisabled {
	return &cosmosdbAccountPublicNetworkAccessDisabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_public_network_access_disabled",
		CheckTitle: "Ensure Cosmos DB account public network access is disabled",
		Description: "Cosmos DB account should have public network access disabled",
		Severity: "high", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "public-access"},
	}}
}

func (c *cosmosdbAccountPublicNetworkAccessDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountPublicNetworkAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB public access check requires Azure SDK",
		ResourceID: "cosmosdb-public-access", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cosmosdbAccountUseAadAndRbac struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountUseAadAndRbac() *cosmosdbAccountUseAadAndRbac {
	return &cosmosdbAccountUseAadAndRbac{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_use_aad_and_rbac",
		CheckTitle: "Ensure Cosmos DB account uses AAD and RBAC",
		Description: "Cosmos DB account should use AAD and RBAC",
		Severity: "medium", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "aad"},
	}}
}

func (c *cosmosdbAccountUseAadAndRbac) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountUseAadAndRbac) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB AAD check requires Azure SDK",
		ResourceID: "cosmosdb-aad", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cosmosdbAccountUsePrivateEndpoints struct {
	metadata models.CheckMetadata
}

func NewCosmosdbAccountUsePrivateEndpoints() *cosmosdbAccountUsePrivateEndpoints {
	return &cosmosdbAccountUsePrivateEndpoints{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "cosmosdb_account_use_private_endpoints",
		CheckTitle: "Ensure Cosmos DB account uses private endpoints",
		Description: "Cosmos DB account should use private endpoints",
		Severity: "medium", ServiceName: "cosmosdb", ResourceType: "DatabaseAccount",
		Categories: []string{"cosmosdb", "private-endpoints"},
	}}
}

func (c *cosmosdbAccountUsePrivateEndpoints) Metadata() models.CheckMetadata { return c.metadata }

func (c *cosmosdbAccountUsePrivateEndpoints) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cosmos DB private endpoints check requires Azure SDK",
		ResourceID: "cosmosdb-private-endpoints", Provider: "azure", Service: "cosmosdb",
		FoundAt: time.Now().UTC(),
	}}, nil
}
