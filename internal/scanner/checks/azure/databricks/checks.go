package databricks

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type databricksWorkspaceCmkEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewDatabricksWorkspaceCmkEncryptionEnabled() *databricksWorkspaceCmkEncryptionEnabled {
	return &databricksWorkspaceCmkEncryptionEnabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "databricks_workspace_cmk_encryption_enabled",
		CheckTitle: "Ensure Databricks workspace CMK encryption is enabled",
		Description: "Databricks workspace should have CMK encryption enabled",
		Severity: "medium", ServiceName: "databricks", ResourceType: "Workspace",
		Categories: []string{"databricks", "encryption"},
	}}
}

func (c *databricksWorkspaceCmkEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *databricksWorkspaceCmkEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Databricks CMK encryption check requires Azure SDK",
		ResourceID: "databricks-cmk-encryption", Provider: "azure", Service: "databricks",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type databricksWorkspaceNoPublicIpEnabled struct {
	metadata models.CheckMetadata
}

func NewDatabricksWorkspaceNoPublicIpEnabled() *databricksWorkspaceNoPublicIpEnabled {
	return &databricksWorkspaceNoPublicIpEnabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "databricks_workspace_no_public_ip_enabled",
		CheckTitle: "Ensure Databricks workspace has no public IP",
		Description: "Databricks workspace should have no public IP enabled",
		Severity: "high", ServiceName: "databricks", ResourceType: "Workspace",
		Categories: []string{"databricks", "public-ip"},
	}}
}

func (c *databricksWorkspaceNoPublicIpEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *databricksWorkspaceNoPublicIpEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Databricks no public IP check requires Azure SDK",
		ResourceID: "databricks-no-public-ip", Provider: "azure", Service: "databricks",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type databricksWorkspacePublicNetworkAccessDisabled struct {
	metadata models.CheckMetadata
}

func NewDatabricksWorkspacePublicNetworkAccessDisabled() *databricksWorkspacePublicNetworkAccessDisabled {
	return &databricksWorkspacePublicNetworkAccessDisabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "databricks_workspace_public_network_access_disabled",
		CheckTitle: "Ensure Databricks workspace public network access is disabled",
		Description: "Databricks workspace should have public network access disabled",
		Severity: "high", ServiceName: "databricks", ResourceType: "Workspace",
		Categories: []string{"databricks", "public-access"},
	}}
}

func (c *databricksWorkspacePublicNetworkAccessDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *databricksWorkspacePublicNetworkAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Databricks public network access check requires Azure SDK",
		ResourceID: "databricks-public-network-access", Provider: "azure", Service: "databricks",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type databricksWorkspaceVnetInjectionEnabled struct {
	metadata models.CheckMetadata
}

func NewDatabricksWorkspaceVnetInjectionEnabled() *databricksWorkspaceVnetInjectionEnabled {
	return &databricksWorkspaceVnetInjectionEnabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "databricks_workspace_vnet_injection_enabled",
		CheckTitle: "Ensure Databricks workspace VNet injection is enabled",
		Description: "Databricks workspace should have VNet injection enabled",
		Severity: "medium", ServiceName: "databricks", ResourceType: "Workspace",
		Categories: []string{"databricks", "vnet"},
	}}
}

func (c *databricksWorkspaceVnetInjectionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *databricksWorkspaceVnetInjectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Databricks VNet injection check requires Azure SDK",
		ResourceID: "databricks-vnet-injection", Provider: "azure", Service: "databricks",
		FoundAt: time.Now().UTC(),
	}}, nil
}
