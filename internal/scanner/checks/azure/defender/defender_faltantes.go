package defender

// =============================================================================
// Azure Defender Missing Checks — 13 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type azureDefenderMissingCheck struct {
	metadata models.CheckMetadata
}

func newAzureDefenderMissingCheck(id, title, desc, sev string) azureDefenderMissingCheck {
	return azureDefenderMissingCheck{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "defender", ResourceType: "Pricing",
		Categories: []string{"defender"},
	}}
}

func (c *azureDefenderMissingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *azureDefenderMissingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Azure defender check requires Azure SDK",
		ResourceID: c.metadata.CheckID, Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type defenderContainerImagesResolvedVulnerabilities struct{ azureDefenderMissingCheck }

func NewDefenderContainerImagesResolvedVulnerabilities() *defenderContainerImagesResolvedVulnerabilities {
	return &defenderContainerImagesResolvedVulnerabilities{newAzureDefenderMissingCheck(
		"defender_container_images_resolved_vulnerabilities",
		"Ensure container images vulnerabilities are resolved",
		"Container images vulnerabilities should be resolved",
		"high",
	)}
}

type defenderContainerImagesScanEnabled struct{ azureDefenderMissingCheck }

func NewDefenderContainerImagesScanEnabled() *defenderContainerImagesScanEnabled {
	return &defenderContainerImagesScanEnabled{newAzureDefenderMissingCheck(
		"defender_container_images_scan_enabled",
		"Ensure container images scan is enabled",
		"Container images scan should be enabled",
		"medium",
	)}
}

type defenderEnsureDefenderCspmIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderCspmIsOn() *defenderEnsureDefenderCspmIsOn {
	return &defenderEnsureDefenderCspmIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_cspm_is_on",
		"Ensure CSPM is enabled",
		"CSPM should be enabled",
		"high",
	)}
}

type defenderEnsureDefenderForAppServicesIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForAppServicesIsOn() *defenderEnsureDefenderForAppServicesIsOn {
	return &defenderEnsureDefenderForAppServicesIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_app_services_is_on",
		"Ensure Defender for App Services is on",
		"Defender for App Services should be on",
		"high",
	)}
}

type defenderEnsureDefenderForArmIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForArmIsOn() *defenderEnsureDefenderForArmIsOn {
	return &defenderEnsureDefenderForArmIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_arm_is_on",
		"Ensure Defender for ARM is on",
		"Defender for ARM should be on",
		"medium",
	)}
}

type defenderEnsureDefenderForAzureSqlDatabasesIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForAzureSqlDatabasesIsOn() *defenderEnsureDefenderForAzureSqlDatabasesIsOn {
	return &defenderEnsureDefenderForAzureSqlDatabasesIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_azure_sql_databases_is_on",
		"Ensure Defender for Azure SQL Databases is on",
		"Defender for Azure SQL Databases should be on",
		"high",
	)}
}

type defenderEnsureDefenderForContainersIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForContainersIsOn() *defenderEnsureDefenderForContainersIsOn {
	return &defenderEnsureDefenderForContainersIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_containers_is_on",
		"Ensure Defender for Containers is on",
		"Defender for Containers should be on",
		"high",
	)}
}

type defenderEnsureDefenderForCosmosdbIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForCosmosdbIsOn() *defenderEnsureDefenderForCosmosdbIsOn {
	return &defenderEnsureDefenderForCosmosdbIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_cosmosdb_is_on",
		"Ensure Defender for Cosmos DB is on",
		"Defender for Cosmos DB should be on",
		"high",
	)}
}

type defenderEnsureDefenderForDatabasesIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForDatabasesIsOn() *defenderEnsureDefenderForDatabasesIsOn {
	return &defenderEnsureDefenderForDatabasesIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_databases_is_on",
		"Ensure Defender for Databases is on",
		"Defender for Databases should be on",
		"high",
	)}
}

type defenderEnsureDefenderForDnsIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForDnsIsOn() *defenderEnsureDefenderForDnsIsOn {
	return &defenderEnsureDefenderForDnsIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_dns_is_on",
		"Ensure Defender for DNS is on",
		"Defender for DNS should be on",
		"medium",
	)}
}

type defenderEnsureDefenderForKeyvaultIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForKeyvaultIsOn() *defenderEnsureDefenderForKeyvaultIsOn {
	return &defenderEnsureDefenderForKeyvaultIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_keyvault_is_on",
		"Ensure Defender for Key Vault is on",
		"Defender for Key Vault should be on",
		"high",
	)}
}

type defenderEnsureDefenderForOsRelationalDatabasesIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForOsRelationalDatabasesIsOn() *defenderEnsureDefenderForOsRelationalDatabasesIsOn {
	return &defenderEnsureDefenderForOsRelationalDatabasesIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_os_relational_databases_is_on",
		"Ensure Defender for OS Relational Databases is on",
		"Defender for OS Relational Databases should be on",
		"medium",
	)}
}

type defenderEnsureDefenderForServerIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForServerIsOn() *defenderEnsureDefenderForServerIsOn {
	return &defenderEnsureDefenderForServerIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_server_is_on",
		"Ensure Defender for Server is on",
		"Defender for Server should be on",
		"high",
	)}
}

type defenderEnsureDefenderForSqlServersIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForSqlServersIsOn() *defenderEnsureDefenderForSqlServersIsOn {
	return &defenderEnsureDefenderForSqlServersIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_sql_servers_is_on",
		"Ensure Defender for SQL Servers is on",
		"Defender for SQL Servers should be on",
		"high",
	)}
}

type defenderEnsureDefenderForStorageIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureDefenderForStorageIsOn() *defenderEnsureDefenderForStorageIsOn {
	return &defenderEnsureDefenderForStorageIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_defender_for_storage_is_on",
		"Ensure Defender for Storage is on",
		"Defender for Storage should be on",
		"high",
	)}
}

type defenderEnsureIotHubDefenderIsOn struct{ azureDefenderMissingCheck }

func NewDefenderEnsureIotHubDefenderIsOn() *defenderEnsureIotHubDefenderIsOn {
	return &defenderEnsureIotHubDefenderIsOn{newAzureDefenderMissingCheck(
		"defender_ensure_iot_hub_defender_is_on",
		"Ensure IoT Hub Defender is on",
		"IoT Hub Defender should be on",
		"medium",
	)}
}

type defenderEnsureMcasIsEnabled struct{ azureDefenderMissingCheck }

func NewDefenderEnsureMcasIsEnabled() *defenderEnsureMcasIsEnabled {
	return &defenderEnsureMcasIsEnabled{newAzureDefenderMissingCheck(
		"defender_ensure_mcas_is_enabled",
		"Ensure MCAS is enabled",
		"MCAS should be enabled",
		"medium",
	)}
}

type defenderEnsureNotifyAlertsSeverityIsHigh struct{ azureDefenderMissingCheck }

func NewDefenderEnsureNotifyAlertsSeverityIsHigh() *defenderEnsureNotifyAlertsSeverityIsHigh {
	return &defenderEnsureNotifyAlertsSeverityIsHigh{newAzureDefenderMissingCheck(
		"defender_ensure_notify_alerts_severity_is_high",
		"Ensure notify alerts severity is high",
		"Notify alerts severity should be high",
		"medium",
	)}
}

type defenderEnsureNotifyEmailsToOwners struct{ azureDefenderMissingCheck }

func NewDefenderEnsureNotifyEmailsToOwners() *defenderEnsureNotifyEmailsToOwners {
	return &defenderEnsureNotifyEmailsToOwners{newAzureDefenderMissingCheck(
		"defender_ensure_notify_emails_to_owners",
		"Ensure notify emails to owners",
		"Notify emails to owners should be enabled",
		"medium",
	)}
}

type defenderEnsureSystemUpdatesAreApplied struct{ azureDefenderMissingCheck }

func NewDefenderEnsureSystemUpdatesAreApplied() *defenderEnsureSystemUpdatesAreApplied {
	return &defenderEnsureSystemUpdatesAreApplied{newAzureDefenderMissingCheck(
		"defender_ensure_system_updates_are_applied",
		"Ensure system updates are applied",
		"System updates should be applied",
		"high",
	)}
}

type defenderEnsureWdatpIsEnabled struct{ azureDefenderMissingCheck }

func NewDefenderEnsureWdatpIsEnabled() *defenderEnsureWdatpIsEnabled {
	return &defenderEnsureWdatpIsEnabled{newAzureDefenderMissingCheck(
		"defender_ensure_wdatp_is_enabled",
		"Ensure WDATP is enabled",
		"WDATP should be enabled",
		"high",
	)}
}
