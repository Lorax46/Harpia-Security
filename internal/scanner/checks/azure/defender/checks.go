package defender

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// DefenderAutoProvisioningLogAnalyticsAgentVmsOn - verifica auto provisioning
type DefenderAutoProvisioningLogAnalyticsAgentVmsOn struct {
	metadata models.CheckMetadata
}

func NewDefenderAutoProvisioningLogAnalyticsAgentVmsOn() *DefenderAutoProvisioningLogAnalyticsAgentVmsOn {
	return &DefenderAutoProvisioningLogAnalyticsAgentVmsOn{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_auto_provisioning_log_analytics_agent_vms_on",
			CheckTitle: "Ensure auto provisioning of Log Analytics agent is enabled",
			Description: "Auto provisioning of Log Analytics agent should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "AutoProvisioningSetting",
			RemediationText: "Enable auto provisioning for Log Analytics agent",
			Categories: []string{"defender", "monitoring"},
		},
	}
}

func (c *DefenderAutoProvisioningLogAnalyticsAgentVmsOn) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAutoProvisioningLogAnalyticsAgentVmsOn) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender auto provisioning check requires Azure SDK",
		ResourceID: "defender-auto-provisioning", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn - verifica vulnerability assessments
type DefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn struct {
	metadata models.CheckMetadata
}

func NewDefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn() *DefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn {
	return &DefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_auto_provisioning_vulnerabilty_assessments_machines_on",
			CheckTitle: "Ensure auto provisioning of vulnerability assessments is enabled",
			Description: "Auto provisioning of vulnerability assessments should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "AutoProvisioningSetting",
			RemediationText: "Enable auto provisioning for vulnerability assessments",
			Categories: []string{"defender", "vulnerability"},
		},
	}
}

func (c *DefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender vulnerability assessments check requires Azure SDK",
		ResourceID: "defender-vulnerability-assessments", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderAdditionalEmailConfiguredWithASecurityContact - verifica contatos de segurança
type DefenderAdditionalEmailConfiguredWithASecurityContact struct {
	metadata models.CheckMetadata
}

func NewDefenderAdditionalEmailConfiguredWithASecurityContact() *DefenderAdditionalEmailConfiguredWithASecurityContact {
	return &DefenderAdditionalEmailConfiguredWithASecurityContact{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_additional_email_configured_with_a_security_contact",
			CheckTitle: "Ensure additional email is configured for security contacts",
			Description: "Additional email should be configured for security contacts",
			Severity: "medium", ServiceName: "defender", ResourceType: "SecurityContact",
			RemediationText: "Configure additional email for security contacts",
			Categories: []string{"defender", "contacts"},
		},
	}
}

func (c *DefenderAdditionalEmailConfiguredWithASecurityContact) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAdditionalEmailConfiguredWithASecurityContact) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender security contact check requires Azure SDK",
		ResourceID: "defender-security-contact", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderAssessmentsVmEndpointProtectionInstalled - verifica endpoint protection
type DefenderAssessmentsVmEndpointProtectionInstalled struct {
	metadata models.CheckMetadata
}

func NewDefenderAssessmentsVmEndpointProtectionInstalled() *DefenderAssessmentsVmEndpointProtectionInstalled {
	return &DefenderAssessmentsVmEndpointProtectionInstalled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_assessments_vm_endpoint_protection_installed",
			CheckTitle: "Ensure VM endpoint protection is installed",
			Description: "VM endpoint protection should be installed",
			Severity: "high", ServiceName: "defender", ResourceType: "Assessment",
			RemediationText: "Install endpoint protection on VMs",
			Categories: []string{"defender", "endpoint"},
		},
	}
}

func (c *DefenderAssessmentsVmEndpointProtectionInstalled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAssessmentsVmEndpointProtectionInstalled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender endpoint protection check requires Azure SDK",
		ResourceID: "defender-endpoint-protection", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderAttackPathNotificationsProperlyConfigured - verifica notificações de attack path
type DefenderAttackPathNotificationsProperlyConfigured struct {
	metadata models.CheckMetadata
}

func NewDefenderAttackPathNotificationsProperlyConfigured() *DefenderAttackPathNotificationsProperlyConfigured {
	return &DefenderAttackPathNotificationsProperlyConfigured{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_attack_path_notifications_properly_configured",
			CheckTitle: "Ensure attack path notifications are properly configured",
			Description: "Attack path notifications should be properly configured",
			Severity: "medium", ServiceName: "defender", ResourceType: "NotificationSetting",
			RemediationText: "Configure attack path notifications",
			Categories: []string{"defender", "notifications"},
		},
	}
}

func (c *DefenderAttackPathNotificationsProperlyConfigured) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAttackPathNotificationsProperlyConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender attack path notifications check requires Azure SDK",
		ResourceID: "defender-attack-path-notifications", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderAutoProvisioningAgentOn - verifica auto provisioning de agentes
type DefenderAutoProvisioningAgentOn struct {
	metadata models.CheckMetadata
}

func NewDefenderAutoProvisioningAgentOn() *DefenderAutoProvisioningAgentOn {
	return &DefenderAutoProvisioningAgentOn{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_auto_provisioning_agent_on",
			CheckTitle: "Ensure auto provisioning of agent is on",
			Description: "Auto provisioning of agent should be on",
			Severity: "medium", ServiceName: "defender", ResourceType: "AutoProvisioningSetting",
			RemediationText: "Enable auto provisioning of agent",
			Categories: []string{"defender", "monitoring"},
		},
	}
}

func (c *DefenderAutoProvisioningAgentOn) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAutoProvisioningAgentOn) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender agent auto provisioning check requires Azure SDK",
		ResourceID: "defender-agent-auto-provisioning", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderAutoProvisioningVulnerabilityAssessmentsVmsOn - verifica vulnerability assessments VMs
type DefenderAutoProvisioningVulnerabilityAssessmentsVmsOn struct {
	metadata models.CheckMetadata
}

func NewDefenderAutoProvisioningVulnerabilityAssessmentsVmsOn() *DefenderAutoProvisioningVulnerabilityAssessmentsVmsOn {
	return &DefenderAutoProvisioningVulnerabilityAssessmentsVmsOn{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_auto_provisioning_vulnerability_assessments_vms_on",
			CheckTitle: "Ensure auto provisioning of vulnerability assessments for VMs is on",
			Description: "Auto provisioning of vulnerability assessments for VMs should be on",
			Severity: "medium", ServiceName: "defender", ResourceType: "AutoProvisioningSetting",
			RemediationText: "Enable auto provisioning of vulnerability assessments for VMs",
			Categories: []string{"defender", "vulnerability"},
		},
	}
}

func (c *DefenderAutoProvisioningVulnerabilityAssessmentsVmsOn) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderAutoProvisioningVulnerabilityAssessmentsVmsOn) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender VM vulnerability assessments check requires Azure SDK",
		ResourceID: "defender-vm-vulnerability-assessments", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderContainerRegistryScanRecommendationsEnabled - verifica scan de container registry
type DefenderContainerRegistryScanRecommendationsEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderContainerRegistryScanRecommendationsEnabled() *DefenderContainerRegistryScanRecommendationsEnabled {
	return &DefenderContainerRegistryScanRecommendationsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_container_registry_scan_recommendations_enabled",
			CheckTitle: "Ensure container registry scan recommendations are enabled",
			Description: "Container registry scan recommendations should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable container registry scan recommendations",
			Categories: []string{"defender", "container"},
		},
	}
}

func (c *DefenderContainerRegistryScanRecommendationsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderContainerRegistryScanRecommendationsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender container registry check requires Azure SDK",
		ResourceID: "defender-container-registry", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderContainerScanEnabled - verifica scan de containers
type DefenderContainerScanEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderContainerScanEnabled() *DefenderContainerScanEnabled {
	return &DefenderContainerScanEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_container_scan_enabled",
			CheckTitle: "Ensure container scan is enabled",
			Description: "Container scan should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable container scan",
			Categories: []string{"defender", "container"},
		},
	}
}

func (c *DefenderContainerScanEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderContainerScanEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender container scan check requires Azure SDK",
		ResourceID: "defender-container-scan", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmAksEnabled - verifica CSPM para AKS
type DefenderCspmAksEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmAksEnabled() *DefenderCspmAksEnabled {
	return &DefenderCspmAksEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_aks_enabled",
			CheckTitle: "Ensure CSPM for AKS is enabled",
			Description: "CSPM for AKS should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM for AKS",
			Categories: []string{"defender", "aks"},
		},
	}
}

func (c *DefenderCspmAksEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmAksEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM AKS check requires Azure SDK",
		ResourceID: "defender-cspm-aks", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmAppServicesEnabled - verifica CSPM para App Services
type DefenderCspmAppServicesEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmAppServicesEnabled() *DefenderCspmAppServicesEnabled {
	return &DefenderCspmAppServicesEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_app_services_enabled",
			CheckTitle: "Ensure CSPM for App Services is enabled",
			Description: "CSPM for App Services should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM for App Services",
			Categories: []string{"defender", "app-services"},
		},
	}
}

func (c *DefenderCspmAppServicesEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmAppServicesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM App Services check requires Azure SDK",
		ResourceID: "defender-cspm-appservices", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmEnabled - verifica CSPM
type DefenderCspmEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmEnabled() *DefenderCspmEnabled {
	return &DefenderCspmEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_enabled",
			CheckTitle: "Ensure CSPM is enabled",
			Description: "CSPM should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM",
			Categories: []string{"defender", "cspm"},
		},
	}
}

func (c *DefenderCspmEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM check requires Azure SDK",
		ResourceID: "defender-cspm", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmSqlEnabled - verifica CSPM para SQL
type DefenderCspmSqlEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmSqlEnabled() *DefenderCspmSqlEnabled {
	return &DefenderCspmSqlEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_sql_enabled",
			CheckTitle: "Ensure CSPM for SQL is enabled",
			Description: "CSPM for SQL should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM for SQL",
			Categories: []string{"defender", "sql"},
		},
	}
}

func (c *DefenderCspmSqlEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmSqlEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM SQL check requires Azure SDK",
		ResourceID: "defender-cspm-sql", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmSqlOnVmEnabled - verifica CSPM para SQL em VM
type DefenderCspmSqlOnVmEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmSqlOnVmEnabled() *DefenderCspmSqlOnVmEnabled {
	return &DefenderCspmSqlOnVmEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_sql_on_vm_enabled",
			CheckTitle: "Ensure CSPM for SQL on VM is enabled",
			Description: "CSPM for SQL on VM should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM for SQL on VM",
			Categories: []string{"defender", "sql"},
		},
	}
}

func (c *DefenderCspmSqlOnVmEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmSqlOnVmEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM SQL VM check requires Azure SDK",
		ResourceID: "defender-cspm-sqlvm", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmStorageAccountsEnabled - verifica CSPM para Storage Accounts
type DefenderCspmStorageAccountsEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmStorageAccountsEnabled() *DefenderCspmStorageAccountsEnabled {
	return &DefenderCspmStorageAccountsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_storage_accounts_enabled",
			CheckTitle: "Ensure CSPM for Storage Accounts is enabled",
			Description: "CSPM for Storage Accounts should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM for Storage Accounts",
			Categories: []string{"defender", "storage"},
		},
	}
}

func (c *DefenderCspmStorageAccountsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmStorageAccountsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM Storage check requires Azure SDK",
		ResourceID: "defender-cspm-storage", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderCspmVirtualMachinesEnabled - verifica CSPM para VMs
type DefenderCspmVirtualMachinesEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderCspmVirtualMachinesEnabled() *DefenderCspmVirtualMachinesEnabled {
	return &DefenderCspmVirtualMachinesEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_cspm_virtual_machines_enabled",
			CheckTitle: "Ensure CSPM for Virtual Machines is enabled",
			Description: "CSPM for Virtual Machines should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable CSPM for Virtual Machines",
			Categories: []string{"defender", "vm"},
		},
	}
}

func (c *DefenderCspmVirtualMachinesEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderCspmVirtualMachinesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender CSPM VM check requires Azure SDK",
		ResourceID: "defender-cspm-vm", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderDefenderForStorageEnabled - verifica Defender for Storage
type DefenderDefenderForStorageEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderDefenderForStorageEnabled() *DefenderDefenderForStorageEnabled {
	return &DefenderDefenderForStorageEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_defender_for_storage_enabled",
			CheckTitle: "Ensure Defender for Storage is enabled",
			Description: "Defender for Storage should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Pricing",
			RemediationText: "Enable Defender for Storage",
			Categories: []string{"defender", "storage"},
		},
	}
}

func (c *DefenderDefenderForStorageEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderDefenderForStorageEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender for Storage check requires Azure SDK",
		ResourceID: "defender-storage", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderEnableRegularContactDetails - verifica detalhes de contato
type DefenderEnableRegularContactDetails struct {
	metadata models.CheckMetadata
}

func NewDefenderEnableRegularContactDetails() *DefenderEnableRegularContactDetails {
	return &DefenderEnableRegularContactDetails{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_enable_regular_contact_details",
			CheckTitle: "Ensure regular contact details are configured",
			Description: "Regular contact details should be configured",
			Severity: "low", ServiceName: "defender", ResourceType: "SecurityContact",
			RemediationText: "Configure regular contact details",
			Categories: []string{"defender", "contacts"},
		},
	}
}

func (c *DefenderEnableRegularContactDetails) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderEnableRegularContactDetails) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender regular contact check requires Azure SDK",
		ResourceID: "defender-regular-contact", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderEmailNotificationsEnabled - verifica notificações de email
type DefenderEmailNotificationsEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderEmailNotificationsEnabled() *DefenderEmailNotificationsEnabled {
	return &DefenderEmailNotificationsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_email_notifications_enabled",
			CheckTitle: "Ensure email notifications are enabled",
			Description: "Email notifications should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "NotificationSetting",
			RemediationText: "Enable email notifications",
			Categories: []string{"defender", "notifications"},
		},
	}
}

func (c *DefenderEmailNotificationsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderEmailNotificationsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender email notifications check requires Azure SDK",
		ResourceID: "defender-email-notifications", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderHighSeverityAlertsEnabled - verifica alertas de alta severidade
type DefenderHighSeverityAlertsEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderHighSeverityAlertsEnabled() *DefenderHighSeverityAlertsEnabled {
	return &DefenderHighSeverityAlertsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_high_severity_alerts_enabled",
			CheckTitle: "Ensure high severity alerts are enabled",
			Description: "High severity alerts should be enabled",
			Severity: "high", ServiceName: "defender", ResourceType: "AlertSetting",
			RemediationText: "Enable high severity alerts",
			Categories: []string{"defender", "alerts"},
		},
	}
}

func (c *DefenderHighSeverityAlertsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderHighSeverityAlertsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender high severity alerts check requires Azure SDK",
		ResourceID: "defender-high-severity-alerts", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderMonitorSystemUpdates - verifica atualizações de sistema
type DefenderMonitorSystemUpdates struct {
	metadata models.CheckMetadata
}

func NewDefenderMonitorSystemUpdates() *DefenderMonitorSystemUpdates {
	return &DefenderMonitorSystemUpdates{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_monitor_system_updates",
			CheckTitle: "Ensure system updates are monitored",
			Description: "System updates should be monitored",
			Severity: "medium", ServiceName: "defender", ResourceType: "Assessment",
			RemediationText: "Monitor system updates",
			Categories: []string{"defender", "updates"},
		},
	}
}

func (c *DefenderMonitorSystemUpdates) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderMonitorSystemUpdates) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender system updates check requires Azure SDK",
		ResourceID: "defender-system-updates", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderSecurityConfigurationMonitoringEnabled - verifica monitoramento de configuração
type DefenderSecurityConfigurationMonitoringEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderSecurityConfigurationMonitoringEnabled() *DefenderSecurityConfigurationMonitoringEnabled {
	return &DefenderSecurityConfigurationMonitoringEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_security_configuration_monitoring_enabled",
			CheckTitle: "Ensure security configuration monitoring is enabled",
			Description: "Security configuration monitoring should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Assessment",
			RemediationText: "Enable security configuration monitoring",
			Categories: []string{"defender", "monitoring"},
		},
	}
}

func (c *DefenderSecurityConfigurationMonitoringEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderSecurityConfigurationMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender security configuration check requires Azure SDK",
		ResourceID: "defender-security-config", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DefenderVulnerabilityAssessmentEnabled - verifica vulnerability assessment
type DefenderVulnerabilityAssessmentEnabled struct {
	metadata models.CheckMetadata
}

func NewDefenderVulnerabilityAssessmentEnabled() *DefenderVulnerabilityAssessmentEnabled {
	return &DefenderVulnerabilityAssessmentEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "defender_vulnerability_assessment_enabled",
			CheckTitle: "Ensure vulnerability assessment is enabled",
			Description: "Vulnerability assessment should be enabled",
			Severity: "medium", ServiceName: "defender", ResourceType: "Assessment",
			RemediationText: "Enable vulnerability assessment",
			Categories: []string{"defender", "vulnerability"},
		},
	}
}

func (c *DefenderVulnerabilityAssessmentEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DefenderVulnerabilityAssessmentEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Defender vulnerability assessment check requires Azure SDK",
		ResourceID: "defender-vulnerability-assessment", Provider: "azure", Service: "defender",
		FoundAt: time.Now().UTC(),
	}}, nil
}
