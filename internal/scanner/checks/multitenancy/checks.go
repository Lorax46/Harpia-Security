package multitenancy

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type multitenancyProvider interface {
	Multitenancy(ctx context.Context) (interface{}, error)
}

// MtTenantIsolationCheck - Tenant isolation is enforced
type MtTenantIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantIsolationCheck() *MtTenantIsolationCheck {
	return &MtTenantIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_isolation",
			CheckTitle:      "Tenant isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Tenant",
			Description:     "Tenant isolation is enforced",
			RemediationText: "Review and remediate tenant isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_isolation
	_ = findings
	return findings, nil
}

// MtDataIsolationCheck - Data isolation is enforced
type MtDataIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtDataIsolationCheck() *MtDataIsolationCheck {
	return &MtDataIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_data_isolation",
			CheckTitle:      "Data isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Data",
			Description:     "Data isolation is enforced",
			RemediationText: "Review and remediate data isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtDataIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtDataIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_data_isolation
	_ = findings
	return findings, nil
}

// MtNetworkIsolationCheck - Network isolation is enforced
type MtNetworkIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtNetworkIsolationCheck() *MtNetworkIsolationCheck {
	return &MtNetworkIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_network_isolation",
			CheckTitle:      "Network isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Network",
			Description:     "Network isolation is enforced",
			RemediationText: "Review and remediate network isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtNetworkIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtNetworkIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_network_isolation
	_ = findings
	return findings, nil
}

// MtComputeIsolationCheck - Compute isolation is enforced
type MtComputeIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtComputeIsolationCheck() *MtComputeIsolationCheck {
	return &MtComputeIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_compute_isolation",
			CheckTitle:      "Compute isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Compute",
			Description:     "Compute isolation is enforced",
			RemediationText: "Review and remediate compute isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtComputeIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtComputeIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_compute_isolation
	_ = findings
	return findings, nil
}

// MtStorageIsolationCheck - Storage isolation is enforced
type MtStorageIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtStorageIsolationCheck() *MtStorageIsolationCheck {
	return &MtStorageIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_storage_isolation",
			CheckTitle:      "Storage isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Storage",
			Description:     "Storage isolation is enforced",
			RemediationText: "Review and remediate storage isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtStorageIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtStorageIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_storage_isolation
	_ = findings
	return findings, nil
}

// MtIdentityIsolationCheck - Identity isolation is enforced
type MtIdentityIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtIdentityIsolationCheck() *MtIdentityIsolationCheck {
	return &MtIdentityIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_identity_isolation",
			CheckTitle:      "Identity isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Identity",
			Description:     "Identity isolation is enforced",
			RemediationText: "Review and remediate identity isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtIdentityIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtIdentityIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_identity_isolation
	_ = findings
	return findings, nil
}

// MtAccessIsolationCheck - Access isolation is enforced
type MtAccessIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtAccessIsolationCheck() *MtAccessIsolationCheck {
	return &MtAccessIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_access_isolation",
			CheckTitle:      "Access isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Access",
			Description:     "Access isolation is enforced",
			RemediationText: "Review and remediate access isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtAccessIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtAccessIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_access_isolation
	_ = findings
	return findings, nil
}

// MtAuditIsolationCheck - Audit isolation is enforced
type MtAuditIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtAuditIsolationCheck() *MtAuditIsolationCheck {
	return &MtAuditIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_audit_isolation",
			CheckTitle:      "Audit isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Audit",
			Description:     "Audit isolation is enforced",
			RemediationText: "Review and remediate audit isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtAuditIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtAuditIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_audit_isolation
	_ = findings
	return findings, nil
}

// MtConfigIsolationCheck - Configuration isolation is enforced
type MtConfigIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtConfigIsolationCheck() *MtConfigIsolationCheck {
	return &MtConfigIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_config_isolation",
			CheckTitle:      "Configuration isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Config",
			Description:     "Configuration isolation is enforced",
			RemediationText: "Review and remediate configuration isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtConfigIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtConfigIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_config_isolation
	_ = findings
	return findings, nil
}

// MtSecretIsolationCheck - Secret isolation is enforced
type MtSecretIsolationCheck struct {
	metadata models.CheckMetadata
}

func NewMtSecretIsolationCheck() *MtSecretIsolationCheck {
	return &MtSecretIsolationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_secret_isolation",
			CheckTitle:      "Secret isolation is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Secret",
			Description:     "Secret isolation is enforced",
			RemediationText: "Review and remediate secret isolation is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtSecretIsolationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtSecretIsolationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_secret_isolation
	_ = findings
	return findings, nil
}

// MtTenantOnboardingCheck - Tenant onboarding is configured
type MtTenantOnboardingCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantOnboardingCheck() *MtTenantOnboardingCheck {
	return &MtTenantOnboardingCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_onboarding",
			CheckTitle:      "Tenant onboarding is configured",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Tenant",
			Description:     "Tenant onboarding is configured",
			RemediationText: "Review and remediate tenant onboarding is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantOnboardingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantOnboardingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_onboarding
	_ = findings
	return findings, nil
}

// MtTenantOffboardingCheck - Tenant offboarding is configured
type MtTenantOffboardingCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantOffboardingCheck() *MtTenantOffboardingCheck {
	return &MtTenantOffboardingCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_offboarding",
			CheckTitle:      "Tenant offboarding is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Tenant",
			Description:     "Tenant offboarding is configured",
			RemediationText: "Review and remediate tenant offboarding is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantOffboardingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantOffboardingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_offboarding
	_ = findings
	return findings, nil
}

// MtTenantSuspensionCheck - Tenant suspension is configured
type MtTenantSuspensionCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantSuspensionCheck() *MtTenantSuspensionCheck {
	return &MtTenantSuspensionCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_suspension",
			CheckTitle:      "Tenant suspension is configured",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Tenant",
			Description:     "Tenant suspension is configured",
			RemediationText: "Review and remediate tenant suspension is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantSuspensionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantSuspensionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_suspension
	_ = findings
	return findings, nil
}

// MtTenantDeletionCheck - Tenant deletion is configured
type MtTenantDeletionCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantDeletionCheck() *MtTenantDeletionCheck {
	return &MtTenantDeletionCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_deletion",
			CheckTitle:      "Tenant deletion is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Tenant",
			Description:     "Tenant deletion is configured",
			RemediationText: "Review and remediate tenant deletion is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantDeletionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantDeletionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_deletion
	_ = findings
	return findings, nil
}

// MtTenantMigrationCheck - Tenant migration is configured
type MtTenantMigrationCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantMigrationCheck() *MtTenantMigrationCheck {
	return &MtTenantMigrationCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_migration",
			CheckTitle:      "Tenant migration is configured",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Tenant",
			Description:     "Tenant migration is configured",
			RemediationText: "Review and remediate tenant migration is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantMigrationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantMigrationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_migration
	_ = findings
	return findings, nil
}

// MtTenantBackupCheck - Tenant backup is configured
type MtTenantBackupCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantBackupCheck() *MtTenantBackupCheck {
	return &MtTenantBackupCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_backup",
			CheckTitle:      "Tenant backup is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Backup",
			Description:     "Tenant backup is configured",
			RemediationText: "Review and remediate tenant backup is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantBackupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantBackupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_backup
	_ = findings
	return findings, nil
}

// MtTenantRestoreCheck - Tenant restore is configured
type MtTenantRestoreCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantRestoreCheck() *MtTenantRestoreCheck {
	return &MtTenantRestoreCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_restore",
			CheckTitle:      "Tenant restore is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Restore",
			Description:     "Tenant restore is configured",
			RemediationText: "Review and remediate tenant restore is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantRestoreCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantRestoreCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_restore
	_ = findings
	return findings, nil
}

// MtTenantCloneCheck - Tenant clone is configured
type MtTenantCloneCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantCloneCheck() *MtTenantCloneCheck {
	return &MtTenantCloneCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_clone",
			CheckTitle:      "Tenant clone is configured",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Tenant",
			Description:     "Tenant clone is configured",
			RemediationText: "Review and remediate tenant clone is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantCloneCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantCloneCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_clone
	_ = findings
	return findings, nil
}

// MtTenantHierarchyCheck - Tenant hierarchy is configured
type MtTenantHierarchyCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantHierarchyCheck() *MtTenantHierarchyCheck {
	return &MtTenantHierarchyCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_hierarchy",
			CheckTitle:      "Tenant hierarchy is configured",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Tenant",
			Description:     "Tenant hierarchy is configured",
			RemediationText: "Review and remediate tenant hierarchy is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantHierarchyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantHierarchyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_hierarchy
	_ = findings
	return findings, nil
}

// MtTenantGroupCheck - Tenant groups are configured
type MtTenantGroupCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantGroupCheck() *MtTenantGroupCheck {
	return &MtTenantGroupCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_group",
			CheckTitle:      "Tenant groups are configured",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Tenant",
			Description:     "Tenant groups are configured",
			RemediationText: "Review and remediate tenant groups are configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantGroupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantGroupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_group
	_ = findings
	return findings, nil
}

// MtTenantAdminCheck - Tenant admin is configured
type MtTenantAdminCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantAdminCheck() *MtTenantAdminCheck {
	return &MtTenantAdminCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_admin",
			CheckTitle:      "Tenant admin is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Tenant",
			Description:     "Tenant admin is configured",
			RemediationText: "Review and remediate tenant admin is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantAdminCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantAdminCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_admin
	_ = findings
	return findings, nil
}

// MtTenantUserMgmtCheck - Tenant user management is configured
type MtTenantUserMgmtCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantUserMgmtCheck() *MtTenantUserMgmtCheck {
	return &MtTenantUserMgmtCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_user_mgmt",
			CheckTitle:      "Tenant user management is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "User",
			Description:     "Tenant user management is configured",
			RemediationText: "Review and remediate tenant user management is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantUserMgmtCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantUserMgmtCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_user_mgmt
	_ = findings
	return findings, nil
}

// MtTenantRoleMgmtCheck - Tenant role management is configured
type MtTenantRoleMgmtCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantRoleMgmtCheck() *MtTenantRoleMgmtCheck {
	return &MtTenantRoleMgmtCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_role_mgmt",
			CheckTitle:      "Tenant role management is configured",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Role",
			Description:     "Tenant role management is configured",
			RemediationText: "Review and remediate tenant role management is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantRoleMgmtCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantRoleMgmtCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_role_mgmt
	_ = findings
	return findings, nil
}

// MtTenantQuotaCheck - Tenant quotas are configured
type MtTenantQuotaCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantQuotaCheck() *MtTenantQuotaCheck {
	return &MtTenantQuotaCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_quota",
			CheckTitle:      "Tenant quotas are configured",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Quota",
			Description:     "Tenant quotas are configured",
			RemediationText: "Review and remediate tenant quotas are configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantQuotaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantQuotaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_quota
	_ = findings
	return findings, nil
}

// MtTenantBillingCheck - Tenant billing is configured
type MtTenantBillingCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantBillingCheck() *MtTenantBillingCheck {
	return &MtTenantBillingCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_billing",
			CheckTitle:      "Tenant billing is configured",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Billing",
			Description:     "Tenant billing is configured",
			RemediationText: "Review and remediate tenant billing is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantBillingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantBillingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_billing
	_ = findings
	return findings, nil
}

// MtTenantUsageCheck - Tenant usage is monitored
type MtTenantUsageCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantUsageCheck() *MtTenantUsageCheck {
	return &MtTenantUsageCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_usage",
			CheckTitle:      "Tenant usage is monitored",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "Usage",
			Description:     "Tenant usage is monitored",
			RemediationText: "Review and remediate tenant usage is monitored",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantUsageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantUsageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_usage
	_ = findings
	return findings, nil
}

// MtTenantLimitCheck - Tenant limits are enforced
type MtTenantLimitCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantLimitCheck() *MtTenantLimitCheck {
	return &MtTenantLimitCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_limit",
			CheckTitle:      "Tenant limits are enforced",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Limit",
			Description:     "Tenant limits are enforced",
			RemediationText: "Review and remediate tenant limits are enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantLimitCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantLimitCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_limit
	_ = findings
	return findings, nil
}

// MtTenantRateLimitCheck - Tenant rate limits are enforced
type MtTenantRateLimitCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantRateLimitCheck() *MtTenantRateLimitCheck {
	return &MtTenantRateLimitCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_rate_limit",
			CheckTitle:      "Tenant rate limits are enforced",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "RateLimit",
			Description:     "Tenant rate limits are enforced",
			RemediationText: "Review and remediate tenant rate limits are enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantRateLimitCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantRateLimitCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_rate_limit
	_ = findings
	return findings, nil
}

// MtTenantApiQuotaCheck - API quotas are enforced
type MtTenantApiQuotaCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantApiQuotaCheck() *MtTenantApiQuotaCheck {
	return &MtTenantApiQuotaCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_api_quota",
			CheckTitle:      "API quotas are enforced",
			ServiceName:     "multitenancy",
			Severity:        "medium",
			ResourceType:    "APIQuota",
			Description:     "API quotas are enforced",
			RemediationText: "Review and remediate api quotas are enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantApiQuotaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantApiQuotaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_api_quota
	_ = findings
	return findings, nil
}

// MtTenantCustomDomainCheck - Custom domains are supported
type MtTenantCustomDomainCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantCustomDomainCheck() *MtTenantCustomDomainCheck {
	return &MtTenantCustomDomainCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_custom_domain",
			CheckTitle:      "Custom domains are supported",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Domain",
			Description:     "Custom domains are supported",
			RemediationText: "Review and remediate custom domains are supported",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantCustomDomainCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantCustomDomainCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_custom_domain
	_ = findings
	return findings, nil
}

// MtTenantBrandingCheck - Tenant branding is supported
type MtTenantBrandingCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantBrandingCheck() *MtTenantBrandingCheck {
	return &MtTenantBrandingCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_branding",
			CheckTitle:      "Tenant branding is supported",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Brand",
			Description:     "Tenant branding is supported",
			RemediationText: "Review and remediate tenant branding is supported",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantBrandingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantBrandingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_branding
	_ = findings
	return findings, nil
}

// MtTenantThemeCheck - Tenant themes are supported
type MtTenantThemeCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantThemeCheck() *MtTenantThemeCheck {
	return &MtTenantThemeCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_theme",
			CheckTitle:      "Tenant themes are supported",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Theme",
			Description:     "Tenant themes are supported",
			RemediationText: "Review and remediate tenant themes are supported",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantThemeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantThemeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_theme
	_ = findings
	return findings, nil
}

// MtTenantLanguageCheck - Multi-language is supported
type MtTenantLanguageCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantLanguageCheck() *MtTenantLanguageCheck {
	return &MtTenantLanguageCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_language",
			CheckTitle:      "Multi-language is supported",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Language",
			Description:     "Multi-language is supported",
			RemediationText: "Review and remediate multi-language is supported",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantLanguageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantLanguageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_language
	_ = findings
	return findings, nil
}

// MtTenantTimezoneCheck - Timezone support is enabled
type MtTenantTimezoneCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantTimezoneCheck() *MtTenantTimezoneCheck {
	return &MtTenantTimezoneCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_timezone",
			CheckTitle:      "Timezone support is enabled",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Timezone",
			Description:     "Timezone support is enabled",
			RemediationText: "Review and remediate timezone support is enabled",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantTimezoneCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantTimezoneCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_timezone
	_ = findings
	return findings, nil
}

// MtTenantCurrencyCheck - Currency support is enabled
type MtTenantCurrencyCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantCurrencyCheck() *MtTenantCurrencyCheck {
	return &MtTenantCurrencyCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_currency",
			CheckTitle:      "Currency support is enabled",
			ServiceName:     "multitenancy",
			Severity:        "low",
			ResourceType:    "Currency",
			Description:     "Currency support is enabled",
			RemediationText: "Review and remediate currency support is enabled",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantCurrencyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantCurrencyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_currency
	_ = findings
	return findings, nil
}

// MtTenantComplianceCheck - Tenant compliance is enforced
type MtTenantComplianceCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantComplianceCheck() *MtTenantComplianceCheck {
	return &MtTenantComplianceCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_compliance",
			CheckTitle:      "Tenant compliance is enforced",
			ServiceName:     "multitenancy",
			Severity:        "high",
			ResourceType:    "Compliance",
			Description:     "Tenant compliance is enforced",
			RemediationText: "Review and remediate tenant compliance is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantComplianceCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantComplianceCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_compliance
	_ = findings
	return findings, nil
}

// MtTenantDataResidencyCheck - Data residency is enforced
type MtTenantDataResidencyCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantDataResidencyCheck() *MtTenantDataResidencyCheck {
	return &MtTenantDataResidencyCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_data_residency",
			CheckTitle:      "Data residency is enforced",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Data",
			Description:     "Data residency is enforced",
			RemediationText: "Review and remediate data residency is enforced",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantDataResidencyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantDataResidencyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_data_residency
	_ = findings
	return findings, nil
}

// MtTenantDisasterRecoveryCheck - Disaster recovery is configured
type MtTenantDisasterRecoveryCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantDisasterRecoveryCheck() *MtTenantDisasterRecoveryCheck {
	return &MtTenantDisasterRecoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_disaster_recovery",
			CheckTitle:      "Disaster recovery is configured",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "DR",
			Description:     "Disaster recovery is configured",
			RemediationText: "Review and remediate disaster recovery is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantDisasterRecoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantDisasterRecoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_disaster_recovery
	_ = findings
	return findings, nil
}

// MtTenantHighAvailabilityCheck - High availability is configured
type MtTenantHighAvailabilityCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantHighAvailabilityCheck() *MtTenantHighAvailabilityCheck {
	return &MtTenantHighAvailabilityCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_high_availability",
			CheckTitle:      "High availability is configured",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "HA",
			Description:     "High availability is configured",
			RemediationText: "Review and remediate high availability is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantHighAvailabilityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantHighAvailabilityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_high_availability
	_ = findings
	return findings, nil
}

// MtTenantFailoverCheck - Failover is configured
type MtTenantFailoverCheck struct {
	metadata models.CheckMetadata
}

func NewMtTenantFailoverCheck() *MtTenantFailoverCheck {
	return &MtTenantFailoverCheck{
		metadata: models.CheckMetadata{
			Provider:        "multitenancy",
			CheckID:         "mt_tenant_failover",
			CheckTitle:      "Failover is configured",
			ServiceName:     "multitenancy",
			Severity:        "critical",
			ResourceType:    "Failover",
			Description:     "Failover is configured",
			RemediationText: "Review and remediate failover is configured",
			Categories:      []string{"multitenancy", "security"},
		},
	}
}

func (c *MtTenantFailoverCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MtTenantFailoverCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(multitenancyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement multitenancyProvider")
	}
	client, err := p.Multitenancy(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement mt_tenant_failover
	_ = findings
	return findings, nil
}
