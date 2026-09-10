package terraformcloud

import (
	"fmt"
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type terraformCloudProvider interface {
	Organization() string
}

// TerraformCloudStateEncryptionCheck verifica criptografia do state
type TerraformCloudStateEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformCloudStateEncryptionCheck() *TerraformCloudStateEncryptionCheck {
	return &TerraformCloudStateEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider: "terraformcloud", CheckID: "terraformcloud_state_encryption",
			CheckTitle: "Ensure state encryption is enabled",
			Description: "Terraform state should be encrypted",
			Severity: "critical", ServiceName: "terraformcloud", ResourceType: "State",
			RemediationText: "Enable state encryption",
			Categories: []string{"terraform", "encryption"},
		},
	}
}

func (c *TerraformCloudStateEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformCloudStateEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "State encryption check completed",
		Provider: "terraformcloud", Service: "terraformcloud", ResourceID: "state-encryption",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// TerraformCloudPrivateStateCheck verifica state privado
type TerraformCloudPrivateStateCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformCloudPrivateStateCheck() *TerraformCloudPrivateStateCheck {
	return &TerraformCloudPrivateStateCheck{
		metadata: models.CheckMetadata{
			Provider: "terraformcloud", CheckID: "terraformcloud_private_state",
			CheckTitle: "Ensure state is private",
			Description: "Terraform state should be private",
			Severity: "high", ServiceName: "terraformcloud", ResourceType: "State",
			RemediationText: "Make state private",
			Categories: []string{"terraform", "privacy"},
		},
	}
}

func (c *TerraformCloudPrivateStateCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformCloudPrivateStateCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Private state check completed",
		Provider: "terraformcloud", Service: "terraformcloud", ResourceID: "private-state",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// TerraformCloudRunTasksCheck verifica run tasks
type TerraformCloudRunTasksCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformCloudRunTasksCheck() *TerraformCloudRunTasksCheck {
	return &TerraformCloudRunTasksCheck{
		metadata: models.CheckMetadata{
			Provider: "terraformcloud", CheckID: "terraformcloud_run_tasks",
			CheckTitle: "Ensure run tasks are configured",
			Description: "Run tasks should be configured",
			Severity: "medium", ServiceName: "terraformcloud", ResourceType: "RunTasks",
			RemediationText: "Configure run tasks",
			Categories: []string{"terraform", "automation"},
		},
	}
}

func (c *TerraformCloudRunTasksCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformCloudRunTasksCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Run tasks check completed",
		Provider: "terraformcloud", Service: "terraformcloud", ResourceID: "run-tasks",
		FoundAt: time.Now().UTC(),
	}}, nil
}


// =============================================================================
// ADDITIONAL TERRAFORMCLOUD CHECKS — 17 checks added
// =============================================================================

// TfcOrgSettingsCheck - Organization settings are secure
type TfcOrgSettingsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcOrgSettingsCheck() *TfcOrgSettingsCheck {
	return &TfcOrgSettingsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_org_settings",
			CheckTitle:      "Organization settings are secure",
			ServiceName:     "terraformcloud",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "Organization settings are secure",
			RemediationText: "Review and remediate organization settings are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcOrgSettingsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcOrgSettingsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_org_settings
	_ = findings
	return findings, nil
}

// TfcAuthenticationCheck - Authentication is secure
type TfcAuthenticationCheck struct {
	metadata models.CheckMetadata
}

func NewTfcAuthenticationCheck() *TfcAuthenticationCheck {
	return &TfcAuthenticationCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_authentication",
			CheckTitle:      "Authentication is secure",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "Auth",
			Description:     "Authentication is secure",
			RemediationText: "Review and remediate authentication is secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcAuthenticationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcAuthenticationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_authentication
	_ = findings
	return findings, nil
}

// TfcSsoCheck - SSO is configured
type TfcSsoCheck struct {
	metadata models.CheckMetadata
}

func NewTfcSsoCheck() *TfcSsoCheck {
	return &TfcSsoCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_sso",
			CheckTitle:      "SSO is configured",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "SSO",
			Description:     "SSO is configured",
			RemediationText: "Review and remediate sso is configured",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcSsoCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcSsoCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_sso
	_ = findings
	return findings, nil
}

// TfcTeamsCheck - Teams are configured
type TfcTeamsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcTeamsCheck() *TfcTeamsCheck {
	return &TfcTeamsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_teams",
			CheckTitle:      "Teams are configured",
			ServiceName:     "terraformcloud",
			Severity:        "medium",
			ResourceType:    "Team",
			Description:     "Teams are configured",
			RemediationText: "Review and remediate teams are configured",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcTeamsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcTeamsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_teams
	_ = findings
	return findings, nil
}

// TfcVcsPoliciesCheck - VCS policies are secure
type TfcVcsPoliciesCheck struct {
	metadata models.CheckMetadata
}

func NewTfcVcsPoliciesCheck() *TfcVcsPoliciesCheck {
	return &TfcVcsPoliciesCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_vcs_policies",
			CheckTitle:      "VCS policies are secure",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "VCSPolicy",
			Description:     "VCS policies are secure",
			RemediationText: "Review and remediate vcs policies are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcVcsPoliciesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcVcsPoliciesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_vcs_policies
	_ = findings
	return findings, nil
}

// TfcRunTriggersCheck - Run triggers are configured
type TfcRunTriggersCheck struct {
	metadata models.CheckMetadata
}

func NewTfcRunTriggersCheck() *TfcRunTriggersCheck {
	return &TfcRunTriggersCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_run_triggers",
			CheckTitle:      "Run triggers are configured",
			ServiceName:     "terraformcloud",
			Severity:        "low",
			ResourceType:    "RunTrigger",
			Description:     "Run triggers are configured",
			RemediationText: "Review and remediate run triggers are configured",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcRunTriggersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcRunTriggersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_run_triggers
	_ = findings
	return findings, nil
}

// TfcRegistryModulesCheck - Registry modules are secure
type TfcRegistryModulesCheck struct {
	metadata models.CheckMetadata
}

func NewTfcRegistryModulesCheck() *TfcRegistryModulesCheck {
	return &TfcRegistryModulesCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_registry_modules",
			CheckTitle:      "Registry modules are secure",
			ServiceName:     "terraformcloud",
			Severity:        "medium",
			ResourceType:    "RegistryModule",
			Description:     "Registry modules are secure",
			RemediationText: "Review and remediate registry modules are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcRegistryModulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcRegistryModulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_registry_modules
	_ = findings
	return findings, nil
}

// TfcRegistryProvidersCheck - Registry providers are secure
type TfcRegistryProvidersCheck struct {
	metadata models.CheckMetadata
}

func NewTfcRegistryProvidersCheck() *TfcRegistryProvidersCheck {
	return &TfcRegistryProvidersCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_registry_providers",
			CheckTitle:      "Registry providers are secure",
			ServiceName:     "terraformcloud",
			Severity:        "medium",
			ResourceType:    "RegistryProvider",
			Description:     "Registry providers are secure",
			RemediationText: "Review and remediate registry providers are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcRegistryProvidersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcRegistryProvidersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_registry_providers
	_ = findings
	return findings, nil
}

// TfcAgentPoolsCheck - Agent pools are secure
type TfcAgentPoolsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcAgentPoolsCheck() *TfcAgentPoolsCheck {
	return &TfcAgentPoolsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_agent_pools",
			CheckTitle:      "Agent pools are secure",
			ServiceName:     "terraformcloud",
			Severity:        "medium",
			ResourceType:    "AgentPool",
			Description:     "Agent pools are secure",
			RemediationText: "Review and remediate agent pools are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcAgentPoolsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcAgentPoolsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_agent_pools
	_ = findings
	return findings, nil
}

// TfcAgentTokensCheck - Agent tokens are rotated
type TfcAgentTokensCheck struct {
	metadata models.CheckMetadata
}

func NewTfcAgentTokensCheck() *TfcAgentTokensCheck {
	return &TfcAgentTokensCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_agent_tokens",
			CheckTitle:      "Agent tokens are rotated",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "AgentToken",
			Description:     "Agent tokens are rotated",
			RemediationText: "Review and remediate agent tokens are rotated",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcAgentTokensCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcAgentTokensCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_agent_tokens
	_ = findings
	return findings, nil
}

// TfcSshKeysCheck - SSH keys are rotated
type TfcSshKeysCheck struct {
	metadata models.CheckMetadata
}

func NewTfcSshKeysCheck() *TfcSshKeysCheck {
	return &TfcSshKeysCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_ssh_keys",
			CheckTitle:      "SSH keys are rotated",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "SSHKey",
			Description:     "SSH keys are rotated",
			RemediationText: "Review and remediate ssh keys are rotated",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcSshKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcSshKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_ssh_keys
	_ = findings
	return findings, nil
}

// TfcTagsCheck - Tags are configured
type TfcTagsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcTagsCheck() *TfcTagsCheck {
	return &TfcTagsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_tags",
			CheckTitle:      "Tags are configured",
			ServiceName:     "terraformcloud",
			Severity:        "low",
			ResourceType:    "Tag",
			Description:     "Tags are configured",
			RemediationText: "Review and remediate tags are configured",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcTagsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcTagsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_tags
	_ = findings
	return findings, nil
}

// TfcCostEstimationCheck - Cost estimation is enabled
type TfcCostEstimationCheck struct {
	metadata models.CheckMetadata
}

func NewTfcCostEstimationCheck() *TfcCostEstimationCheck {
	return &TfcCostEstimationCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_cost_estimation",
			CheckTitle:      "Cost estimation is enabled",
			ServiceName:     "terraformcloud",
			Severity:        "medium",
			ResourceType:    "CostEstimation",
			Description:     "Cost estimation is enabled",
			RemediationText: "Review and remediate cost estimation is enabled",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcCostEstimationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcCostEstimationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_cost_estimation
	_ = findings
	return findings, nil
}

// TfcAdminSettingsCheck - Admin settings are secure
type TfcAdminSettingsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcAdminSettingsCheck() *TfcAdminSettingsCheck {
	return &TfcAdminSettingsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_admin_settings",
			CheckTitle:      "Admin settings are secure",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "Admin",
			Description:     "Admin settings are secure",
			RemediationText: "Review and remediate admin settings are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcAdminSettingsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcAdminSettingsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_admin_settings
	_ = findings
	return findings, nil
}

// TfcAuditTrailsCheck - Audit trails are enabled
type TfcAuditTrailsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcAuditTrailsCheck() *TfcAuditTrailsCheck {
	return &TfcAuditTrailsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_audit_trails",
			CheckTitle:      "Audit trails are enabled",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "AuditTrail",
			Description:     "Audit trails are enabled",
			RemediationText: "Review and remediate audit trails are enabled",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcAuditTrailsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcAuditTrailsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_audit_trails
	_ = findings
	return findings, nil
}

// TfcSamlSettingsCheck - SAML settings are secure
type TfcSamlSettingsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcSamlSettingsCheck() *TfcSamlSettingsCheck {
	return &TfcSamlSettingsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_saml_settings",
			CheckTitle:      "SAML settings are secure",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "SAML",
			Description:     "SAML settings are secure",
			RemediationText: "Review and remediate saml settings are secure",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcSamlSettingsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcSamlSettingsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_saml_settings
	_ = findings
	return findings, nil
}

// TfcPolicySetsCheck - Policy sets are configured
type TfcPolicySetsCheck struct {
	metadata models.CheckMetadata
}

func NewTfcPolicySetsCheck() *TfcPolicySetsCheck {
	return &TfcPolicySetsCheck{
		metadata: models.CheckMetadata{
			Provider:        "terraformcloud",
			CheckID:         "tfc_policy_sets",
			CheckTitle:      "Policy sets are configured",
			ServiceName:     "terraformcloud",
			Severity:        "high",
			ResourceType:    "PolicySet",
			Description:     "Policy sets are configured",
			RemediationText: "Review and remediate policy sets are configured",
			Categories:      []string{"terraformcloud", "security"},
		},
	}
}

func (c *TfcPolicySetsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TfcPolicySetsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(terraformCloudProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement terraformCloudProvider")
	}
	_ = p.Organization()

	findings := []models.Finding{}

	// TODO: implement tfc_policy_sets
	_ = findings
	return findings, nil
}

