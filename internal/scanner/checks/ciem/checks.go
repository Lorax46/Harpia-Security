package ciem

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type ciemProvider interface {
	Ciem(ctx context.Context) (interface{}, error)
}

// CiemProvider interface

// UnusedUsersCheck - No unused IAM users
type UnusedUsersCheck struct {
	metadata models.CheckMetadata
}

func NewUnusedUsersCheck() *UnusedUsersCheck {
	return &UnusedUsersCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_unused_users",
			CheckTitle:      "No unused IAM users",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "User",
			Description:     "No unused IAM users",
			RemediationText: "Review and remediate no unused iam users",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *UnusedUsersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnusedUsersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_unused_users
	_ = findings
	return findings, nil
}

// UnusedRolesCheck - No unused IAM roles
type UnusedRolesCheck struct {
	metadata models.CheckMetadata
}

func NewUnusedRolesCheck() *UnusedRolesCheck {
	return &UnusedRolesCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_unused_roles",
			CheckTitle:      "No unused IAM roles",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Role",
			Description:     "No unused IAM roles",
			RemediationText: "Review and remediate no unused iam roles",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *UnusedRolesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnusedRolesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_unused_roles
	_ = findings
	return findings, nil
}

// UnusedGroupsCheck - No unused IAM groups
type UnusedGroupsCheck struct {
	metadata models.CheckMetadata
}

func NewUnusedGroupsCheck() *UnusedGroupsCheck {
	return &UnusedGroupsCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_unused_groups",
			CheckTitle:      "No unused IAM groups",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Group",
			Description:     "No unused IAM groups",
			RemediationText: "Review and remediate no unused iam groups",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *UnusedGroupsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnusedGroupsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_unused_groups
	_ = findings
	return findings, nil
}

// UnusedPoliciesCheck - No unused IAM policies
type UnusedPoliciesCheck struct {
	metadata models.CheckMetadata
}

func NewUnusedPoliciesCheck() *UnusedPoliciesCheck {
	return &UnusedPoliciesCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_unused_policies",
			CheckTitle:      "No unused IAM policies",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Policy",
			Description:     "No unused IAM policies",
			RemediationText: "Review and remediate no unused iam policies",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *UnusedPoliciesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnusedPoliciesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_unused_policies
	_ = findings
	return findings, nil
}

// UnusedAccessKeysCheck - No unused access keys
type UnusedAccessKeysCheck struct {
	metadata models.CheckMetadata
}

func NewUnusedAccessKeysCheck() *UnusedAccessKeysCheck {
	return &UnusedAccessKeysCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_unused_access_keys",
			CheckTitle:      "No unused access keys",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "AccessKey",
			Description:     "No unused access keys",
			RemediationText: "Review and remediate no unused access keys",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *UnusedAccessKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnusedAccessKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_unused_access_keys
	_ = findings
	return findings, nil
}

// UnusedConsoleCredentialsCheck - No unused console credentials
type UnusedConsoleCredentialsCheck struct {
	metadata models.CheckMetadata
}

func NewUnusedConsoleCredentialsCheck() *UnusedConsoleCredentialsCheck {
	return &UnusedConsoleCredentialsCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_unused_console_credentials",
			CheckTitle:      "No unused console credentials",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "User",
			Description:     "No unused console credentials",
			RemediationText: "Review and remediate no unused console credentials",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *UnusedConsoleCredentialsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnusedConsoleCredentialsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_unused_console_credentials
	_ = findings
	return findings, nil
}

// LeastPrivilegePolicyCheck - Policies follow least privilege
type LeastPrivilegePolicyCheck struct {
	metadata models.CheckMetadata
}

func NewLeastPrivilegePolicyCheck() *LeastPrivilegePolicyCheck {
	return &LeastPrivilegePolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_least_privilege_policy",
			CheckTitle:      "Policies follow least privilege",
			ServiceName:     "ciem",
			Severity:        "critical",
			ResourceType:    "Policy",
			Description:     "Policies follow least privilege",
			RemediationText: "Review and remediate policies follow least privilege",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *LeastPrivilegePolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LeastPrivilegePolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_least_privilege_policy
	_ = findings
	return findings, nil
}

// NoFullAdminCheck - No full admin access
type NoFullAdminCheck struct {
	metadata models.CheckMetadata
}

func NewNoFullAdminCheck() *NoFullAdminCheck {
	return &NoFullAdminCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_no_full_admin",
			CheckTitle:      "No full admin access",
			ServiceName:     "ciem",
			Severity:        "critical",
			ResourceType:    "Policy",
			Description:     "No full admin access",
			RemediationText: "Review and remediate no full admin access",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *NoFullAdminCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoFullAdminCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_no_full_admin
	_ = findings
	return findings, nil
}

// NoWildcardActionsCheck - No wildcard actions in policies
type NoWildcardActionsCheck struct {
	metadata models.CheckMetadata
}

func NewNoWildcardActionsCheck() *NoWildcardActionsCheck {
	return &NoWildcardActionsCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_no_wildcard_actions",
			CheckTitle:      "No wildcard actions in policies",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Policy",
			Description:     "No wildcard actions in policies",
			RemediationText: "Review and remediate no wildcard actions in policies",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *NoWildcardActionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoWildcardActionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_no_wildcard_actions
	_ = findings
	return findings, nil
}

// NoWildcardResourcesCheck - No wildcard resources in policies
type NoWildcardResourcesCheck struct {
	metadata models.CheckMetadata
}

func NewNoWildcardResourcesCheck() *NoWildcardResourcesCheck {
	return &NoWildcardResourcesCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_no_wildcard_resources",
			CheckTitle:      "No wildcard resources in policies",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Policy",
			Description:     "No wildcard resources in policies",
			RemediationText: "Review and remediate no wildcard resources in policies",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *NoWildcardResourcesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoWildcardResourcesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_no_wildcard_resources
	_ = findings
	return findings, nil
}

// PermissionsBoundaryCheck - Permissions boundaries are used
type PermissionsBoundaryCheck struct {
	metadata models.CheckMetadata
}

func NewPermissionsBoundaryCheck() *PermissionsBoundaryCheck {
	return &PermissionsBoundaryCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_permissions_boundary",
			CheckTitle:      "Permissions boundaries are used",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "User",
			Description:     "Permissions boundaries are used",
			RemediationText: "Review and remediate permissions boundaries are used",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *PermissionsBoundaryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PermissionsBoundaryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_permissions_boundary
	_ = findings
	return findings, nil
}

// ScpProtectionCheck - SCPs protect against privilege escalation
type ScpProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewScpProtectionCheck() *ScpProtectionCheck {
	return &ScpProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_scp_protection",
			CheckTitle:      "SCPs protect against privilege escalation",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Org",
			Description:     "SCPs protect against privilege escalation",
			RemediationText: "Review and remediate scps protect against privilege escalation",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *ScpProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ScpProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_scp_protection
	_ = findings
	return findings, nil
}

// ServiceControlPolicyCheck - Service control policies are configured
type ServiceControlPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewServiceControlPolicyCheck() *ServiceControlPolicyCheck {
	return &ServiceControlPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_service_control_policy",
			CheckTitle:      "Service control policies are configured",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Org",
			Description:     "Service control policies are configured",
			RemediationText: "Review and remediate service control policies are configured",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *ServiceControlPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceControlPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_service_control_policy
	_ = findings
	return findings, nil
}

// ResourcePolicyCheck - Resource policies are configured
type ResourcePolicyCheck struct {
	metadata models.CheckMetadata
}

func NewResourcePolicyCheck() *ResourcePolicyCheck {
	return &ResourcePolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_resource_policy",
			CheckTitle:      "Resource policies are configured",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Resource",
			Description:     "Resource policies are configured",
			RemediationText: "Review and remediate resource policies are configured",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *ResourcePolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ResourcePolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_resource_policy
	_ = findings
	return findings, nil
}

// CrossAccountTrustCheck - Cross-account trust is reviewed
type CrossAccountTrustCheck struct {
	metadata models.CheckMetadata
}

func NewCrossAccountTrustCheck() *CrossAccountTrustCheck {
	return &CrossAccountTrustCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_cross_account_trust",
			CheckTitle:      "Cross-account trust is reviewed",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Role",
			Description:     "Cross-account trust is reviewed",
			RemediationText: "Review and remediate cross-account trust is reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *CrossAccountTrustCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CrossAccountTrustCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_cross_account_trust
	_ = findings
	return findings, nil
}

// ExternalIdRequiredCheck - External ID is required for cross-account
type ExternalIdRequiredCheck struct {
	metadata models.CheckMetadata
}

func NewExternalIdRequiredCheck() *ExternalIdRequiredCheck {
	return &ExternalIdRequiredCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_external_id_required",
			CheckTitle:      "External ID is required for cross-account",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Role",
			Description:     "External ID is required for cross-account",
			RemediationText: "Review and remediate external id is required for cross-account",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *ExternalIdRequiredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalIdRequiredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_external_id_required
	_ = findings
	return findings, nil
}

// MfaForAssumeRoleCheck - MFA is required to assume roles
type MfaForAssumeRoleCheck struct {
	metadata models.CheckMetadata
}

func NewMfaForAssumeRoleCheck() *MfaForAssumeRoleCheck {
	return &MfaForAssumeRoleCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_mfa_for_assume_role",
			CheckTitle:      "MFA is required to assume roles",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Role",
			Description:     "MFA is required to assume roles",
			RemediationText: "Review and remediate mfa is required to assume roles",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *MfaForAssumeRoleCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MfaForAssumeRoleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_mfa_for_assume_role
	_ = findings
	return findings, nil
}

// SessionDurationCheck - Session duration is limited
type SessionDurationCheck struct {
	metadata models.CheckMetadata
}

func NewSessionDurationCheck() *SessionDurationCheck {
	return &SessionDurationCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_session_duration",
			CheckTitle:      "Session duration is limited",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Role",
			Description:     "Session duration is limited",
			RemediationText: "Review and remediate session duration is limited",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *SessionDurationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SessionDurationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_session_duration
	_ = findings
	return findings, nil
}

// TrustedAccessCheck - AWS Trusted Access is reviewed
type TrustedAccessCheck struct {
	metadata models.CheckMetadata
}

func NewTrustedAccessCheck() *TrustedAccessCheck {
	return &TrustedAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_trusted_access",
			CheckTitle:      "AWS Trusted Access is reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "AWS Trusted Access is reviewed",
			RemediationText: "Review and remediate aws trusted access is reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *TrustedAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TrustedAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_trusted_access
	_ = findings
	return findings, nil
}

// AccessAnalyzerCheck - IAM Access Analyzer is enabled
type AccessAnalyzerCheck struct {
	metadata models.CheckMetadata
}

func NewAccessAnalyzerCheck() *AccessAnalyzerCheck {
	return &AccessAnalyzerCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_access_analyzer",
			CheckTitle:      "IAM Access Analyzer is enabled",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Account",
			Description:     "IAM Access Analyzer is enabled",
			RemediationText: "Review and remediate iam access analyzer is enabled",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *AccessAnalyzerCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessAnalyzerCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_access_analyzer
	_ = findings
	return findings, nil
}

// AccessAnalyzerFindingsCheck - Access Analyzer findings are resolved
type AccessAnalyzerFindingsCheck struct {
	metadata models.CheckMetadata
}

func NewAccessAnalyzerFindingsCheck() *AccessAnalyzerFindingsCheck {
	return &AccessAnalyzerFindingsCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_access_analyzer_findings",
			CheckTitle:      "Access Analyzer findings are resolved",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Account",
			Description:     "Access Analyzer findings are resolved",
			RemediationText: "Review and remediate access analyzer findings are resolved",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *AccessAnalyzerFindingsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessAnalyzerFindingsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_access_analyzer_findings
	_ = findings
	return findings, nil
}

// ServiceLinkedRoleCheck - Service-linked roles are reviewed
type ServiceLinkedRoleCheck struct {
	metadata models.CheckMetadata
}

func NewServiceLinkedRoleCheck() *ServiceLinkedRoleCheck {
	return &ServiceLinkedRoleCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_service_linked_role",
			CheckTitle:      "Service-linked roles are reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Role",
			Description:     "Service-linked roles are reviewed",
			RemediationText: "Review and remediate service-linked roles are reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *ServiceLinkedRoleCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceLinkedRoleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_service_linked_role
	_ = findings
	return findings, nil
}

// PassroleRestrictedCheck - PassRole is restricted
type PassroleRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewPassroleRestrictedCheck() *PassroleRestrictedCheck {
	return &PassroleRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_passrole_restricted",
			CheckTitle:      "PassRole is restricted",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Policy",
			Description:     "PassRole is restricted",
			RemediationText: "Review and remediate passrole is restricted",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *PassroleRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PassroleRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_passrole_restricted
	_ = findings
	return findings, nil
}

// AssumeRoleRestrictedCheck - AssumeRole is restricted
type AssumeRoleRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewAssumeRoleRestrictedCheck() *AssumeRoleRestrictedCheck {
	return &AssumeRoleRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_assume_role_restricted",
			CheckTitle:      "AssumeRole is restricted",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Policy",
			Description:     "AssumeRole is restricted",
			RemediationText: "Review and remediate assumerole is restricted",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *AssumeRoleRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AssumeRoleRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_assume_role_restricted
	_ = findings
	return findings, nil
}

// CredentialReportCheck - Credential report is reviewed
type CredentialReportCheck struct {
	metadata models.CheckMetadata
}

func NewCredentialReportCheck() *CredentialReportCheck {
	return &CredentialReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_credential_report",
			CheckTitle:      "Credential report is reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Account",
			Description:     "Credential report is reviewed",
			RemediationText: "Review and remediate credential report is reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *CredentialReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CredentialReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_credential_report
	_ = findings
	return findings, nil
}

// PasswordPolicyStrongCheck - Password policy is strong
type PasswordPolicyStrongCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyStrongCheck() *PasswordPolicyStrongCheck {
	return &PasswordPolicyStrongCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_password_policy_strong",
			CheckTitle:      "Password policy is strong",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Account",
			Description:     "Password policy is strong",
			RemediationText: "Review and remediate password policy is strong",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *PasswordPolicyStrongCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyStrongCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_password_policy_strong
	_ = findings
	return findings, nil
}

// PasswordExpirationCheck - Password expiration is configured
type PasswordExpirationCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordExpirationCheck() *PasswordExpirationCheck {
	return &PasswordExpirationCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_password_expiration",
			CheckTitle:      "Password expiration is configured",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Account",
			Description:     "Password expiration is configured",
			RemediationText: "Review and remediate password expiration is configured",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *PasswordExpirationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordExpirationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_password_expiration
	_ = findings
	return findings, nil
}

// PasswordReuseCheck - Password reuse is prevented
type PasswordReuseCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordReuseCheck() *PasswordReuseCheck {
	return &PasswordReuseCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_password_reuse",
			CheckTitle:      "Password reuse is prevented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Account",
			Description:     "Password reuse is prevented",
			RemediationText: "Review and remediate password reuse is prevented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *PasswordReuseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordReuseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_password_reuse
	_ = findings
	return findings, nil
}

// ApiThrottlingCheck - API throttling is configured
type ApiThrottlingCheck struct {
	metadata models.CheckMetadata
}

func NewApiThrottlingCheck() *ApiThrottlingCheck {
	return &ApiThrottlingCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_api_throttling",
			CheckTitle:      "API throttling is configured",
			ServiceName:     "ciem",
			Severity:        "low",
			ResourceType:    "Account",
			Description:     "API throttling is configured",
			RemediationText: "Review and remediate api throttling is configured",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *ApiThrottlingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiThrottlingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_api_throttling
	_ = findings
	return findings, nil
}

// AwsManagedPolicyCheck - AWS managed policies are reviewed
type AwsManagedPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewAwsManagedPolicyCheck() *AwsManagedPolicyCheck {
	return &AwsManagedPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_aws_managed_policy",
			CheckTitle:      "AWS managed policies are reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Policy",
			Description:     "AWS managed policies are reviewed",
			RemediationText: "Review and remediate aws managed policies are reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *AwsManagedPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AwsManagedPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_aws_managed_policy
	_ = findings
	return findings, nil
}

// CustomerManagedPolicyCheck - Customer managed policies are reviewed
type CustomerManagedPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewCustomerManagedPolicyCheck() *CustomerManagedPolicyCheck {
	return &CustomerManagedPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_customer_managed_policy",
			CheckTitle:      "Customer managed policies are reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Policy",
			Description:     "Customer managed policies are reviewed",
			RemediationText: "Review and remediate customer managed policies are reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *CustomerManagedPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CustomerManagedPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_customer_managed_policy
	_ = findings
	return findings, nil
}

// InlinePolicyCheck - Inline policies are minimized
type InlinePolicyCheck struct {
	metadata models.CheckMetadata
}

func NewInlinePolicyCheck() *InlinePolicyCheck {
	return &InlinePolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_inline_policy",
			CheckTitle:      "Inline policies are minimized",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "User",
			Description:     "Inline policies are minimized",
			RemediationText: "Review and remediate inline policies are minimized",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *InlinePolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InlinePolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_inline_policy
	_ = findings
	return findings, nil
}

// GroupMembershipCheck - Group membership is reviewed
type GroupMembershipCheck struct {
	metadata models.CheckMetadata
}

func NewGroupMembershipCheck() *GroupMembershipCheck {
	return &GroupMembershipCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_group_membership",
			CheckTitle:      "Group membership is reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Group",
			Description:     "Group membership is reviewed",
			RemediationText: "Review and remediate group membership is reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GroupMembershipCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GroupMembershipCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_group_membership
	_ = findings
	return findings, nil
}

// RoleChainingCheck - Role chaining is prevented
type RoleChainingCheck struct {
	metadata models.CheckMetadata
}

func NewRoleChainingCheck() *RoleChainingCheck {
	return &RoleChainingCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_role_chaining",
			CheckTitle:      "Role chaining is prevented",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Role",
			Description:     "Role chaining is prevented",
			RemediationText: "Review and remediate role chaining is prevented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *RoleChainingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RoleChainingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_role_chaining
	_ = findings
	return findings, nil
}

// FederatedAccessCheck - Federated access is secure
type FederatedAccessCheck struct {
	metadata models.CheckMetadata
}

func NewFederatedAccessCheck() *FederatedAccessCheck {
	return &FederatedAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_federated_access",
			CheckTitle:      "Federated access is secure",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "IdentityProvider",
			Description:     "Federated access is secure",
			RemediationText: "Review and remediate federated access is secure",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *FederatedAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FederatedAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_federated_access
	_ = findings
	return findings, nil
}

// SamlProviderCheck - SAML providers are valid
type SamlProviderCheck struct {
	metadata models.CheckMetadata
}

func NewSamlProviderCheck() *SamlProviderCheck {
	return &SamlProviderCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_saml_provider",
			CheckTitle:      "SAML providers are valid",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "IdentityProvider",
			Description:     "SAML providers are valid",
			RemediationText: "Review and remediate saml providers are valid",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *SamlProviderCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SamlProviderCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_saml_provider
	_ = findings
	return findings, nil
}

// OidcProviderCheck - OIDC providers are valid
type OidcProviderCheck struct {
	metadata models.CheckMetadata
}

func NewOidcProviderCheck() *OidcProviderCheck {
	return &OidcProviderCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_oidc_provider",
			CheckTitle:      "OIDC providers are valid",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "IdentityProvider",
			Description:     "OIDC providers are valid",
			RemediationText: "Review and remediate oidc providers are valid",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *OidcProviderCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OidcProviderCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_oidc_provider
	_ = findings
	return findings, nil
}

// IdentityCenterCheck - IAM Identity Center is configured
type IdentityCenterCheck struct {
	metadata models.CheckMetadata
}

func NewIdentityCenterCheck() *IdentityCenterCheck {
	return &IdentityCenterCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_identity_center",
			CheckTitle:      "IAM Identity Center is configured",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Account",
			Description:     "IAM Identity Center is configured",
			RemediationText: "Review and remediate iam identity center is configured",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *IdentityCenterCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityCenterCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_identity_center
	_ = findings
	return findings, nil
}

// PermissionSetCheck - Permission sets are least privilege
type PermissionSetCheck struct {
	metadata models.CheckMetadata
}

func NewPermissionSetCheck() *PermissionSetCheck {
	return &PermissionSetCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_permission_set",
			CheckTitle:      "Permission sets are least privilege",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "PermissionSet",
			Description:     "Permission sets are least privilege",
			RemediationText: "Review and remediate permission sets are least privilege",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *PermissionSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PermissionSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_permission_set
	_ = findings
	return findings, nil
}

// AccountAssignmentCheck - Account assignments are reviewed
type AccountAssignmentCheck struct {
	metadata models.CheckMetadata
}

func NewAccountAssignmentCheck() *AccountAssignmentCheck {
	return &AccountAssignmentCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_account_assignment",
			CheckTitle:      "Account assignments are reviewed",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Account",
			Description:     "Account assignments are reviewed",
			RemediationText: "Review and remediate account assignments are reviewed",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *AccountAssignmentCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccountAssignmentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_account_assignment
	_ = findings
	return findings, nil
}

// GovernanceRbacCheck - RBAC governance is implemented
type GovernanceRbacCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceRbacCheck() *GovernanceRbacCheck {
	return &GovernanceRbacCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_rbac",
			CheckTitle:      "RBAC governance is implemented",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Org",
			Description:     "RBAC governance is implemented",
			RemediationText: "Review and remediate rbac governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceRbacCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceRbacCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_rbac
	_ = findings
	return findings, nil
}

// GovernanceAbacCheck - ABAC governance is implemented
type GovernanceAbacCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceAbacCheck() *GovernanceAbacCheck {
	return &GovernanceAbacCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_abac",
			CheckTitle:      "ABAC governance is implemented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "ABAC governance is implemented",
			RemediationText: "Review and remediate abac governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceAbacCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceAbacCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_abac
	_ = findings
	return findings, nil
}

// GovernanceDacCheck - DAC governance is implemented
type GovernanceDacCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceDacCheck() *GovernanceDacCheck {
	return &GovernanceDacCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_dac",
			CheckTitle:      "DAC governance is implemented",
			ServiceName:     "ciem",
			Severity:        "low",
			ResourceType:    "Org",
			Description:     "DAC governance is implemented",
			RemediationText: "Review and remediate dac governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceDacCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceDacCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_dac
	_ = findings
	return findings, nil
}

// GovernanceMacCheck - MAC governance is implemented
type GovernanceMacCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceMacCheck() *GovernanceMacCheck {
	return &GovernanceMacCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_mac",
			CheckTitle:      "MAC governance is implemented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "MAC governance is implemented",
			RemediationText: "Review and remediate mac governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceMacCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceMacCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_mac
	_ = findings
	return findings, nil
}

// GovernanceSamlCheck - SAML governance is implemented
type GovernanceSamlCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceSamlCheck() *GovernanceSamlCheck {
	return &GovernanceSamlCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_saml",
			CheckTitle:      "SAML governance is implemented",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Org",
			Description:     "SAML governance is implemented",
			RemediationText: "Review and remediate saml governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceSamlCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceSamlCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_saml
	_ = findings
	return findings, nil
}

// GovernanceScimCheck - SCIM governance is implemented
type GovernanceScimCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceScimCheck() *GovernanceScimCheck {
	return &GovernanceScimCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_scim",
			CheckTitle:      "SCIM governance is implemented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "SCIM governance is implemented",
			RemediationText: "Review and remediate scim governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceScimCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceScimCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_scim
	_ = findings
	return findings, nil
}

// GovernanceJwtCheck - JWT governance is implemented
type GovernanceJwtCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceJwtCheck() *GovernanceJwtCheck {
	return &GovernanceJwtCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_jwt",
			CheckTitle:      "JWT governance is implemented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "JWT governance is implemented",
			RemediationText: "Review and remediate jwt governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceJwtCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceJwtCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_jwt
	_ = findings
	return findings, nil
}

// GovernanceOauthCheck - OAuth governance is implemented
type GovernanceOauthCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceOauthCheck() *GovernanceOauthCheck {
	return &GovernanceOauthCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_oauth",
			CheckTitle:      "OAuth governance is implemented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "OAuth governance is implemented",
			RemediationText: "Review and remediate oauth governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceOauthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceOauthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_oauth
	_ = findings
	return findings, nil
}

// GovernanceApiKeyCheck - API key governance is implemented
type GovernanceApiKeyCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceApiKeyCheck() *GovernanceApiKeyCheck {
	return &GovernanceApiKeyCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_api_key",
			CheckTitle:      "API key governance is implemented",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Org",
			Description:     "API key governance is implemented",
			RemediationText: "Review and remediate api key governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceApiKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceApiKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_api_key
	_ = findings
	return findings, nil
}

// GovernanceTokenCheck - Token governance is implemented
type GovernanceTokenCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceTokenCheck() *GovernanceTokenCheck {
	return &GovernanceTokenCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_token",
			CheckTitle:      "Token governance is implemented",
			ServiceName:     "ciem",
			Severity:        "medium",
			ResourceType:    "Org",
			Description:     "Token governance is implemented",
			RemediationText: "Review and remediate token governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceTokenCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceTokenCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_token
	_ = findings
	return findings, nil
}

// GovernanceCertificateCheck - Certificate governance is implemented
type GovernanceCertificateCheck struct {
	metadata models.CheckMetadata
}

func NewGovernanceCertificateCheck() *GovernanceCertificateCheck {
	return &GovernanceCertificateCheck{
		metadata: models.CheckMetadata{
			Provider:        "ciem",
			CheckID:         "ciem_governance_certificate",
			CheckTitle:      "Certificate governance is implemented",
			ServiceName:     "ciem",
			Severity:        "high",
			ResourceType:    "Org",
			Description:     "Certificate governance is implemented",
			RemediationText: "Review and remediate certificate governance is implemented",
			Categories:      []string{"ciem", "security"},
		},
	}
}

func (c *GovernanceCertificateCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GovernanceCertificateCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ciemProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ciemProvider")
	}
	client, err := p.Ciem(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement ciem_governance_certificate
	_ = findings
	return findings, nil
}
