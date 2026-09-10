package organizations

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// OrganizationsTagsPoliciesEnabledAndAttached - AWS Organization has tag policies enabled and attached
type OrganizationsTagsPoliciesEnabledAndAttached struct {
    metadata models.CheckMetadata
}

func NewOrganizationsTagsPoliciesEnabledAndAttached() *OrganizationsTagsPoliciesEnabledAndAttached {
    return &OrganizationsTagsPoliciesEnabledAndAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "organizations_tags_policies_enabled_and_attached",
            CheckTitle: "AWS Organization has tag policies enabled and attached",
            ServiceName: "organizations",
            Severity: "low",
            Description: "**AWS Organizations** tag policies are evaluated for their presence and attachment to organization targets (accounts or OUs), distinguishing between no policies, policies defined but not attached, and policies attached to at least one target.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"organizations"},
        },
    }
}

func (c *OrganizationsTagsPoliciesEnabledAndAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OrganizationsTagsPoliciesEnabledAndAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "organizations",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OrganizationsDelegatedAdministrators - AWS Organization has only trusted delegated administrators
type OrganizationsDelegatedAdministrators struct {
    metadata models.CheckMetadata
}

func NewOrganizationsDelegatedAdministrators() *OrganizationsDelegatedAdministrators {
    return &OrganizationsDelegatedAdministrators{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "organizations_delegated_administrators",
            CheckTitle: "AWS Organization has only trusted delegated administrators",
            ServiceName: "organizations",
            Severity: "critical",
            Description: "**AWS Organizations delegated administrators** are compared against a predefined **trusted list** to identify delegations that are not explicitly approved. The evaluation also notes when no delegated administrators exist.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"organizations"},
        },
    }
}

func (c *OrganizationsDelegatedAdministrators) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OrganizationsDelegatedAdministrators) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "organizations",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OrganizationsAccountPartOfOrganizations - AWS account is a member of an active AWS Organization
type OrganizationsAccountPartOfOrganizations struct {
    metadata models.CheckMetadata
}

func NewOrganizationsAccountPartOfOrganizations() *OrganizationsAccountPartOfOrganizations {
    return &OrganizationsAccountPartOfOrganizations{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "organizations_account_part_of_organizations",
            CheckTitle: "AWS account is a member of an active AWS Organization",
            ServiceName: "organizations",
            Severity: "medium",
            Description: "**AWS account** membership in **AWS Organizations** with organization status `ACTIVE`.  Assesses if the account is associated with an organization and that the organization state is `ACTIVE`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"organizations"},
        },
    }
}

func (c *OrganizationsAccountPartOfOrganizations) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OrganizationsAccountPartOfOrganizations) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "organizations",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OrganizationsOptOutAiServicesPolicy - AWS Organization has opted out of all AI services and child accounts cannot override the policy
type OrganizationsOptOutAiServicesPolicy struct {
    metadata models.CheckMetadata
}

func NewOrganizationsOptOutAiServicesPolicy() *OrganizationsOptOutAiServicesPolicy {
    return &OrganizationsOptOutAiServicesPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "organizations_opt_out_ai_services_policy",
            CheckTitle: "AWS Organization has opted out of all AI services and child accounts cannot override the policy",
            ServiceName: "organizations",
            Severity: "medium",
            Description: "**AWS Organizations** is assessed for an AI services opt-out policy that sets `services.default.opt_out_policy` to `optOut` and blocks child overrides via `@@operators_allowed_for_child_policies` set to `@@none`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"organizations"},
        },
    }
}

func (c *OrganizationsOptOutAiServicesPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OrganizationsOptOutAiServicesPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "organizations",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OrganizationsScpCheckDenyRegions - AWS Organization restricts operations to only the configured AWS Regions with SCP policies
type OrganizationsScpCheckDenyRegions struct {
    metadata models.CheckMetadata
}

func NewOrganizationsScpCheckDenyRegions() *OrganizationsScpCheckDenyRegions {
    return &OrganizationsScpCheckDenyRegions{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "organizations_scp_check_deny_regions",
            CheckTitle: "AWS Organization restricts operations to only the configured AWS Regions with SCP policies",
            ServiceName: "organizations",
            Severity: "high",
            Description: "**AWS Organizations SCPs** limit account actions to approved regions using conditions on `aws:RequestedRegion`.  This evaluates whether policies exist and fully restrict access to the configured allowlist, rather than only some regions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"organizations"},
        },
    }
}

func (c *OrganizationsScpCheckDenyRegions) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OrganizationsScpCheckDenyRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "organizations",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

