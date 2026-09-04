package securityhub

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// SecurityhubDelegatedAdminEnabledAllRegions - Security Hub has delegated admin configured and is enabled in all regions with organization auto-enable
type SecurityhubDelegatedAdminEnabledAllRegions struct {
    metadata models.CheckMetadata
}

func NewSecurityhubDelegatedAdminEnabledAllRegions() *SecurityhubDelegatedAdminEnabledAllRegions {
    return &SecurityhubDelegatedAdminEnabledAllRegions{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "securityhub_delegated_admin_enabled_all_regions",
            CheckTitle: "Security Hub has delegated admin configured and is enabled in all regions with organization auto-enable",
            ServiceName: "securityhub",
            Severity: "high",
            Description: "**AWS Security Hub** has a delegated administrator configured at the organization level, hubs are active in all opted-in regions, and organization auto-enable is active so that new member accounts are automatically enrolled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"securityhub"},
        },
    }
}

func (c *SecurityhubDelegatedAdminEnabledAllRegions) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecurityhubDelegatedAdminEnabledAllRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "securityhub",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SecurityhubEnabled - Security Hub is enabled with standards or integrations configured
type SecurityhubEnabled struct {
    metadata models.CheckMetadata
}

func NewSecurityhubEnabled() *SecurityhubEnabled {
    return &SecurityhubEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "securityhub_enabled",
            CheckTitle: "Security Hub is enabled with standards or integrations configured",
            ServiceName: "securityhub",
            Severity: "high",
            Description: "**AWS Security Hub** is `ACTIVE` in the Region and has at least one enabled **security standard** or connected **integration**. Otherwise, it is either not enabled or enabled without standards/integrations.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"securityhub"},
        },
    }
}

func (c *SecurityhubEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecurityhubEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "securityhub",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

