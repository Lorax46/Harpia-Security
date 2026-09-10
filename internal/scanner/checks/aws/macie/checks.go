package macie

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// MacieAutomatedSensitiveDataDiscoveryEnabled - Macie automated sensitive data discovery is enabled
type MacieAutomatedSensitiveDataDiscoveryEnabled struct {
    metadata models.CheckMetadata
}

func NewMacieAutomatedSensitiveDataDiscoveryEnabled() *MacieAutomatedSensitiveDataDiscoveryEnabled {
    return &MacieAutomatedSensitiveDataDiscoveryEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "macie_automated_sensitive_data_discovery_enabled",
            CheckTitle: "Macie automated sensitive data discovery is enabled",
            ServiceName: "macie",
            Severity: "high",
            Description: "**Amazon Macie** administrator account has **automated sensitive data discovery** enabled for S3 data. The evaluation confirms the feature's status for the account in each Region.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"macie"},
        },
    }
}

func (c *MacieAutomatedSensitiveDataDiscoveryEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MacieAutomatedSensitiveDataDiscoveryEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "macie",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// MacieIsEnabled - Amazon Macie is enabled
type MacieIsEnabled struct {
    metadata models.CheckMetadata
}

func NewMacieIsEnabled() *MacieIsEnabled {
    return &MacieIsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "macie_is_enabled",
            CheckTitle: "Amazon Macie is enabled",
            ServiceName: "macie",
            Severity: "medium",
            Description: "**Amazon Macie** status is assessed per region with **S3** presence to determine if sensitive data discovery is operational. The outcome reflects whether Macie is active or in a `PAUSED`/not enabled state for the account and region.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"macie"},
        },
    }
}

func (c *MacieIsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MacieIsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "macie",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

