package accessanalyzer

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AccessanalyzerEnabledWithoutFindings - IAM Access Analyzer analyzer is active and has no active findings
type AccessanalyzerEnabledWithoutFindings struct {
    metadata models.CheckMetadata
}

func NewAccessanalyzerEnabledWithoutFindings() *AccessanalyzerEnabledWithoutFindings {
    return &AccessanalyzerEnabledWithoutFindings{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "accessanalyzer_enabled_without_findings",
            CheckTitle: "IAM Access Analyzer analyzer is active and has no active findings",
            ServiceName: "accessanalyzer",
            Severity: "low",
            Description: "**IAM Access Analyzer** analyzers are in `Active` state and currently report zero `Active` findings within their scope of monitored resources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"accessanalyzer"},
        },
    }
}

func (c *AccessanalyzerEnabledWithoutFindings) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AccessanalyzerEnabledWithoutFindings) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "accessanalyzer",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AccessanalyzerEnabled - IAM Access Analyzer is enabled
type AccessanalyzerEnabled struct {
    metadata models.CheckMetadata
}

func NewAccessanalyzerEnabled() *AccessanalyzerEnabled {
    return &AccessanalyzerEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "accessanalyzer_enabled",
            CheckTitle: "IAM Access Analyzer is enabled",
            ServiceName: "accessanalyzer",
            Severity: "low",
            Description: "**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"accessanalyzer"},
        },
    }
}

func (c *AccessanalyzerEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AccessanalyzerEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "accessanalyzer",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

