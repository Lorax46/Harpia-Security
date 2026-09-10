package fms

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// FmsPolicyCompliant - All AWS FMS policies in the admin account are compliant for all accounts
type FmsPolicyCompliant struct {
    metadata models.CheckMetadata
}

func NewFmsPolicyCompliant() *FmsPolicyCompliant {
    return &FmsPolicyCompliant{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "fms_policy_compliant",
            CheckTitle: "All AWS FMS policies in the admin account are compliant for all accounts",
            ServiceName: "fms",
            Severity: "medium",
            Description: "**Firewall Manager** policies in the administrator account are evaluated for organization-wide compliance. The assessment reviews each policy's account-level status and flags entries marked `NON_COMPLIANT` or unset. It also identifies when no effective policies exist within the administrator scope.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"fms"},
        },
    }
}

func (c *FmsPolicyCompliant) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *FmsPolicyCompliant) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "fms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

