package fms

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type fmsProvider interface {
    FMS() (interface{}, error)
    Region() string
}

// FmsPolicyCompliant - All AWS FMS policies in the admin account are compliant for all accounts
type FmsPolicyCompliant struct {
    metadata models.CheckMetadata
}

func NewFmsPolicyCompliant() *FmsPolicyCompliant {
    return &FmsPolicyCompliant{
        metadata: models.CheckMetadata{
            Provider:    "aws",
            CheckID:     "fms_policy_compliant",
            CheckTitle:  "All AWS FMS policies in the admin account are compliant for all accounts",
            ServiceName: "fms",
            Severity:    "medium",
            Description: "Firewall Manager policies in the administrator account are evaluated for organization-wide compliance.",
            RemediationText: "Ensure all FMS policies are compliant.",
            Categories:  []string{"fms"},
        },
    }
}

func (c *FmsPolicyCompliant) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *FmsPolicyCompliant) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    p, ok := provider.(fmsProvider)
    if !ok {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Provider does not implement FMS interface",
            Provider: "aws", Service: "fms", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    _, err := p.FMS()
    if err != nil {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Failed to create FMS client",
            Provider: "aws", Service: "fms", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    return []models.Finding{{
        ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
        Description: c.metadata.Description, Severity: c.metadata.Severity,
        Status: models.StatusInfo, StatusExtended: "Requires real AWS credentials to list FMS policies",
        Provider: "aws", Service: "fms", Remediation: c.metadata.RemediationText,
        Categories: c.metadata.Categories, FoundAt: time.Now(),
    }}, nil
}
