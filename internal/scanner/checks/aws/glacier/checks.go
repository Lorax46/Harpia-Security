package glacier

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// GlacierVaultsPolicyPublicAccess - S3 Glacier vault has no policy or its policy does not allow access to everyone
type GlacierVaultsPolicyPublicAccess struct {
    metadata models.CheckMetadata
}

func NewGlacierVaultsPolicyPublicAccess() *GlacierVaultsPolicyPublicAccess {
    return &GlacierVaultsPolicyPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glacier_vaults_policy_public_access",
            CheckTitle: "S3 Glacier vault has no policy or its policy does not allow access to everyone",
            ServiceName: "glacier",
            Severity: "critical",
            Description: "**Glacier vault** access policy is evaluated for exposure to **public principals**. The finding highlights `Allow` statements that grant access to `Principal: '*'` (including wildcard forms), and notes when a vault lacks a policy.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glacier"},
        },
    }
}

func (c *GlacierVaultsPolicyPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlacierVaultsPolicyPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glacier",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

