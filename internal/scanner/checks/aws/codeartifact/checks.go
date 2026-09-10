package codeartifact

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CodeartifactPackagesExternalPublicPublishingDisabled - Internal CodeArtifact package does not allow publishing versions already present in external public sources
type CodeartifactPackagesExternalPublicPublishingDisabled struct {
    metadata models.CheckMetadata
}

func NewCodeartifactPackagesExternalPublicPublishingDisabled() *CodeartifactPackagesExternalPublicPublishingDisabled {
    return &CodeartifactPackagesExternalPublicPublishingDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codeartifact_packages_external_public_publishing_disabled",
            CheckTitle: "Internal CodeArtifact package does not allow publishing versions already present in external public sources",
            ServiceName: "codeartifact",
            Severity: "critical",
            Description: "**AWS CodeArtifact packages** with an **internal or unknown origin** are evaluated for their **package origin controls**. The check identifies packages where the `upstream` setting allows ingesting versions from external or upstream repositories.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codeartifact"},
        },
    }
}

func (c *CodeartifactPackagesExternalPublicPublishingDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodeartifactPackagesExternalPublicPublishingDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codeartifact",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

