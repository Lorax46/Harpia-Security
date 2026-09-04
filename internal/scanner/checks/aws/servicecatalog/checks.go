package servicecatalog

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// ServicecatalogPortfolioSharedWithinOrganizationOnly - Service Catalog portfolio is shared only within the AWS Organization
type ServicecatalogPortfolioSharedWithinOrganizationOnly struct {
    metadata models.CheckMetadata
}

func NewServicecatalogPortfolioSharedWithinOrganizationOnly() *ServicecatalogPortfolioSharedWithinOrganizationOnly {
    return &ServicecatalogPortfolioSharedWithinOrganizationOnly{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "servicecatalog_portfolio_shared_within_organization_only",
            CheckTitle: "Service Catalog portfolio is shared only within the AWS Organization",
            ServiceName: "servicecatalog",
            Severity: "high",
            Description: "**AWS Service Catalog portfolios** are assessed to confirm sharing occurs via **AWS Organizations** integration, not direct `ACCOUNT` shares. It reviews shared portfolios and identifies those targeted to individual accounts instead of organizational scopes.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"servicecatalog"},
        },
    }
}

func (c *ServicecatalogPortfolioSharedWithinOrganizationOnly) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ServicecatalogPortfolioSharedWithinOrganizationOnly) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "servicecatalog",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

