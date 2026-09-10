package codecommit

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// CodecommitRepositoryNoSecrets - CodeCommit repository has no secrets in its default branch
type CodecommitRepositoryNoSecrets struct {
    metadata models.CheckMetadata
}

func NewCodecommitRepositoryNoSecrets() *CodecommitRepositoryNoSecrets {
    return &CodecommitRepositoryNoSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codecommit_repository_no_secrets",
            CheckTitle: "CodeCommit repository has no secrets in its default branch",
            ServiceName: "codecommit",
            Severity: "high",
            Description: "**AWS CodeCommit repositories** are scanned for **hardcoded secrets** such as API keys, tokens, and passwords in every file tracked at the tip of the default branch. CodeCommit repositories, including their branches and commit history, are a top source of leaked credentials, and secrets can persist in history even after being removed from HEAD.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codecommit"},
        },
    }
}

func (c *CodecommitRepositoryNoSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodecommitRepositoryNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codecommit",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

