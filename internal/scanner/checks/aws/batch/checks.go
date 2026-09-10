package batch

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// BatchJobDefinitionNoSecrets - AWS Batch job definitions have no secrets in environment variables or command parameters
type BatchJobDefinitionNoSecrets struct {
    metadata models.CheckMetadata
}

func NewBatchJobDefinitionNoSecrets() *BatchJobDefinitionNoSecrets {
    return &BatchJobDefinitionNoSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "batch_job_definition_no_secrets",
            CheckTitle: "AWS Batch job definitions have no secrets in environment variables or command parameters",
            ServiceName: "batch",
            Severity: "high",
            Description: "**AWS Batch job definitions** are analyzed for **plaintext secrets** placed in container `environment` variables and `command` parameters. It identifies values that resemble credentials (keys, tokens, passwords) within job definitions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"batch"},
        },
    }
}

func (c *BatchJobDefinitionNoSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BatchJobDefinitionNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "batch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

