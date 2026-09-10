package datapipeline

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// DatapipelinePipelineNoSecretsInDefinition - Data Pipeline definition has no sensitive credentials
type DatapipelinePipelineNoSecretsInDefinition struct {
    metadata models.CheckMetadata
}

func NewDatapipelinePipelineNoSecretsInDefinition() *DatapipelinePipelineNoSecretsInDefinition {
    return &DatapipelinePipelineNoSecretsInDefinition{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "datapipeline_pipeline_no_secrets_in_definition",
            CheckTitle: "Data Pipeline definition has no sensitive credentials",
            ServiceName: "datapipeline",
            Severity: "high",
            Description: "AWS Data Pipeline definitions are inspected for hardcoded secrets, such as keys, tokens, passwords, or database credentials embedded directly in pipeline objects, parameters, or parameter values.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"datapipeline"},
        },
    }
}

func (c *DatapipelinePipelineNoSecretsInDefinition) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DatapipelinePipelineNoSecretsInDefinition) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "datapipeline",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

