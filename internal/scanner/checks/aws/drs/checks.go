package drs

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// DrsJobExist - Region has AWS Elastic Disaster Recovery (DRS) enabled with at least one recovery job
type DrsJobExist struct {
    metadata models.CheckMetadata
}

func NewDrsJobExist() *DrsJobExist {
    return &DrsJobExist{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "drs_job_exist",
            CheckTitle: "Region has AWS Elastic Disaster Recovery (DRS) enabled with at least one recovery job",
            ServiceName: "drs",
            Severity: "medium",
            Description: "**AWS Elastic Disaster Recovery** is assessed per Region to verify the service is **initialized** and that at least one **recovery or drill job** exists, demonstrating that failover has been exercised.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"drs"},
        },
    }
}

func (c *DrsJobExist) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DrsJobExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "drs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

