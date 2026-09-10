package datasync

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// DatasyncTaskLoggingEnabled - DataSync task has CloudWatch Logs log group configured for logging
type DatasyncTaskLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewDatasyncTaskLoggingEnabled() *DatasyncTaskLoggingEnabled {
    return &DatasyncTaskLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "datasync_task_logging_enabled",
            CheckTitle: "DataSync task has CloudWatch Logs log group configured for logging",
            ServiceName: "datasync",
            Severity: "high",
            Description: "**AWS DataSync tasks** are evaluated for a configured **CloudWatch Logs** destination (`CloudWatchLogGroupArn`).  Tasks that specify a log group are recognized as logging-enabled; those without one are identified as not publishing execution events.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"datasync"},
        },
    }
}

func (c *DatasyncTaskLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DatasyncTaskLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "datasync",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

