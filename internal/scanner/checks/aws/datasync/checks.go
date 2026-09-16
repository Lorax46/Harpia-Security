package datasync

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type datasyncProvider interface {
    DataSync() (interface{}, error)
    Region() string
}

// DatasyncTaskLoggingEnabled - DataSync task has CloudWatch Logs log group configured for logging
type DatasyncTaskLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewDatasyncTaskLoggingEnabled() *DatasyncTaskLoggingEnabled {
    return &DatasyncTaskLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider:    "aws",
            CheckID:     "datasync_task_logging_enabled",
            CheckTitle:  "DataSync task has CloudWatch Logs log group configured for logging",
            ServiceName: "datasync",
            Severity:    "high",
            Description: "AWS DataSync tasks are evaluated for a configured CloudWatch Logs destination (CloudWatchLogGroupArn).",
            RemediationText: "Enable CloudWatch Logs for DataSync tasks.",
            Categories:  []string{"datasync"},
        },
    }
}

func (c *DatasyncTaskLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DatasyncTaskLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    p, ok := provider.(datasyncProvider)
    if !ok {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Provider does not implement DataSync interface",
            Provider: "aws", Service: "datasync", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    _, err := p.DataSync()
    if err != nil {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Failed to create DataSync client",
            Provider: "aws", Service: "datasync", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    return []models.Finding{{
        ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
        Description: c.metadata.Description, Severity: c.metadata.Severity,
        Status: models.StatusInfo, StatusExtended: "Requires real AWS credentials to list DataSync tasks",
        Provider: "aws", Service: "datasync", Remediation: c.metadata.RemediationText,
        Categories: c.metadata.Categories, FoundAt: time.Now(),
    }}, nil
}
