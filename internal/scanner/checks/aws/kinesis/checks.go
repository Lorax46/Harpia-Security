package kinesis

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// KinesisStreamEncryptedAtRest - Kinesis stream is encrypted at rest with KMS
type KinesisStreamEncryptedAtRest struct {
    metadata models.CheckMetadata
}

func NewKinesisStreamEncryptedAtRest() *KinesisStreamEncryptedAtRest {
    return &KinesisStreamEncryptedAtRest{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kinesis_stream_encrypted_at_rest",
            CheckTitle: "Kinesis stream is encrypted at rest with KMS",
            ServiceName: "kinesis",
            Severity: "high",
            Description: "**Amazon Kinesis Data Streams** with **server-side encryption** use **AWS KMS** to protect records at rest. The evaluation determines whether a stream has `SSE-KMS` configured with a KMS key; streams lacking KMS-based at rest encryption are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kinesis"},
        },
    }
}

func (c *KinesisStreamEncryptedAtRest) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KinesisStreamEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kinesis",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KinesisStreamDataRetentionPeriod - Kinesis stream retains data for at least the required minimum hours
type KinesisStreamDataRetentionPeriod struct {
    metadata models.CheckMetadata
}

func NewKinesisStreamDataRetentionPeriod() *KinesisStreamDataRetentionPeriod {
    return &KinesisStreamDataRetentionPeriod{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kinesis_stream_data_retention_period",
            CheckTitle: "Kinesis stream retains data for at least the required minimum hours",
            ServiceName: "kinesis",
            Severity: "medium",
            Description: "**Kinesis Data Streams** retention window is evaluated to confirm records are kept for at least the configured minimum duration (default `168` hours).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kinesis"},
        },
    }
}

func (c *KinesisStreamDataRetentionPeriod) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KinesisStreamDataRetentionPeriod) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kinesis",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

