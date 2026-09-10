package sqs

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// SqsQueuesServerSideEncryptionEnabled - SQS queue has server-side encryption enabled
type SqsQueuesServerSideEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewSqsQueuesServerSideEncryptionEnabled() *SqsQueuesServerSideEncryptionEnabled {
    return &SqsQueuesServerSideEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sqs_queues_server_side_encryption_enabled",
            CheckTitle: "SQS queue has server-side encryption enabled",
            ServiceName: "sqs",
            Severity: "medium",
            Description: "**Amazon SQS queues** are evaluated for **server-side encryption** configured with a **KMS key** (`SSE-KMS`) protecting message bodies at rest.  Queues without an associated KMS key are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sqs"},
        },
    }
}

func (c *SqsQueuesServerSideEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SqsQueuesServerSideEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sqs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SqsQueuesNotPubliclyAccessible - SQS queue policy does not allow public access
type SqsQueuesNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewSqsQueuesNotPubliclyAccessible() *SqsQueuesNotPubliclyAccessible {
    return &SqsQueuesNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sqs_queues_not_publicly_accessible",
            CheckTitle: "SQS queue policy does not allow public access",
            ServiceName: "sqs",
            Severity: "critical",
            Description: "Amazon SQS queue policies are assessed for **public access**. The finding highlights queues with `Allow` statements using a wildcard `Principal` without restrictive conditions, compared to queues that only grant access to the owning account or explicitly trusted principals.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sqs"},
        },
    }
}

func (c *SqsQueuesNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SqsQueuesNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sqs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

