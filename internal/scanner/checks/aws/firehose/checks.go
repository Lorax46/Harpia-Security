package firehose

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// FirehoseStreamEncryptedAtRest - Kinesis Data Firehose delivery stream is encrypted at rest
type FirehoseStreamEncryptedAtRest struct {
    metadata models.CheckMetadata
}

func NewFirehoseStreamEncryptedAtRest() *FirehoseStreamEncryptedAtRest {
    return &FirehoseStreamEncryptedAtRest{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "firehose_stream_encrypted_at_rest",
            CheckTitle: "Kinesis Data Firehose delivery stream is encrypted at rest",
            ServiceName: "firehose",
            Severity: "medium",
            Description: "**Amazon Data Firehose** delivery streams must enable **server-side encryption at rest** with AWS KMS regardless of the source type. Encryption of upstream sources such as **Kinesis Data Streams** or **MSK** does not replace the need to protect the delivery stream itself.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"firehose"},
        },
    }
}

func (c *FirehoseStreamEncryptedAtRest) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *FirehoseStreamEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "firehose",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

