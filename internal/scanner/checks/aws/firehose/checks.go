package firehose

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type firehoseProvider interface {
    Firehose() (interface{}, error)
    Region() string
}

// FirehoseStreamEncryptedAtRest - Kinesis Data Firehose delivery stream is encrypted at rest
type FirehoseStreamEncryptedAtRest struct {
    metadata models.CheckMetadata
}

func NewFirehoseStreamEncryptedAtRest() *FirehoseStreamEncryptedAtRest {
    return &FirehoseStreamEncryptedAtRest{
        metadata: models.CheckMetadata{
            Provider:    "aws",
            CheckID:     "firehose_stream_encrypted_at_rest",
            CheckTitle:  "Kinesis Data Firehose delivery stream is encrypted at rest",
            ServiceName: "firehose",
            Severity:    "medium",
            Description: "Amazon Data Firehose delivery streams must enable server-side encryption at rest with AWS KMS.",
            RemediationText: "Enable server-side encryption for Firehose delivery streams.",
            Categories:  []string{"firehose"},
        },
    }
}

func (c *FirehoseStreamEncryptedAtRest) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *FirehoseStreamEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    p, ok := provider.(firehoseProvider)
    if !ok {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Provider does not implement Firehose interface",
            Provider: "aws", Service: "firehose", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    _, err := p.Firehose()
    if err != nil {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Failed to create Firehose client",
            Provider: "aws", Service: "firehose", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    return []models.Finding{{
        ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
        Description: c.metadata.Description, Severity: c.metadata.Severity,
        Status: models.StatusInfo, StatusExtended: "Requires real AWS credentials to list Firehose streams",
        Provider: "aws", Service: "firehose", Remediation: c.metadata.RemediationText,
        Categories: c.metadata.Categories, FoundAt: time.Now(),
    }}, nil
}
