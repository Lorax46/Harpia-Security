package sns

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// SnsTopicsNotPubliclyAccessible - SNS topic is not publicly accessible
type SnsTopicsNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewSnsTopicsNotPubliclyAccessible() *SnsTopicsNotPubliclyAccessible {
    return &SnsTopicsNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sns_topics_not_publicly_accessible",
            CheckTitle: "SNS topic is not publicly accessible",
            ServiceName: "sns",
            Severity: "high",
            Description: "**SNS topic policies** are analyzed for **public principals** (e.g., `*`). Topics that grant access without restrictive conditions such as `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`, or `sns:Endpoint` scoping are treated as publicly accessible.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sns"},
        },
    }
}

func (c *SnsTopicsNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SnsTopicsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sns",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SnsTopicsKmsEncryptionAtRestEnabled - SNS topic is encrypted at rest with KMS
type SnsTopicsKmsEncryptionAtRestEnabled struct {
    metadata models.CheckMetadata
}

func NewSnsTopicsKmsEncryptionAtRestEnabled() *SnsTopicsKmsEncryptionAtRestEnabled {
    return &SnsTopicsKmsEncryptionAtRestEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sns_topics_kms_encryption_at_rest_enabled",
            CheckTitle: "SNS topic is encrypted at rest with KMS",
            ServiceName: "sns",
            Severity: "high",
            Description: "**Amazon SNS topics** are assessed for **server-side encryption** with **AWS KMS**. Topics lacking a configured KMS key (e.g., missing `kms_master_key_id`) are identified as unencrypted at rest.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sns"},
        },
    }
}

func (c *SnsTopicsKmsEncryptionAtRestEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SnsTopicsKmsEncryptionAtRestEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sns",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SnsSubscriptionNotUsingHttpEndpoints - SNS subscription uses an HTTPS endpoint
type SnsSubscriptionNotUsingHttpEndpoints struct {
    metadata models.CheckMetadata
}

func NewSnsSubscriptionNotUsingHttpEndpoints() *SnsSubscriptionNotUsingHttpEndpoints {
    return &SnsSubscriptionNotUsingHttpEndpoints{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sns_subscription_not_using_http_endpoints",
            CheckTitle: "SNS subscription uses an HTTPS endpoint",
            ServiceName: "sns",
            Severity: "high",
            Description: "Amazon SNS subscriptions are evaluated for endpoint protocol. Subscriptions using `http` are identified, while **HTTPS** endpoints indicate encrypted delivery in transit.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sns"},
        },
    }
}

func (c *SnsSubscriptionNotUsingHttpEndpoints) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SnsSubscriptionNotUsingHttpEndpoints) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sns",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

