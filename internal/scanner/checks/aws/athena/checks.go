package athena

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AthenaWorkgroupEncryption - Athena workgroup encrypts query results in S3 with server-side encryption
type AthenaWorkgroupEncryption struct {
    metadata models.CheckMetadata
}

func NewAthenaWorkgroupEncryption() *AthenaWorkgroupEncryption {
    return &AthenaWorkgroupEncryption{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "athena_workgroup_encryption",
            CheckTitle: "Athena workgroup encrypts query results in S3 with server-side encryption",
            ServiceName: "athena",
            Severity: "medium",
            Description: "**Athena workgroups** are evaluated for **encryption of query results** to confirm result data is stored encrypted at rest, whether saved in Amazon S3 or via managed query results",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"athena"},
        },
    }
}

func (c *AthenaWorkgroupEncryption) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AthenaWorkgroupEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "athena",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AthenaWorkgroupLoggingEnabled - Amazon Athena workgroup has CloudWatch logging enabled
type AthenaWorkgroupLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewAthenaWorkgroupLoggingEnabled() *AthenaWorkgroupLoggingEnabled {
    return &AthenaWorkgroupLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "athena_workgroup_logging_enabled",
            CheckTitle: "Amazon Athena workgroup has CloudWatch logging enabled",
            ServiceName: "athena",
            Severity: "medium",
            Description: "**Athena workgroups** publish **query metrics** to CloudWatch. This evaluation determines whether each workgroup has query activity logging enabled in CloudWatch.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"athena"},
        },
    }
}

func (c *AthenaWorkgroupLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AthenaWorkgroupLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "athena",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AthenaWorkgroupEnforceConfiguration - Athena workgroup enforces workgroup configuration and cannot be overridden by client-side settings
type AthenaWorkgroupEnforceConfiguration struct {
    metadata models.CheckMetadata
}

func NewAthenaWorkgroupEnforceConfiguration() *AthenaWorkgroupEnforceConfiguration {
    return &AthenaWorkgroupEnforceConfiguration{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "athena_workgroup_enforce_configuration",
            CheckTitle: "Athena workgroup enforces workgroup configuration and cannot be overridden by client-side settings",
            ServiceName: "athena",
            Severity: "medium",
            Description: "**Athena workgroups** that set `enforce_workgroup_configuration=true` apply the **workgroup's settings** to every query, overriding client-side options for results location, expected bucket owner, encryption, and control of objects written to the results bucket.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"athena"},
        },
    }
}

func (c *AthenaWorkgroupEnforceConfiguration) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AthenaWorkgroupEnforceConfiguration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "athena",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

