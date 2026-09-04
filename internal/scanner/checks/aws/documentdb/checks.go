package documentdb

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// DocumentdbClusterBackupEnabled - DocumentDB cluster has automated backups enabled with retention period of at least 7 days
type DocumentdbClusterBackupEnabled struct {
    metadata models.CheckMetadata
}

func NewDocumentdbClusterBackupEnabled() *DocumentdbClusterBackupEnabled {
    return &DocumentdbClusterBackupEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "documentdb_cluster_backup_enabled",
            CheckTitle: "DocumentDB cluster has automated backups enabled with retention period of at least 7 days",
            ServiceName: "documentdb",
            Severity: "medium",
            Description: "**Amazon DocumentDB clusters** are evaluated for **automated backups** and an adequate **backup retention period**. Clusters should have `backup_retention_period` set to at least the configured minimum (default `7` days). Values of `0` indicate backups are disabled; values below the threshold are considered insufficient.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"documentdb"},
        },
    }
}

func (c *DocumentdbClusterBackupEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DocumentdbClusterBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "documentdb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DocumentdbClusterPublicSnapshot - DocumentDB manual cluster snapshot is not shared publicly
type DocumentdbClusterPublicSnapshot struct {
    metadata models.CheckMetadata
}

func NewDocumentdbClusterPublicSnapshot() *DocumentdbClusterPublicSnapshot {
    return &DocumentdbClusterPublicSnapshot{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "documentdb_cluster_public_snapshot",
            CheckTitle: "DocumentDB manual cluster snapshot is not shared publicly",
            ServiceName: "documentdb",
            Severity: "critical",
            Description: "**Amazon DocumentDB** manual cluster snapshot visibility is evaluated to detect snapshots marked as **public** instead of limited to specified AWS accounts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"documentdb"},
        },
    }
}

func (c *DocumentdbClusterPublicSnapshot) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DocumentdbClusterPublicSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "documentdb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DocumentdbClusterCloudwatchLogExport - DocumentDB cluster exports audit and profiler logs to CloudWatch Logs
type DocumentdbClusterCloudwatchLogExport struct {
    metadata models.CheckMetadata
}

func NewDocumentdbClusterCloudwatchLogExport() *DocumentdbClusterCloudwatchLogExport {
    return &DocumentdbClusterCloudwatchLogExport{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "documentdb_cluster_cloudwatch_log_export",
            CheckTitle: "DocumentDB cluster exports audit and profiler logs to CloudWatch Logs",
            ServiceName: "documentdb",
            Severity: "medium",
            Description: "Amazon DocumentDB clusters are evaluated for exporting `audit` and `profiler` logs to **CloudWatch Logs**. Clusters missing one or both log types are identified as lacking complete log export configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"documentdb"},
        },
    }
}

func (c *DocumentdbClusterCloudwatchLogExport) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DocumentdbClusterCloudwatchLogExport) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "documentdb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DocumentdbClusterStorageEncrypted - DocumentDB cluster storage is encrypted at rest
type DocumentdbClusterStorageEncrypted struct {
    metadata models.CheckMetadata
}

func NewDocumentdbClusterStorageEncrypted() *DocumentdbClusterStorageEncrypted {
    return &DocumentdbClusterStorageEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "documentdb_cluster_storage_encrypted",
            CheckTitle: "DocumentDB cluster storage is encrypted at rest",
            ServiceName: "documentdb",
            Severity: "medium",
            Description: "**Amazon DocumentDB clusters** are assessed for **storage encryption at rest** via the cluster's `encrypted` setting.  It identifies clusters where data volumes, automated backups, and snapshots aren't protected by AWS KMS-managed encryption.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"documentdb"},
        },
    }
}

func (c *DocumentdbClusterStorageEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DocumentdbClusterStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "documentdb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DocumentdbClusterMultiAzEnabled - DocumentDB cluster has Multi-AZ enabled
type DocumentdbClusterMultiAzEnabled struct {
    metadata models.CheckMetadata
}

func NewDocumentdbClusterMultiAzEnabled() *DocumentdbClusterMultiAzEnabled {
    return &DocumentdbClusterMultiAzEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "documentdb_cluster_multi_az_enabled",
            CheckTitle: "DocumentDB cluster has Multi-AZ enabled",
            ServiceName: "documentdb",
            Severity: "medium",
            Description: "**Amazon DocumentDB clusters** with **Multi-AZ** (`multi_az`) indicate deployment of a primary and one or more replicas across Availability Zones.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"documentdb"},
        },
    }
}

func (c *DocumentdbClusterMultiAzEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DocumentdbClusterMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "documentdb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DocumentdbClusterDeletionProtection - DocumentDB cluster has deletion protection enabled
type DocumentdbClusterDeletionProtection struct {
    metadata models.CheckMetadata
}

func NewDocumentdbClusterDeletionProtection() *DocumentdbClusterDeletionProtection {
    return &DocumentdbClusterDeletionProtection{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "documentdb_cluster_deletion_protection",
            CheckTitle: "DocumentDB cluster has deletion protection enabled",
            ServiceName: "documentdb",
            Severity: "medium",
            Description: "**Amazon DocumentDB clusters** are evaluated for the `deletion_protection` setting on the cluster configuration.  The finding highlights clusters where this protection is not enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"documentdb"},
        },
    }
}

func (c *DocumentdbClusterDeletionProtection) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DocumentdbClusterDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "documentdb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

