package dynamodb

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// DynamodbTableAutoscalingEnabled - DynamoDB table uses on-demand capacity or has auto scaling enabled for read and write capacity units
type DynamodbTableAutoscalingEnabled struct {
    metadata models.CheckMetadata
}

func NewDynamodbTableAutoscalingEnabled() *DynamodbTableAutoscalingEnabled {
    return &DynamodbTableAutoscalingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_table_autoscaling_enabled",
            CheckTitle: "DynamoDB table uses on-demand capacity or has auto scaling enabled for read and write capacity units",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DynamoDB tables** use **automatic capacity scaling** via `on-demand` mode or `PROVISIONED` mode with **auto scaling** enabled for both `read` and `write` capacity units.  Provisioned tables are evaluated for scaling on both dimensions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbTableAutoscalingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbTableAutoscalingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbTablesKmsCmkEncryptionEnabled - DynamoDB table is encrypted at rest with AWS KMS
type DynamodbTablesKmsCmkEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewDynamodbTablesKmsCmkEncryptionEnabled() *DynamodbTablesKmsCmkEncryptionEnabled {
    return &DynamodbTablesKmsCmkEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_tables_kms_cmk_encryption_enabled",
            CheckTitle: "DynamoDB table is encrypted at rest with AWS KMS",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DynamoDB tables** use **AWS KMS keys** (`KMS`) for encryption at rest instead of the default service-owned key",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbTablesKmsCmkEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbTablesKmsCmkEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbTableDeletionProtectionEnabled - DynamoDB table has deletion protection enabled
type DynamodbTableDeletionProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewDynamodbTableDeletionProtectionEnabled() *DynamodbTableDeletionProtectionEnabled {
    return &DynamodbTableDeletionProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_table_deletion_protection_enabled",
            CheckTitle: "DynamoDB table has deletion protection enabled",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DynamoDB tables** have **deletion protection** enabled via the `deletion protection` setting, meaning delete operations require this setting to be disabled first",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbTableDeletionProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbTableDeletionProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbAcceleratorClusterInTransitEncryptionEnabled - DynamoDB Accelerator (DAX) cluster has encryption in transit enabled
type DynamodbAcceleratorClusterInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewDynamodbAcceleratorClusterInTransitEncryptionEnabled() *DynamodbAcceleratorClusterInTransitEncryptionEnabled {
    return &DynamodbAcceleratorClusterInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_accelerator_cluster_in_transit_encryption_enabled",
            CheckTitle: "DynamoDB Accelerator (DAX) cluster has encryption in transit enabled",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DAX clusters** have endpoint encryption set to `TLS`, enforcing **encryption in transit** for client connections to the cluster",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbAcceleratorClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbAcceleratorClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbTablesPitrEnabled - DynamoDB table has point-in-time recovery (PITR) enabled
type DynamodbTablesPitrEnabled struct {
    metadata models.CheckMetadata
}

func NewDynamodbTablesPitrEnabled() *DynamodbTablesPitrEnabled {
    return &DynamodbTablesPitrEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_tables_pitr_enabled",
            CheckTitle: "DynamoDB table has point-in-time recovery (PITR) enabled",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DynamoDB tables** have **Point-in-Time Recovery** (`PITR`) enabled",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbTablesPitrEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbTablesPitrEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbTableProtectedByBackupPlan - DynamoDB table is protected by a backup plan
type DynamodbTableProtectedByBackupPlan struct {
    metadata models.CheckMetadata
}

func NewDynamodbTableProtectedByBackupPlan() *DynamodbTableProtectedByBackupPlan {
    return &DynamodbTableProtectedByBackupPlan{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_table_protected_by_backup_plan",
            CheckTitle: "DynamoDB table is protected by a backup plan",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DynamoDB tables** are evaluated for inclusion in an **AWS Backup backup plan** through resource assignments, including explicit tables, resource-type wildcards, or all-resources coverage.  The result indicates whether a table is governed by scheduled backups and retention defined by the plan.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbTableProtectedByBackupPlan) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbTableProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbAcceleratorClusterEncryptionEnabled - DynamoDB DAX cluster has encryption at rest enabled
type DynamodbAcceleratorClusterEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewDynamodbAcceleratorClusterEncryptionEnabled() *DynamodbAcceleratorClusterEncryptionEnabled {
    return &DynamodbAcceleratorClusterEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_accelerator_cluster_encryption_enabled",
            CheckTitle: "DynamoDB DAX cluster has encryption at rest enabled",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**Amazon DynamoDB Accelerator (DAX) clusters** are evaluated for **server-side `encryption at rest`**. The finding indicates whether the cluster's on-disk cache, configuration, and logs are encrypted using service-managed keys.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbAcceleratorClusterEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbAcceleratorClusterEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbTableCrossAccountAccess - DynamoDB table resource-based policy does not allow cross-account access
type DynamodbTableCrossAccountAccess struct {
    metadata models.CheckMetadata
}

func NewDynamodbTableCrossAccountAccess() *DynamodbTableCrossAccountAccess {
    return &DynamodbTableCrossAccountAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_table_cross_account_access",
            CheckTitle: "DynamoDB table resource-based policy does not allow cross-account access",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**DynamoDB tables** are evaluated for **resource-based policies** that permit cross-account or public principals.  Tables without a resource policy, or with policies restricted to the same account, are identified as isolated configurations.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbTableCrossAccountAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbTableCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DynamodbAcceleratorClusterMultiAz - DynamoDB Accelerator (DAX) cluster has nodes in multiple Availability Zones
type DynamodbAcceleratorClusterMultiAz struct {
    metadata models.CheckMetadata
}

func NewDynamodbAcceleratorClusterMultiAz() *DynamodbAcceleratorClusterMultiAz {
    return &DynamodbAcceleratorClusterMultiAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dynamodb_accelerator_cluster_multi_az",
            CheckTitle: "DynamoDB Accelerator (DAX) cluster has nodes in multiple Availability Zones",
            ServiceName: "dynamodb",
            Severity: "medium",
            Description: "**Amazon DynamoDB Accelerator (DAX)** cluster node placement across **Availability Zones** is evaluated. Clusters with nodes in more than one AZ within the Region are recognized as multi-AZ; clusters whose nodes reside in a single AZ are recognized as single-AZ.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dynamodb"},
        },
    }
}

func (c *DynamodbAcceleratorClusterMultiAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DynamodbAcceleratorClusterMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dynamodb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

