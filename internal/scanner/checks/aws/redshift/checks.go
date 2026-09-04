package redshift

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// RedshiftClusterMultiAzEnabled - Redshift cluster has Multi-AZ enabled
type RedshiftClusterMultiAzEnabled struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterMultiAzEnabled() *RedshiftClusterMultiAzEnabled {
    return &RedshiftClusterMultiAzEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_multi_az_enabled",
            CheckTitle: "Redshift cluster has Multi-AZ enabled",
            ServiceName: "redshift",
            Severity: "medium",
            Description: "**Amazon Redshift clusters** are evaluated for **Multi-AZ deployment** on provisioned `RA3` clusters, confirming compute spans two Availability Zones and is served via a single endpoint.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterMultiAzEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterNonDefaultDatabaseName - Redshift cluster does not use the default database name dev
type RedshiftClusterNonDefaultDatabaseName struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterNonDefaultDatabaseName() *RedshiftClusterNonDefaultDatabaseName {
    return &RedshiftClusterNonDefaultDatabaseName{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_non_default_database_name",
            CheckTitle: "Redshift cluster does not use the default database name dev",
            ServiceName: "redshift",
            Severity: "low",
            Description: "**Amazon Redshift clusters** are identified when the database name equals the default `dev`, rather than a custom name.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterNonDefaultDatabaseName) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterNonDefaultDatabaseName) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterEncryptedAtRest - Redshift cluster is encrypted at rest
type RedshiftClusterEncryptedAtRest struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterEncryptedAtRest() *RedshiftClusterEncryptedAtRest {
    return &RedshiftClusterEncryptedAtRest{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_encrypted_at_rest",
            CheckTitle: "Redshift cluster is encrypted at rest",
            ServiceName: "redshift",
            Severity: "critical",
            Description: "**Amazon Redshift clusters** use **encryption at rest**. The evaluation inspects the cluster's encryption setting to determine if on-disk data and snapshots are protected with a managed key.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterEncryptedAtRest) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterNonDefaultUsername - Amazon Redshift cluster does not use the default admin username
type RedshiftClusterNonDefaultUsername struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterNonDefaultUsername() *RedshiftClusterNonDefaultUsername {
    return &RedshiftClusterNonDefaultUsername{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_non_default_username",
            CheckTitle: "Amazon Redshift cluster does not use the default admin username",
            ServiceName: "redshift",
            Severity: "medium",
            Description: "**Amazon Redshift clusters** are assessed for use of a **non-default admin username**; clusters using the known default `awsuser` are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterNonDefaultUsername) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterNonDefaultUsername) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterEnhancedVpcRouting - Redshift cluster has Enhanced VPC Routing enabled
type RedshiftClusterEnhancedVpcRouting struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterEnhancedVpcRouting() *RedshiftClusterEnhancedVpcRouting {
    return &RedshiftClusterEnhancedVpcRouting{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_enhanced_vpc_routing",
            CheckTitle: "Redshift cluster has Enhanced VPC Routing enabled",
            ServiceName: "redshift",
            Severity: "medium",
            Description: "**Amazon Redshift clusters** are assessed for the `EnhancedVpcRouting` setting, which routes all `COPY` and `UNLOAD` traffic between the cluster and data repositories through the VPC, enabling use of VPC security controls and logging.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterEnhancedVpcRouting) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterEnhancedVpcRouting) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterInTransitEncryptionEnabled - Redshift cluster is encrypted in transit
type RedshiftClusterInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterInTransitEncryptionEnabled() *RedshiftClusterInTransitEncryptionEnabled {
    return &RedshiftClusterInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_in_transit_encryption_enabled",
            CheckTitle: "Redshift cluster is encrypted in transit",
            ServiceName: "redshift",
            Severity: "high",
            Description: "**Amazon Redshift clusters** enforce **encryption in transit** by requiring **TLS** for client connections when `require_ssl` is enabled.  This evaluation identifies clusters where connections are not forced to use TLS.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterAutomaticUpgrades - Redshift cluster has automatic version upgrade enabled
type RedshiftClusterAutomaticUpgrades struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterAutomaticUpgrades() *RedshiftClusterAutomaticUpgrades {
    return &RedshiftClusterAutomaticUpgrades{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_automatic_upgrades",
            CheckTitle: "Redshift cluster has automatic version upgrade enabled",
            ServiceName: "redshift",
            Severity: "medium",
            Description: "**Amazon Redshift clusters** have automatic major engine upgrades allowed via `AllowVersionUpgrade` so updates are applied during the maintenance window.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterAutomaticUpgrades) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterAutomaticUpgrades) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterAuditLogging - Redshift cluster has audit logging enabled
type RedshiftClusterAuditLogging struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterAuditLogging() *RedshiftClusterAuditLogging {
    return &RedshiftClusterAuditLogging{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_audit_logging",
            CheckTitle: "Redshift cluster has audit logging enabled",
            ServiceName: "redshift",
            Severity: "medium",
            Description: "Amazon Redshift clusters are evaluated for **database audit logging** that exports connection, user, and user-activity events to Amazon S3 or CloudWatch.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterAuditLogging) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterAuditLogging) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterPublicAccess - Redshift cluster is not publicly exposed to the Internet
type RedshiftClusterPublicAccess struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterPublicAccess() *RedshiftClusterPublicAccess {
    return &RedshiftClusterPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_public_access",
            CheckTitle: "Redshift cluster is not publicly exposed to the Internet",
            ServiceName: "redshift",
            Severity: "critical",
            Description: "Amazon Redshift clusters with `publicly accessible` endpoints in **public subnets** and security groups allowing TCP from `0.0.0.0/0` or `::/0` are identified as internet-exposed.  Public endpoints without internet reachability due to private subnets or restrictive rules are recognized separately.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RedshiftClusterAutomatedSnapshot - Redshift cluster has automated snapshots enabled
type RedshiftClusterAutomatedSnapshot struct {
    metadata models.CheckMetadata
}

func NewRedshiftClusterAutomatedSnapshot() *RedshiftClusterAutomatedSnapshot {
    return &RedshiftClusterAutomatedSnapshot{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "redshift_cluster_automated_snapshot",
            CheckTitle: "Redshift cluster has automated snapshots enabled",
            ServiceName: "redshift",
            Severity: "high",
            Description: "**Amazon Redshift clusters** are evaluated for **automated snapshots** being enabled with a retention period `> 0`, confirming that periodic backups are created and retained.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"redshift"},
        },
    }
}

func (c *RedshiftClusterAutomatedSnapshot) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RedshiftClusterAutomatedSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "redshift",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

