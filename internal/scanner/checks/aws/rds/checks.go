package rds

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// RdsInstanceCertificateExpiration - RDS instance SSL/TLS certificate has more than 3 months of validity remaining
type RdsInstanceCertificateExpiration struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceCertificateExpiration() *RdsInstanceCertificateExpiration {
    return &RdsInstanceCertificateExpiration{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_certificate_expiration",
            CheckTitle: "RDS instance SSL/TLS certificate has more than 3 months of validity remaining",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB instances** are evaluated for **server certificate validity** windows, including default and **customer-managed certificates**. Certificates **expired** or **approaching expiration** (e.g., `<1 month`, `<3 months`, `3-6 months`, `>6 months`) are identified using the certificate `valid_till` date.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceCertificateExpiration) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceCertificateExpiration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceDeletionProtection - RDS instance has deletion protection enabled
type RdsInstanceDeletionProtection struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceDeletionProtection() *RdsInstanceDeletionProtection {
    return &RdsInstanceDeletionProtection{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_deletion_protection",
            CheckTitle: "RDS instance has deletion protection enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are assessed for **deletion protection**. If an instance belongs to an Aurora cluster, the setting is evaluated at the cluster level; otherwise, it is evaluated on the instance itself.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceDeletionProtection) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterCriticalEventSubscription - RDS cluster event subscription is enabled for maintenance and failure categories
type RdsClusterCriticalEventSubscription struct {
    metadata models.CheckMetadata
}

func NewRdsClusterCriticalEventSubscription() *RdsClusterCriticalEventSubscription {
    return &RdsClusterCriticalEventSubscription{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_critical_event_subscription",
            CheckTitle: "RDS cluster event subscription is enabled for maintenance and failure categories",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS event subscriptions** for the `db-cluster` source type are enabled and cover critical cluster event categories: **`maintenance`** and **`failure`** (or all cluster events).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterCriticalEventSubscription) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterCriticalEventSubscription) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterCopyTagsToSnapshots - RDS DB cluster has copy tags to snapshots enabled
type RdsClusterCopyTagsToSnapshots struct {
    metadata models.CheckMetadata
}

func NewRdsClusterCopyTagsToSnapshots() *RdsClusterCopyTagsToSnapshots {
    return &RdsClusterCopyTagsToSnapshots{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_copy_tags_to_snapshots",
            CheckTitle: "RDS DB cluster has copy tags to snapshots enabled",
            ServiceName: "rds",
            Severity: "low",
            Description: "**RDS DB clusters** are evaluated for the `CopyTagsToSnapshot` setting that propagates cluster tags to their DB snapshots.  *Aurora tagging is configured at the cluster level; instance-level copying isn't supported.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterCopyTagsToSnapshots) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceDeprecatedEngineVersion - RDS instance uses a supported engine version
type RdsInstanceDeprecatedEngineVersion struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceDeprecatedEngineVersion() *RdsInstanceDeprecatedEngineVersion {
    return &RdsInstanceDeprecatedEngineVersion{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_deprecated_engine_version",
            CheckTitle: "RDS instance uses a supported engine version",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB instances** use a **supported, non-deprecated engine version** for MariaDB, MySQL, or PostgreSQL. The instance's `engine` and `engine_version` are evaluated against versions currently supported in the region.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceDeprecatedEngineVersion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceDeprecatedEngineVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceInsideVpc - RDS instance is deployed in a VPC
type RdsInstanceInsideVpc struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceInsideVpc() *RdsInstanceInsideVpc {
    return &RdsInstanceInsideVpc{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_inside_vpc",
            CheckTitle: "RDS instance is deployed in a VPC",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB instances** are assessed for **VPC placement** by the presence of a `vpc_id` indicating deployment within a VPC.  Instances without this association are treated as outside VPC networking.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceInsideVpc) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceInsideVpc) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterDefaultAdmin - RDS cluster master username is not admin or postgres
type RdsClusterDefaultAdmin struct {
    metadata models.CheckMetadata
}

func NewRdsClusterDefaultAdmin() *RdsClusterDefaultAdmin {
    return &RdsClusterDefaultAdmin{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_default_admin",
            CheckTitle: "RDS cluster master username is not admin or postgres",
            ServiceName: "rds",
            Severity: "medium",
            Description: "RDS DB clusters are evaluated for use of a **custom administrator username**, flagging clusters that use defaults such as `admin` or `postgres`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterDefaultAdmin) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterDefaultAdmin) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceEnhancedMonitoringEnabled - RDS instance has enhanced monitoring enabled
type RdsInstanceEnhancedMonitoringEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceEnhancedMonitoringEnabled() *RdsInstanceEnhancedMonitoringEnabled {
    return &RdsInstanceEnhancedMonitoringEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_enhanced_monitoring_enabled",
            CheckTitle: "RDS instance has enhanced monitoring enabled",
            ServiceName: "rds",
            Severity: "low",
            Description: "**RDS DB instances** are evaluated for **Enhanced Monitoring** being enabled, which publishes real-time **OS-level metrics** (CPU, memory, disk, network) to CloudWatch Logs for each instance.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceEnhancedMonitoringEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceEnhancedMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceIamAuthenticationEnabled - RDS instance has IAM database authentication enabled
type RdsInstanceIamAuthenticationEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceIamAuthenticationEnabled() *RdsInstanceIamAuthenticationEnabled {
    return &RdsInstanceIamAuthenticationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_iam_authentication_enabled",
            CheckTitle: "RDS instance has IAM database authentication enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** using MySQL, MariaDB, or PostgreSQL engines (including Aurora variants) have **IAM database authentication** enabled at the instance level or, when part of a cluster, evaluated for cluster-level enablement.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceIamAuthenticationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceEventSubscriptionSecurityGroups - RDS event subscription for DB security groups is enabled for configuration change and failure events
type RdsInstanceEventSubscriptionSecurityGroups struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceEventSubscriptionSecurityGroups() *RdsInstanceEventSubscriptionSecurityGroups {
    return &RdsInstanceEventSubscriptionSecurityGroups{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_event_subscription_security_groups",
            CheckTitle: "RDS event subscription for DB security groups is enabled for configuration change and failure events",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS event subscriptions** are evaluated for **database security group** events. The check expects an enabled subscription with source type `db-security-group` that includes the `configuration change` and `failure` event categories.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceEventSubscriptionSecurityGroups) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceEventSubscriptionSecurityGroups) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceNoPublicAccess - RDS instance is not publicly exposed to the Internet
type RdsInstanceNoPublicAccess struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceNoPublicAccess() *RdsInstanceNoPublicAccess {
    return &RdsInstanceNoPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_no_public_access",
            CheckTitle: "RDS instance is not publicly exposed to the Internet",
            ServiceName: "rds",
            Severity: "critical",
            Description: "**RDS DB instances** are assessed for **internet exposure** using the `PubliclyAccessible` setting, security group ingress to the DB port from any address, and whether subnets are **public**. Instances that combine an internet-facing endpoint, open ingress, and public subnets are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceNoPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceNoPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceCriticalEventSubscription - RDS instance event subscription is enabled for maintenance, configuration change, and failure categories
type RdsInstanceCriticalEventSubscription struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceCriticalEventSubscription() *RdsInstanceCriticalEventSubscription {
    return &RdsInstanceCriticalEventSubscription{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_critical_event_subscription",
            CheckTitle: "RDS instance event subscription is enabled for maintenance, configuration change, and failure categories",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS event subscriptions** for DB instances are assessed for coverage of the critical categories `maintenance`, `configuration change`, and `failure`.  The evaluation looks for enabled `db-instance` subscriptions and confirms these categories are included or that all events are selected.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceCriticalEventSubscription) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceCriticalEventSubscription) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterMultiAz - RDS cluster has Multi-AZ enabled
type RdsClusterMultiAz struct {
    metadata models.CheckMetadata
}

func NewRdsClusterMultiAz() *RdsClusterMultiAz {
    return &RdsClusterMultiAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_multi_az",
            CheckTitle: "RDS cluster has Multi-AZ enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB clusters** are assessed for deployment across **multiple Availability Zones** (*Multi-AZ*), verifying that redundant instances exist to support **automatic failover** instead of a single-AZ configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterMultiAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsSnapshotsPublicAccess - RDS snapshot is not publicly shared
type RdsSnapshotsPublicAccess struct {
    metadata models.CheckMetadata
}

func NewRdsSnapshotsPublicAccess() *RdsSnapshotsPublicAccess {
    return &RdsSnapshotsPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_snapshots_public_access",
            CheckTitle: "RDS snapshot is not publicly shared",
            ServiceName: "rds",
            Severity: "critical",
            Description: "**RDS DB snapshots** and **DB cluster snapshots** with **public visibility** (shared with `all` AWS accounts) are detected.  Snapshots limited to specific accounts or kept private are identified as restricted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsSnapshotsPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsSnapshotsPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterDeletionProtection - RDS cluster has deletion protection enabled
type RdsClusterDeletionProtection struct {
    metadata models.CheckMetadata
}

func NewRdsClusterDeletionProtection() *RdsClusterDeletionProtection {
    return &RdsClusterDeletionProtection{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_deletion_protection",
            CheckTitle: "RDS cluster has deletion protection enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB clusters** have **deletion protection** enabled (`deletion_protection=true`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterDeletionProtection) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterMinorVersionUpgradeEnabled - RDS cluster has automatic minor version upgrades enabled
type RdsClusterMinorVersionUpgradeEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsClusterMinorVersionUpgradeEnabled() *RdsClusterMinorVersionUpgradeEnabled {
    return &RdsClusterMinorVersionUpgradeEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_minor_version_upgrade_enabled",
            CheckTitle: "RDS cluster has automatic minor version upgrades enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS Multi-AZ DB clusters** are configured for **automatic minor engine upgrades** via `auto_minor_version_upgrade`.  The evaluation checks these clusters to see if this setting is enabled so preferred minor releases are applied during the maintenance window.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceEventSubscriptionParameterGroups - RDS DB parameter group event subscription is enabled and subscribes to configuration change events or all categories
type RdsInstanceEventSubscriptionParameterGroups struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceEventSubscriptionParameterGroups() *RdsInstanceEventSubscriptionParameterGroups {
    return &RdsInstanceEventSubscriptionParameterGroups{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_event_subscription_parameter_groups",
            CheckTitle: "RDS DB parameter group event subscription is enabled and subscribes to configuration change events or all categories",
            ServiceName: "rds",
            Severity: "low",
            Description: "**RDS event subscriptions** for **DB parameter groups** notify on `configuration change` events (or all categories) when the subscription is enabled",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceEventSubscriptionParameterGroups) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceEventSubscriptionParameterGroups) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceMultiAz - RDS instance has Multi-AZ enabled
type RdsInstanceMultiAz struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceMultiAz() *RdsInstanceMultiAz {
    return &RdsInstanceMultiAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_multi_az",
            CheckTitle: "RDS instance has Multi-AZ enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are evaluated for **Multi-AZ** configuration, either enabled on the instance or inherited from the associated DB cluster.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceMultiAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceIntegrationCloudwatchLogs - RDS instance exports logs to CloudWatch Logs
type RdsInstanceIntegrationCloudwatchLogs struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceIntegrationCloudwatchLogs() *RdsInstanceIntegrationCloudwatchLogs {
    return &RdsInstanceIntegrationCloudwatchLogs{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_integration_cloudwatch_logs",
            CheckTitle: "RDS instance exports logs to CloudWatch Logs",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are configured to **publish database logs** to **CloudWatch Logs** (e.g., `error`, `general`, `slowquery`, `audit`).  The evaluation identifies instances that have log exports enabled to a CloudWatch log group.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceIntegrationCloudwatchLogs) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceBackupEnabled - RDS instance has backup retention period greater than 0 days
type RdsInstanceBackupEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceBackupEnabled() *RdsInstanceBackupEnabled {
    return &RdsInstanceBackupEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_backup_enabled",
            CheckTitle: "RDS instance has backup retention period greater than 0 days",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are evaluated for **automated backups** by confirming the backup retention period is greater than `0` days, indicating point-in-time recovery is configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceBackupEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceDefaultAdmin - RDS instance does not use the default master username (admin or postgres)
type RdsInstanceDefaultAdmin struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceDefaultAdmin() *RdsInstanceDefaultAdmin {
    return &RdsInstanceDefaultAdmin{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_default_admin",
            CheckTitle: "RDS instance does not use the default master username (admin or postgres)",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are evaluated for use of a **custom administrator username**. The finding identifies instances or clusters where the admin user matches common defaults like `admin` or `postgres` (checked at the instance or cluster level).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceDefaultAdmin) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceDefaultAdmin) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceExtendedSupport - RDS instance is not enrolled in RDS Extended Support
type RdsInstanceExtendedSupport struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceExtendedSupport() *RdsInstanceExtendedSupport {
    return &RdsInstanceExtendedSupport{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_extended_support",
            CheckTitle: "RDS instance is not enrolled in RDS Extended Support",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are evaluated for enrollment in Amazon RDS Extended Support. The check fails if `EngineLifecycleSupportis` set to `open-source-rds-extended-support`, indicating the instance will incur additional charges after standard support ends.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceExtendedSupport) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceExtendedSupport) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsSnapshotsEncrypted - RDS DB instance snapshot or DB cluster snapshot is encrypted
type RdsSnapshotsEncrypted struct {
    metadata models.CheckMetadata
}

func NewRdsSnapshotsEncrypted() *RdsSnapshotsEncrypted {
    return &RdsSnapshotsEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_snapshots_encrypted",
            CheckTitle: "RDS DB instance snapshot or DB cluster snapshot is encrypted",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB snapshots** and **DB cluster snapshots** are evaluated for **encryption at rest**, identifying snapshots created with a KMS key versus unencrypted ones.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsSnapshotsEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsSnapshotsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceTransportEncrypted - RDS instance or cluster enforces SSL/TLS encryption for client connections
type RdsInstanceTransportEncrypted struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceTransportEncrypted() *RdsInstanceTransportEncrypted {
    return &RdsInstanceTransportEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_transport_encrypted",
            CheckTitle: "RDS instance or cluster enforces SSL/TLS encryption for client connections",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB instances** and **DB clusters** enforce **SSL/TLS** for client connections via parameter groups. The check looks for `rds.force_ssl=1` (PostgreSQL, SQL Server) or `require_secure_transport` enabled (MySQL-family) and identifies databases where encryption enforcement isn't active.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceTransportEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceTransportEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceNonDefaultPort - RDS instance uses a non-default port for its engine
type RdsInstanceNonDefaultPort struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceNonDefaultPort() *RdsInstanceNonDefaultPort {
    return &RdsInstanceNonDefaultPort{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_non_default_port",
            CheckTitle: "RDS instance uses a non-default port for its engine",
            ServiceName: "rds",
            Severity: "low",
            Description: "**RDS DB instances** are evaluated for use of a port that differs from the engine's default. Matching an engine with its default port-`3306` (MySQL/MariaDB/Aurora MySQL), `5432` (PostgreSQL/Aurora), `1521` (Oracle), `1433` (SQL Server), `50000` (Db2)-indicates the instance uses the default listener.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceNonDefaultPort) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceNonDefaultPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceCopyTagsToSnapshots - RDS DB instance has copy tags to snapshots enabled
type RdsInstanceCopyTagsToSnapshots struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceCopyTagsToSnapshots() *RdsInstanceCopyTagsToSnapshots {
    return &RdsInstanceCopyTagsToSnapshots{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_copy_tags_to_snapshots",
            CheckTitle: "RDS DB instance has copy tags to snapshots enabled",
            ServiceName: "rds",
            Severity: "low",
            Description: "**RDS DB instances** are assessed for propagating instance tags to their **DB snapshots** using `CopyTagsToSnapshot`.  *Aurora engines manage this at the cluster level and aren't evaluated per instance.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceCopyTagsToSnapshots) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterIntegrationCloudwatchLogs - RDS cluster has CloudWatch Logs export enabled
type RdsClusterIntegrationCloudwatchLogs struct {
    metadata models.CheckMetadata
}

func NewRdsClusterIntegrationCloudwatchLogs() *RdsClusterIntegrationCloudwatchLogs {
    return &RdsClusterIntegrationCloudwatchLogs{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_integration_cloudwatch_logs",
            CheckTitle: "RDS cluster has CloudWatch Logs export enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS clusters** running Aurora MySQL, Aurora PostgreSQL, MySQL, or PostgreSQL are assessed for **CloudWatch Logs publishing**, confirming that database logs are exported to a CloudWatch Logs group.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterIntegrationCloudwatchLogs) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceStorageEncrypted - RDS DB instance storage is encrypted at rest
type RdsInstanceStorageEncrypted struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceStorageEncrypted() *RdsInstanceStorageEncrypted {
    return &RdsInstanceStorageEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_storage_encrypted",
            CheckTitle: "RDS DB instance storage is encrypted at rest",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB instances** are assessed for **KMS-based encryption at rest** (`StorageEncrypted=true`), covering instance storage and derived artifacts such as snapshots, automated backups, and read replicas.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceStorageEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceProtectedByBackupPlan - RDS instance is protected by an AWS Backup plan
type RdsInstanceProtectedByBackupPlan struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceProtectedByBackupPlan() *RdsInstanceProtectedByBackupPlan {
    return &RdsInstanceProtectedByBackupPlan{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_protected_by_backup_plan",
            CheckTitle: "RDS instance is protected by an AWS Backup plan",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB instances** (non-Aurora) are included in an **AWS Backup plan**, indicating scheduled backups and retention are applied to the resource.  *Aurora engines are evaluated separately.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceProtectedByBackupPlan) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterBacktrackEnabled - RDS Aurora MySQL cluster has Backtrack enabled
type RdsClusterBacktrackEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsClusterBacktrackEnabled() *RdsClusterBacktrackEnabled {
    return &RdsClusterBacktrackEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_backtrack_enabled",
            CheckTitle: "RDS Aurora MySQL cluster has Backtrack enabled",
            ServiceName: "rds",
            Severity: "low",
            Description: "**Aurora MySQL DB clusters** have **Backtrack** configured with a non-zero `BacktrackWindow`, retaining change records to allow rewinding to a consistent earlier time. *Applies to `aurora-mysql` engines only.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterBacktrackEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterBacktrackEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterProtectedByBackupPlan - RDS cluster is protected by an AWS Backup plan
type RdsClusterProtectedByBackupPlan struct {
    metadata models.CheckMetadata
}

func NewRdsClusterProtectedByBackupPlan() *RdsClusterProtectedByBackupPlan {
    return &RdsClusterProtectedByBackupPlan{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_protected_by_backup_plan",
            CheckTitle: "RDS cluster is protected by an AWS Backup plan",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB clusters** are covered by an **AWS Backup backup plan** when resource assignments include the cluster, either explicitly, by tags, or via an appropriate resource scope.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterProtectedByBackupPlan) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterNonDefaultPort - RDS cluster uses a non-default port for its database engine
type RdsClusterNonDefaultPort struct {
    metadata models.CheckMetadata
}

func NewRdsClusterNonDefaultPort() *RdsClusterNonDefaultPort {
    return &RdsClusterNonDefaultPort{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_non_default_port",
            CheckTitle: "RDS cluster uses a non-default port for its database engine",
            ServiceName: "rds",
            Severity: "low",
            Description: "**RDS DB clusters** are assessed for use of a **non-default database port**.  Evaluation focuses on whether the cluster listens on the engine's well-known default port (e.g., `3306`, `5432`, `1433`, `1521`, `50000`) or on a custom port.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterNonDefaultPort) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterNonDefaultPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsInstanceMinorVersionUpgradeEnabled - RDS instance has minor version upgrade enabled
type RdsInstanceMinorVersionUpgradeEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsInstanceMinorVersionUpgradeEnabled() *RdsInstanceMinorVersionUpgradeEnabled {
    return &RdsInstanceMinorVersionUpgradeEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_instance_minor_version_upgrade_enabled",
            CheckTitle: "RDS instance has minor version upgrade enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB instances** are evaluated for the `auto_minor_version_upgrade` setting that enables **automatic minor engine updates** during maintenance windows.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsInstanceMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsInstanceMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterStorageEncrypted - RDS cluster storage is encrypted
type RdsClusterStorageEncrypted struct {
    metadata models.CheckMetadata
}

func NewRdsClusterStorageEncrypted() *RdsClusterStorageEncrypted {
    return &RdsClusterStorageEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_storage_encrypted",
            CheckTitle: "RDS cluster storage is encrypted",
            ServiceName: "rds",
            Severity: "high",
            Description: "**RDS DB clusters** are assessed for **encryption at rest** via AWS KMS. It determines whether cluster storage-and related artifacts like automated backups and snapshots-are encrypted with a KMS key.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterStorageEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// RdsClusterIamAuthenticationEnabled - RDS cluster has IAM authentication enabled
type RdsClusterIamAuthenticationEnabled struct {
    metadata models.CheckMetadata
}

func NewRdsClusterIamAuthenticationEnabled() *RdsClusterIamAuthenticationEnabled {
    return &RdsClusterIamAuthenticationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "rds_cluster_iam_authentication_enabled",
            CheckTitle: "RDS cluster has IAM authentication enabled",
            ServiceName: "rds",
            Severity: "medium",
            Description: "**RDS DB clusters** on supported engines (MySQL/MariaDB/PostgreSQL/Aurora) have **IAM database authentication** enabled for database logins, indicating token-based access managed by IAM instead of static passwords.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"rds"},
        },
    }
}

func (c *RdsClusterIamAuthenticationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *RdsClusterIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "rds",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

