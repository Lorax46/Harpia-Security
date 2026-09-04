package elasticache

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// ElasticacheRedisReplicationGroupAuthEnabled - ElastiCache Redis replication group with engine version < 6.0 has Redis OSS AUTH enabled
type ElasticacheRedisReplicationGroupAuthEnabled struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisReplicationGroupAuthEnabled() *ElasticacheRedisReplicationGroupAuthEnabled {
    return &ElasticacheRedisReplicationGroupAuthEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_replication_group_auth_enabled",
            CheckTitle: "ElastiCache Redis replication group with engine version < 6.0 has Redis OSS AUTH enabled",
            ServiceName: "elasticache",
            Severity: "medium",
            Description: "Amazon ElastiCache Redis replication groups running versions prior to `6.0` are evaluated for the use of **AUTH tokens**. For `6.0+`, the finding indicates **ACL/RBAC** configuration should be reviewed instead of token-based AUTH.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisReplicationGroupAuthEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisReplicationGroupAuthEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheClusterUsesPublicSubnet - ElastiCache cluster is not using public subnets
type ElasticacheClusterUsesPublicSubnet struct {
    metadata models.CheckMetadata
}

func NewElasticacheClusterUsesPublicSubnet() *ElasticacheClusterUsesPublicSubnet {
    return &ElasticacheClusterUsesPublicSubnet{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_cluster_uses_public_subnet",
            CheckTitle: "ElastiCache cluster is not using public subnets",
            ServiceName: "elasticache",
            Severity: "medium",
            Description: "**ElastiCache resources** (Redis nodes and Memcached clusters) are assessed for placement in **public subnets**.  The finding identifies cache subnet groups that include subnets configured with Internet routing instead of private-only subnets.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheClusterUsesPublicSubnet) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheClusterUsesPublicSubnet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheRedisClusterAutoMinorVersionUpgrades - ElastiCache Redis cache cluster has automatic minor version upgrades enabled
type ElasticacheRedisClusterAutoMinorVersionUpgrades struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisClusterAutoMinorVersionUpgrades() *ElasticacheRedisClusterAutoMinorVersionUpgrades {
    return &ElasticacheRedisClusterAutoMinorVersionUpgrades{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_cluster_auto_minor_version_upgrades",
            CheckTitle: "ElastiCache Redis cache cluster has automatic minor version upgrades enabled",
            ServiceName: "elasticache",
            Severity: "high",
            Description: "**ElastiCache for Redis** replication groups are configured to apply **automatic minor engine upgrades** using `AutoMinorVersionUpgrade`",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisClusterAutoMinorVersionUpgrades) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisClusterAutoMinorVersionUpgrades) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheRedisClusterBackupEnabled - ElastiCache Redis cache cluster has automated snapshot backups enabled with retention of at least 7 days
type ElasticacheRedisClusterBackupEnabled struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisClusterBackupEnabled() *ElasticacheRedisClusterBackupEnabled {
    return &ElasticacheRedisClusterBackupEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_cluster_backup_enabled",
            CheckTitle: "ElastiCache Redis cache cluster has automated snapshot backups enabled with retention of at least 7 days",
            ServiceName: "elasticache",
            Severity: "high",
            Description: "Amazon ElastiCache Redis replication groups have **automated snapshot backups** enabled with a **retention period** of at least `7` days.  The evaluation focuses on whether backups are enabled and the configured retention meets the minimum threshold.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisClusterBackupEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisClusterBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheRedisClusterMultiAzEnabled - ElastiCache Redis replication group has Multi-AZ enabled
type ElasticacheRedisClusterMultiAzEnabled struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisClusterMultiAzEnabled() *ElasticacheRedisClusterMultiAzEnabled {
    return &ElasticacheRedisClusterMultiAzEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_cluster_multi_az_enabled",
            CheckTitle: "ElastiCache Redis replication group has Multi-AZ enabled",
            ServiceName: "elasticache",
            Severity: "medium",
            Description: "**ElastiCache for Redis replication groups** have **Multi-AZ automatic failover** enabled, distributing primary and replicas across distinct Availability Zones",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisClusterMultiAzEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisClusterMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheRedisClusterRestEncryptionEnabled - ElastiCache Redis cache cluster has at rest encryption enabled
type ElasticacheRedisClusterRestEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisClusterRestEncryptionEnabled() *ElasticacheRedisClusterRestEncryptionEnabled {
    return &ElasticacheRedisClusterRestEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_cluster_rest_encryption_enabled",
            CheckTitle: "ElastiCache Redis cache cluster has at rest encryption enabled",
            ServiceName: "elasticache",
            Severity: "medium",
            Description: "**ElastiCache for Redis replication groups** are evaluated for **encryption at rest** of on-disk cache data and backups. The finding pinpoints groups where this protection is not enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisClusterRestEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisClusterRestEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheRedisClusterAutomaticFailoverEnabled - ElastiCache Redis cluster has automatic failover enabled
type ElasticacheRedisClusterAutomaticFailoverEnabled struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisClusterAutomaticFailoverEnabled() *ElasticacheRedisClusterAutomaticFailoverEnabled {
    return &ElasticacheRedisClusterAutomaticFailoverEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_cluster_automatic_failover_enabled",
            CheckTitle: "ElastiCache Redis cluster has automatic failover enabled",
            ServiceName: "elasticache",
            Severity: "medium",
            Description: "**Amazon ElastiCache (Redis OSS) replication groups** have **automatic failover** set to `enabled`, allowing a replica to be promoted when the primary becomes unavailable",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisClusterAutomaticFailoverEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisClusterAutomaticFailoverEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElasticacheRedisClusterInTransitEncryptionEnabled - ElastiCache Redis cache cluster has in-transit encryption enabled
type ElasticacheRedisClusterInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewElasticacheRedisClusterInTransitEncryptionEnabled() *ElasticacheRedisClusterInTransitEncryptionEnabled {
    return &ElasticacheRedisClusterInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elasticache_redis_cluster_in_transit_encryption_enabled",
            CheckTitle: "ElastiCache Redis cache cluster has in-transit encryption enabled",
            ServiceName: "elasticache",
            Severity: "medium",
            Description: "**ElastiCache for Redis** replication groups have **in-transit encryption (TLS)** enabled for client and inter-node traffic (`TransitEncryptionEnabled=true`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elasticache"},
        },
    }
}

func (c *ElasticacheRedisClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElasticacheRedisClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elasticache",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

