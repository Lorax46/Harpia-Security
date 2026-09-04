package dms

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// DmsEndpointSslEnabled - DMS endpoint has SSL enabled
type DmsEndpointSslEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsEndpointSslEnabled() *DmsEndpointSslEnabled {
    return &DmsEndpointSslEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_endpoint_ssl_enabled",
            CheckTitle: "DMS endpoint has SSL enabled",
            ServiceName: "dms",
            Severity: "high",
            Description: "**AWS DMS endpoints** have their SSL/TLS mode inspected; any value other than `none` denotes encrypted connections between the replication instance and databases.  Supported modes include `require`, `verify-ca`, and `verify-full`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsEndpointSslEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsEndpointSslEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsEndpointNeptuneIamAuthorizationEnabled - DMS endpoint for Neptune has IAM authorization enabled
type DmsEndpointNeptuneIamAuthorizationEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsEndpointNeptuneIamAuthorizationEnabled() *DmsEndpointNeptuneIamAuthorizationEnabled {
    return &DmsEndpointNeptuneIamAuthorizationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_endpoint_neptune_iam_authorization_enabled",
            CheckTitle: "DMS endpoint for Neptune has IAM authorization enabled",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**DMS Neptune endpoints** have **IAM authorization** enabled via the endpoint setting `IamAuthEnabled`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsEndpointNeptuneIamAuthorizationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsEndpointNeptuneIamAuthorizationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsReplicationTaskTargetLoggingEnabled - DMS replication task has TARGET_APPLY and TARGET_LOAD logging enabled with at least default severity
type DmsReplicationTaskTargetLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsReplicationTaskTargetLoggingEnabled() *DmsReplicationTaskTargetLoggingEnabled {
    return &DmsReplicationTaskTargetLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_replication_task_target_logging_enabled",
            CheckTitle: "DMS replication task has TARGET_APPLY and TARGET_LOAD logging enabled with at least default severity",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**AWS DMS replication tasks** have target logging enabled, including `TARGET_APPLY` and `TARGET_LOAD`, each set to at least `LOGGER_SEVERITY_DEFAULT`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsReplicationTaskTargetLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsReplicationTaskTargetLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsInstanceMinorVersionUpgradeEnabled - DMS replication instance has auto minor version upgrade enabled
type DmsInstanceMinorVersionUpgradeEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsInstanceMinorVersionUpgradeEnabled() *DmsInstanceMinorVersionUpgradeEnabled {
    return &DmsInstanceMinorVersionUpgradeEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_instance_minor_version_upgrade_enabled",
            CheckTitle: "DMS replication instance has auto minor version upgrade enabled",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**AWS DMS replication instances** are evaluated for the `auto_minor_version_upgrade` setting to confirm **automatic minor engine updates** are enabled during the maintenance window.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsInstanceMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsInstanceMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsEndpointMongodbAuthenticationEnabled - DMS MongoDB endpoint has an authentication mechanism enabled
type DmsEndpointMongodbAuthenticationEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsEndpointMongodbAuthenticationEnabled() *DmsEndpointMongodbAuthenticationEnabled {
    return &DmsEndpointMongodbAuthenticationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_endpoint_mongodb_authentication_enabled",
            CheckTitle: "DMS MongoDB endpoint has an authentication mechanism enabled",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**AWS DMS MongoDB endpoints** use an authentication mechanism. Configuration expects `AuthType` not `no` (e.g., `password`) with an `authMechanism` such as `scram_sha_1` or `mongodb_cr`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsEndpointMongodbAuthenticationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsEndpointMongodbAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsInstanceMultiAzEnabled - DMS replication instance has Multi-AZ enabled
type DmsInstanceMultiAzEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsInstanceMultiAzEnabled() *DmsInstanceMultiAzEnabled {
    return &DmsInstanceMultiAzEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_instance_multi_az_enabled",
            CheckTitle: "DMS replication instance has Multi-AZ enabled",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**AWS DMS replication instances** are evaluated for **Multi-AZ** configuration. Instances with `multi_az` enabled are treated as having a cross-AZ standby; those without it are identified as single-AZ.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsInstanceMultiAzEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsInstanceMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsReplicationTaskSourceLoggingEnabled - DMS replication task has logging enabled and SOURCE_CAPTURE and SOURCE_UNLOAD components set to at least Default severity
type DmsReplicationTaskSourceLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsReplicationTaskSourceLoggingEnabled() *DmsReplicationTaskSourceLoggingEnabled {
    return &DmsReplicationTaskSourceLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_replication_task_source_logging_enabled",
            CheckTitle: "DMS replication task has logging enabled and SOURCE_CAPTURE and SOURCE_UNLOAD components set to at least Default severity",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**AWS DMS replication tasks** have **logging enabled** and configure `SOURCE_CAPTURE` and `SOURCE_UNLOAD` with severity at least `LOGGER_SEVERITY_DEFAULT` (or higher: `LOGGER_SEVERITY_DEBUG`, `LOGGER_SEVERITY_DETAILED_DEBUG`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsReplicationTaskSourceLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsReplicationTaskSourceLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsEndpointRedisInTransitEncryptionEnabled - DMS endpoint for Redis OSS is encrypted in transit
type DmsEndpointRedisInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewDmsEndpointRedisInTransitEncryptionEnabled() *DmsEndpointRedisInTransitEncryptionEnabled {
    return &DmsEndpointRedisInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_endpoint_redis_in_transit_encryption_enabled",
            CheckTitle: "DMS endpoint for Redis OSS is encrypted in transit",
            ServiceName: "dms",
            Severity: "medium",
            Description: "**DMS Redis OSS endpoints** are assessed for the presence of **TLS** in their endpoint settings, such as `ssl-encryption`, indicating encrypted connections between the DMS replication instance and Redis.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsEndpointRedisInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsEndpointRedisInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DmsInstanceNoPublicAccess - DMS replication instance is not publicly exposed to the Internet
type DmsInstanceNoPublicAccess struct {
    metadata models.CheckMetadata
}

func NewDmsInstanceNoPublicAccess() *DmsInstanceNoPublicAccess {
    return &DmsInstanceNoPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dms_instance_no_public_access",
            CheckTitle: "DMS replication instance is not publicly exposed to the Internet",
            ServiceName: "dms",
            Severity: "critical",
            Description: "**AWS DMS replication instances** are evaluated for **public exposure**. Exposure is identified when `PubliclyAccessible` is enabled and an attached security group allows inbound traffic from any address. Private or allowlisted instances are not considered exposed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dms"},
        },
    }
}

func (c *DmsInstanceNoPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DmsInstanceNoPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

