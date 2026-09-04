package kafka

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// KafkaClusterIsPublic - Kafka cluster is not publicly accessible
type KafkaClusterIsPublic struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterIsPublic() *KafkaClusterIsPublic {
    return &KafkaClusterIsPublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_is_public",
            CheckTitle: "Kafka cluster is not publicly accessible",
            ServiceName: "kafka",
            Severity: "critical",
            Description: "**Amazon MSK clusters** with broker endpoints **exposed to the public Internet**.  Serverless clusters are private by default; provisioned clusters are evaluated for their `public access` configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterIsPublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterIsPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaConnectorInTransitEncryptionEnabled - MSK Connect connector has encryption in transit enabled
type KafkaConnectorInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewKafkaConnectorInTransitEncryptionEnabled() *KafkaConnectorInTransitEncryptionEnabled {
    return &KafkaConnectorInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_connector_in_transit_encryption_enabled",
            CheckTitle: "MSK Connect connector has encryption in transit enabled",
            ServiceName: "kafka",
            Severity: "high",
            Description: "**MSK Connect connectors** are evaluated for **in-transit encryption** using `TLS` on client connections to Kafka brokers and connected systems.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaConnectorInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaConnectorInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaClusterUsesLatestVersion - MSK cluster uses the latest Kafka version or is serverless with AWS-managed version
type KafkaClusterUsesLatestVersion struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterUsesLatestVersion() *KafkaClusterUsesLatestVersion {
    return &KafkaClusterUsesLatestVersion{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_uses_latest_version",
            CheckTitle: "MSK cluster uses the latest Kafka version or is serverless with AWS-managed version",
            ServiceName: "kafka",
            Severity: "medium",
            Description: "**Amazon MSK clusters** are evaluated for use of the latest supported **Apache Kafka version**. Provisioned clusters are compared to the most recent release, while **serverless clusters** are treated as automatically managed for versioning.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterUsesLatestVersion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterUsesLatestVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaClusterInTransitEncryptionEnabled - Kafka cluster has encryption in transit enabled
type KafkaClusterInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterInTransitEncryptionEnabled() *KafkaClusterInTransitEncryptionEnabled {
    return &KafkaClusterInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_in_transit_encryption_enabled",
            CheckTitle: "Kafka cluster has encryption in transit enabled",
            ServiceName: "kafka",
            Severity: "high",
            Description: "**Amazon MSK clusters** are evaluated for **encryption in transit** on both paths: **clientbroker** set to `TLS` only and **inter-broker** encryption enabled. *Serverless clusters provide this by default*.  The finding highlights clusters where client-broker traffic isn't `TLS`-only or inter-broker encryption is turned off.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaClusterEnhancedMonitoringEnabled - Amazon MSK cluster has enhanced monitoring enabled
type KafkaClusterEnhancedMonitoringEnabled struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterEnhancedMonitoringEnabled() *KafkaClusterEnhancedMonitoringEnabled {
    return &KafkaClusterEnhancedMonitoringEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_enhanced_monitoring_enabled",
            CheckTitle: "Amazon MSK cluster has enhanced monitoring enabled",
            ServiceName: "kafka",
            Severity: "medium",
            Description: "**Amazon MSK clusters** are assessed for **enhanced monitoring** levels beyond `DEFAULT` (e.g., `PER_BROKER`, `PER_TOPIC_PER_BROKER`, `PER_TOPIC_PER_PARTITION`).  *Serverless clusters* include enhanced monitoring by design; provisioned clusters are evaluated by their configured monitoring level.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterEnhancedMonitoringEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterEnhancedMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaClusterUnrestrictedAccessDisabled - Kafka cluster requires authentication
type KafkaClusterUnrestrictedAccessDisabled struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterUnrestrictedAccessDisabled() *KafkaClusterUnrestrictedAccessDisabled {
    return &KafkaClusterUnrestrictedAccessDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_unrestricted_access_disabled",
            CheckTitle: "Kafka cluster requires authentication",
            ServiceName: "kafka",
            Severity: "critical",
            Description: "Amazon MSK clusters are evaluated for **unauthenticated client access**. Serverless clusters inherently require authentication; provisioned clusters are checked for configurations that allow **unrestricted connections** rather than authenticated clients.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterUnrestrictedAccessDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterUnrestrictedAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaClusterEncryptionAtRestUsesCmk - Kafka cluster has encryption at rest enabled with a customer managed key (CMK) or is serverless
type KafkaClusterEncryptionAtRestUsesCmk struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterEncryptionAtRestUsesCmk() *KafkaClusterEncryptionAtRestUsesCmk {
    return &KafkaClusterEncryptionAtRestUsesCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_encryption_at_rest_uses_cmk",
            CheckTitle: "Kafka cluster has encryption at rest enabled with a customer managed key (CMK) or is serverless",
            ServiceName: "kafka",
            Severity: "medium",
            Description: "Amazon MSK clusters are inspected for **encryption at rest** using a **customer-managed KMS key** for data volumes. Serverless clusters are inherently encrypted. Provisioned clusters are recognized only when the configured `DataVolumeKMSKeyId` corresponds to a customer-managed key.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterEncryptionAtRestUsesCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterEncryptionAtRestUsesCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KafkaClusterMutualTlsAuthenticationEnabled - Kafka cluster has TLS authentication enabled
type KafkaClusterMutualTlsAuthenticationEnabled struct {
    metadata models.CheckMetadata
}

func NewKafkaClusterMutualTlsAuthenticationEnabled() *KafkaClusterMutualTlsAuthenticationEnabled {
    return &KafkaClusterMutualTlsAuthenticationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kafka_cluster_mutual_tls_authentication_enabled",
            CheckTitle: "Kafka cluster has TLS authentication enabled",
            ServiceName: "kafka",
            Severity: "high",
            Description: "Amazon MSK clusters enforce **client authentication** on client-to-broker connections. Serverless clusters use TLS-based authentication by default; provisioned clusters must have **mutual TLS (mTLS)** explicitly enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kafka"},
        },
    }
}

func (c *KafkaClusterMutualTlsAuthenticationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KafkaClusterMutualTlsAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kafka",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

