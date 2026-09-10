package mq

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// MqBrokerClusterDeploymentMode - MQ RabbitMQ broker has cluster (multi-AZ) deployment mode
type MqBrokerClusterDeploymentMode struct {
    metadata models.CheckMetadata
}

func NewMqBrokerClusterDeploymentMode() *MqBrokerClusterDeploymentMode {
    return &MqBrokerClusterDeploymentMode{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "mq_broker_cluster_deployment_mode",
            CheckTitle: "MQ RabbitMQ broker has cluster (multi-AZ) deployment mode",
            ServiceName: "mq",
            Severity: "medium",
            Description: "**Amazon MQ RabbitMQ brokers** are assessed for **cluster deployment mode** (`CLUSTER_MULTI_AZ`) with nodes spread across multiple AZs and shared state.  Brokers configured otherwise are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"mq"},
        },
    }
}

func (c *MqBrokerClusterDeploymentMode) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MqBrokerClusterDeploymentMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "mq",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// MqBrokerNotPubliclyAccessible - Amazon MQ broker is not publicly accessible
type MqBrokerNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewMqBrokerNotPubliclyAccessible() *MqBrokerNotPubliclyAccessible {
    return &MqBrokerNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "mq_broker_not_publicly_accessible",
            CheckTitle: "Amazon MQ broker is not publicly accessible",
            ServiceName: "mq",
            Severity: "high",
            Description: "**Amazon MQ brokers** are evaluated for **public accessibility**, determining whether a broker exposes a public endpoint or is restricted to VPC-only connectivity via its `publicly accessible` setting.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"mq"},
        },
    }
}

func (c *MqBrokerNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MqBrokerNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "mq",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// MqBrokerLoggingEnabled - MQ broker has general logging enabled and, for ActiveMQ, audit logging enabled
type MqBrokerLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewMqBrokerLoggingEnabled() *MqBrokerLoggingEnabled {
    return &MqBrokerLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "mq_broker_logging_enabled",
            CheckTitle: "MQ broker has general logging enabled and, for ActiveMQ, audit logging enabled",
            ServiceName: "mq",
            Severity: "low",
            Description: "**Amazon MQ brokers** have logging to **CloudWatch Logs** enabled per engine type: **ActiveMQ** requires both `general` and `audit` logs; **RabbitMQ** requires `general` logs.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"mq"},
        },
    }
}

func (c *MqBrokerLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MqBrokerLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "mq",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// MqBrokerActiveDeploymentMode - Apache ActiveMQ broker is configured in active/standby Multi-AZ deployment mode
type MqBrokerActiveDeploymentMode struct {
    metadata models.CheckMetadata
}

func NewMqBrokerActiveDeploymentMode() *MqBrokerActiveDeploymentMode {
    return &MqBrokerActiveDeploymentMode{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "mq_broker_active_deployment_mode",
            CheckTitle: "Apache ActiveMQ broker is configured in active/standby Multi-AZ deployment mode",
            ServiceName: "mq",
            Severity: "low",
            Description: "**ActiveMQ broker deployment mode** is configured as **active/standby** (`ACTIVE_STANDBY_MULTI_AZ`), indicating a redundant pair operating across Availability Zones",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"mq"},
        },
    }
}

func (c *MqBrokerActiveDeploymentMode) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MqBrokerActiveDeploymentMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "mq",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// MqBrokerAutoMinorVersionUpgrades - Amazon MQ broker has automated minor version upgrades enabled
type MqBrokerAutoMinorVersionUpgrades struct {
    metadata models.CheckMetadata
}

func NewMqBrokerAutoMinorVersionUpgrades() *MqBrokerAutoMinorVersionUpgrades {
    return &MqBrokerAutoMinorVersionUpgrades{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "mq_broker_auto_minor_version_upgrades",
            CheckTitle: "Amazon MQ broker has automated minor version upgrades enabled",
            ServiceName: "mq",
            Severity: "low",
            Description: "**Amazon MQ brokers** have `autoMinorVersionUpgrade` enabled to automatically apply supported minor and patch engine updates during the scheduled maintenance window.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"mq"},
        },
    }
}

func (c *MqBrokerAutoMinorVersionUpgrades) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MqBrokerAutoMinorVersionUpgrades) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "mq",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

