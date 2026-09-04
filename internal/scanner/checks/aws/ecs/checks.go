package ecs

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// EcsTaskDefinitionsHostNetworkingModeUsers - Amazon ECS task definition does not use host network mode, or non-privileged containers specify a non-root user
type EcsTaskDefinitionsHostNetworkingModeUsers struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsHostNetworkingModeUsers() *EcsTaskDefinitionsHostNetworkingModeUsers {
    return &EcsTaskDefinitionsHostNetworkingModeUsers{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_host_networking_mode_users",
            CheckTitle: "Amazon ECS task definition does not use host network mode, or non-privileged containers specify a non-root user",
            ServiceName: "ecs",
            Severity: "high",
            Description: "**Amazon ECS task definitions** in `host` network mode are assessed for containers where `privileged=false` and the container `user` is `root` or unset.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsHostNetworkingModeUsers) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsHostNetworkingModeUsers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsServiceNoAssignPublicIp - ECS service does not have automatic public IP assignment
type EcsServiceNoAssignPublicIp struct {
    metadata models.CheckMetadata
}

func NewEcsServiceNoAssignPublicIp() *EcsServiceNoAssignPublicIp {
    return &EcsServiceNoAssignPublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_service_no_assign_public_ip",
            CheckTitle: "ECS service does not have automatic public IP assignment",
            ServiceName: "ecs",
            Severity: "high",
            Description: "**ECS services** are assessed for automatic public IP assignment via the `assignPublicIp` setting in their network configuration.  The finding indicates whether tasks launched by the service receive a public IP or are limited to private addressing.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsServiceNoAssignPublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsServiceNoAssignPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskDefinitionsHostNamespaceNotShared - ECS task definition does not share the host's process namespace with its containers
type EcsTaskDefinitionsHostNamespaceNotShared struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsHostNamespaceNotShared() *EcsTaskDefinitionsHostNamespaceNotShared {
    return &EcsTaskDefinitionsHostNamespaceNotShared{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_host_namespace_not_shared",
            CheckTitle: "ECS task definition does not share the host's process namespace with its containers",
            ServiceName: "ecs",
            Severity: "high",
            Description: "**ECS task definitions** where `pidMode` is `host` are configured to share the host's **process namespace** with containers, rather than using isolated task or private namespaces.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsHostNamespaceNotShared) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsHostNamespaceNotShared) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsServiceFargateLatestPlatformVersion - ECS Fargate service uses the latest Fargate platform version
type EcsServiceFargateLatestPlatformVersion struct {
    metadata models.CheckMetadata
}

func NewEcsServiceFargateLatestPlatformVersion() *EcsServiceFargateLatestPlatformVersion {
    return &EcsServiceFargateLatestPlatformVersion{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_service_fargate_latest_platform_version",
            CheckTitle: "ECS Fargate service uses the latest Fargate platform version",
            ServiceName: "ecs",
            Severity: "medium",
            Description: "**ECS Fargate services** use the **latest Fargate platform version** via `platformVersion`=`LATEST` or an explicit value matching the current release for their `platformFamily` (Linux/Windows).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsServiceFargateLatestPlatformVersion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsServiceFargateLatestPlatformVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsClusterContainerInsightsEnabled - ECS cluster has Container Insights enabled or enhanced
type EcsClusterContainerInsightsEnabled struct {
    metadata models.CheckMetadata
}

func NewEcsClusterContainerInsightsEnabled() *EcsClusterContainerInsightsEnabled {
    return &EcsClusterContainerInsightsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_cluster_container_insights_enabled",
            CheckTitle: "ECS cluster has Container Insights enabled or enhanced",
            ServiceName: "ecs",
            Severity: "medium",
            Description: "**ECS clusters** have CloudWatch **Container Insights** configured via the `containerInsights` setting, accepting `enabled` or `enhanced` values to emit cluster, service, task, and container telemetry.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsClusterContainerInsightsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsClusterContainerInsightsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskSetNoAssignPublicIp - ECS task set does not automatically assign a public IP address
type EcsTaskSetNoAssignPublicIp struct {
    metadata models.CheckMetadata
}

func NewEcsTaskSetNoAssignPublicIp() *EcsTaskSetNoAssignPublicIp {
    return &EcsTaskSetNoAssignPublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_set_no_assign_public_ip",
            CheckTitle: "ECS task set does not automatically assign a public IP address",
            ServiceName: "ecs",
            Severity: "high",
            Description: "**ECS task sets** are assessed for **automatic public IP assignment** via `AssignPublicIP`. When set to `ENABLED`, tasks are given public addresses in their network configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskSetNoAssignPublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskSetNoAssignPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskDefinitionsLoggingEnabled - ECS task definition has logging configured for all containers
type EcsTaskDefinitionsLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsLoggingEnabled() *EcsTaskDefinitionsLoggingEnabled {
    return &EcsTaskDefinitionsLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_logging_enabled",
            CheckTitle: "ECS task definition has logging configured for all containers",
            ServiceName: "ecs",
            Severity: "high",
            Description: "**Amazon ECS task definition** containers specify a **logging configuration** with a non-null `logDriver` for every container in the latest active revision.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskDefinitionsLoggingBlockMode - ECS task definition has container logging in non-blocking mode
type EcsTaskDefinitionsLoggingBlockMode struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsLoggingBlockMode() *EcsTaskDefinitionsLoggingBlockMode {
    return &EcsTaskDefinitionsLoggingBlockMode{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_logging_block_mode",
            CheckTitle: "ECS task definition has container logging in non-blocking mode",
            ServiceName: "ecs",
            Severity: "low",
            Description: "**ECS task definition containers** use **non-blocking logging mode** via the `logConfiguration.mode` option on the latest active revision",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsLoggingBlockMode) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsLoggingBlockMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskDefinitionsContainersReadonlyAccess - ECS task definition has all containers with read-only root filesystems
type EcsTaskDefinitionsContainersReadonlyAccess struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsContainersReadonlyAccess() *EcsTaskDefinitionsContainersReadonlyAccess {
    return &EcsTaskDefinitionsContainersReadonlyAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_containers_readonly_access",
            CheckTitle: "ECS task definition has all containers with read-only root filesystems",
            ServiceName: "ecs",
            Severity: "high",
            Description: "Amazon ECS task definitions specify whether container root filesystems are **read-only** via `readonlyRootFilesystem`. Containers where this setting is absent or set to `false` effectively have write access to the root filesystem.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsContainersReadonlyAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsContainersReadonlyAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskDefinitionsNoPrivilegedContainers - ECS task definition has no privileged containers
type EcsTaskDefinitionsNoPrivilegedContainers struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsNoPrivilegedContainers() *EcsTaskDefinitionsNoPrivilegedContainers {
    return &EcsTaskDefinitionsNoPrivilegedContainers{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_no_privileged_containers",
            CheckTitle: "ECS task definition has no privileged containers",
            ServiceName: "ecs",
            Severity: "high",
            Description: "**Amazon ECS task definitions** are evaluated for containers configured with **privileged mode** (`privileged: true`).  The outcome indicates whether any container definition enables this setting.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsNoPrivilegedContainers) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsNoPrivilegedContainers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcsTaskDefinitionsNoEnvironmentSecrets - ECS task definition has no secrets in environment variables
type EcsTaskDefinitionsNoEnvironmentSecrets struct {
    metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsNoEnvironmentSecrets() *EcsTaskDefinitionsNoEnvironmentSecrets {
    return &EcsTaskDefinitionsNoEnvironmentSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecs_task_definitions_no_environment_secrets",
            CheckTitle: "ECS task definition has no secrets in environment variables",
            ServiceName: "ecs",
            Severity: "critical",
            Description: "**ECS task definitions** are analyzed for **plaintext secrets** placed in container `environment` variables. It identifies values that resemble credentials (keys, tokens, passwords) within container definitions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecs"},
        },
    }
}

func (c *EcsTaskDefinitionsNoEnvironmentSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcsTaskDefinitionsNoEnvironmentSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

