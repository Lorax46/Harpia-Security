package autoscaling

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AutoscalingGroupLaunchConfigurationRequiresImdsv2 - Auto Scaling group enforces IMDSv2 or disables the instance metadata service
type AutoscalingGroupLaunchConfigurationRequiresImdsv2 struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupLaunchConfigurationRequiresImdsv2() *AutoscalingGroupLaunchConfigurationRequiresImdsv2 {
    return &AutoscalingGroupLaunchConfigurationRequiresImdsv2{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_launch_configuration_requires_imdsv2",
            CheckTitle: "Auto Scaling group enforces IMDSv2 or disables the instance metadata service",
            ServiceName: "autoscaling",
            Severity: "high",
            Description: "Amazon EC2 Auto Scaling launch configurations are evaluated for **Instance Metadata Service** settings. Instances should have the metadata endpoint `enabled` with `http_tokens=required` (enforcing **IMDSv2**), or have the metadata service `disabled`.  Allowing `http_tokens=optional` or omitting the version leaves legacy access enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupLaunchConfigurationRequiresImdsv2) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupLaunchConfigurationRequiresImdsv2) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingGroupMultipleAz - Auto Scaling group uses multiple Availability Zones
type AutoscalingGroupMultipleAz struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupMultipleAz() *AutoscalingGroupMultipleAz {
    return &AutoscalingGroupMultipleAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_multiple_az",
            CheckTitle: "Auto Scaling group uses multiple Availability Zones",
            ServiceName: "autoscaling",
            Severity: "medium",
            Description: "**EC2 Auto Scaling groups** use **multiple Availability Zones** within a Region, with instances distributed across more than one zone rather than confined to a single zone.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupMultipleAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupMultipleAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingFindSecretsEc2LaunchConfiguration - [DEPRECATED] EC2 Auto Scaling launch configuration user data contains no secrets
type AutoscalingFindSecretsEc2LaunchConfiguration struct {
    metadata models.CheckMetadata
}

func NewAutoscalingFindSecretsEc2LaunchConfiguration() *AutoscalingFindSecretsEc2LaunchConfiguration {
    return &AutoscalingFindSecretsEc2LaunchConfiguration{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_find_secrets_ec2_launch_configuration",
            CheckTitle: "[DEPRECATED] EC2 Auto Scaling launch configuration user data contains no secrets",
            ServiceName: "autoscaling",
            Severity: "critical",
            Description: "[DEPRECATED] EC2 Auto Scaling launch configurations are analyzed for **secrets** embedded in `User Data`, such as passwords, tokens, or API keys in bootstrapping scripts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingFindSecretsEc2LaunchConfiguration) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingFindSecretsEc2LaunchConfiguration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingGroupLaunchConfigurationNoPublicIp - Auto Scaling group associated launch configuration does not assign a public IP address
type AutoscalingGroupLaunchConfigurationNoPublicIp struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupLaunchConfigurationNoPublicIp() *AutoscalingGroupLaunchConfigurationNoPublicIp {
    return &AutoscalingGroupLaunchConfigurationNoPublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_launch_configuration_no_public_ip",
            CheckTitle: "Auto Scaling group associated launch configuration does not assign a public IP address",
            ServiceName: "autoscaling",
            Severity: "high",
            Description: "**Amazon EC2 Auto Scaling groups** are evaluated to determine whether their associated **launch configuration** assigns **public IP addresses** to instances (e.g., `AssociatePublicIpAddress=true`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupLaunchConfigurationNoPublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupLaunchConfigurationNoPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingGroupCapacityRebalanceEnabled - Amazon EC2 Auto Scaling group has Capacity Rebalancing enabled
type AutoscalingGroupCapacityRebalanceEnabled struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupCapacityRebalanceEnabled() *AutoscalingGroupCapacityRebalanceEnabled {
    return &AutoscalingGroupCapacityRebalanceEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_capacity_rebalance_enabled",
            CheckTitle: "Amazon EC2 Auto Scaling group has Capacity Rebalancing enabled",
            ServiceName: "autoscaling",
            Severity: "medium",
            Description: "**EC2 Auto Scaling groups** use **Capacity Rebalancing** to act on EC2 `rebalance` recommendations by launching replacement Spot instances and terminating at-risk ones after they are healthy.  *Assesses whether this proactive replacement behavior is enabled.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupCapacityRebalanceEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupCapacityRebalanceEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingGroupMultipleInstanceTypes - Auto Scaling group spans multiple Availability Zones and has multiple instance types per Availability Zone
type AutoscalingGroupMultipleInstanceTypes struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupMultipleInstanceTypes() *AutoscalingGroupMultipleInstanceTypes {
    return &AutoscalingGroupMultipleInstanceTypes{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_multiple_instance_types",
            CheckTitle: "Auto Scaling group spans multiple Availability Zones and has multiple instance types per Availability Zone",
            ServiceName: "autoscaling",
            Severity: "medium",
            Description: "**EC2 Auto Scaling groups** are evaluated for using **multiple instance types** in each **Availability Zone** and spanning more than one AZ.  Groups are identified when every AZ defines at least two instance types; groups with any AZ using a single or no type, or confined to one AZ, are noted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupMultipleInstanceTypes) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupMultipleInstanceTypes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingGroupUsingEc2LaunchTemplate - Amazon EC2 Auto Scaling group uses an EC2 launch template
type AutoscalingGroupUsingEc2LaunchTemplate struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupUsingEc2LaunchTemplate() *AutoscalingGroupUsingEc2LaunchTemplate {
    return &AutoscalingGroupUsingEc2LaunchTemplate{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_using_ec2_launch_template",
            CheckTitle: "Amazon EC2 Auto Scaling group uses an EC2 launch template",
            ServiceName: "autoscaling",
            Severity: "medium",
            Description: "**EC2 Auto Scaling groups** use an **EC2 launch template** directly or via a `mixed instances policy` to define instance configuration and versioned settings.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupUsingEc2LaunchTemplate) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupUsingEc2LaunchTemplate) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AutoscalingGroupElbHealthCheckEnabled - Auto Scaling group associated with a load balancer has ELB health checks enabled
type AutoscalingGroupElbHealthCheckEnabled struct {
    metadata models.CheckMetadata
}

func NewAutoscalingGroupElbHealthCheckEnabled() *AutoscalingGroupElbHealthCheckEnabled {
    return &AutoscalingGroupElbHealthCheckEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "autoscaling_group_elb_health_check_enabled",
            CheckTitle: "Auto Scaling group associated with a load balancer has ELB health checks enabled",
            ServiceName: "autoscaling",
            Severity: "low",
            Description: "EC2 Auto Scaling groups attached to a load balancer are evaluated for **ELB-based health checks** that use the load balancer's target health instead of instance-only checks.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"autoscaling"},
        },
    }
}

func (c *AutoscalingGroupElbHealthCheckEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AutoscalingGroupElbHealthCheckEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "autoscaling",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

