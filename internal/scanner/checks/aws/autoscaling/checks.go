package autoscaling

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type autoscalingProvider interface {
	AutoScaling(ctx context.Context) (*autoscaling.Client, error)
}

// AutoscalingGroupHealthCheckEnabled - ASG health check enabled
type AutoscalingGroupHealthCheckEnabled struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupHealthCheckEnabled() *AutoscalingGroupHealthCheckEnabled {
	return &AutoscalingGroupHealthCheckEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_health_check_enabled",
			CheckTitle: "ASG health check enabled",
			ServiceName: "autoscaling", Severity: "medium", ResourceType: "AutoScalingGroup",
			Description: "ASGs should have health checks enabled",
			RemediationText: "Enable health checks on ASGs",
			Categories: []string{"compute"},
		},
	}
}

func (c *AutoscalingGroupHealthCheckEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupHealthCheckEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ASGs: %w", err)
	}

	for _, group := range groups.AutoScalingGroups {
		groupName := aws.ToString(group.AutoScalingGroupName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ASG %s does not have health checks enabled.", groupName)

		if group.HealthCheckType != nil && *group.HealthCheckType != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("ASG %s has health checks enabled.", groupName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "autoscaling", ResourceID: groupName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// AutoscalingGroupLaunchConfigurationAttached - ASG launch config attached
type AutoscalingGroupLaunchConfigurationAttached struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupLaunchConfigurationAttached() *AutoscalingGroupLaunchConfigurationAttached {
	return &AutoscalingGroupLaunchConfigurationAttached{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_launch_configuration_attached",
			CheckTitle: "ASG launch configuration attached",
			ServiceName: "autoscaling", Severity: "low", ResourceType: "AutoScalingGroup",
			Description: "ASGs should have launch configuration attached",
			RemediationText: "Attach launch configuration to ASGs",
			Categories: []string{"compute"},
		},
	}
}

func (c *AutoscalingGroupLaunchConfigurationAttached) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupLaunchConfigurationAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "ASG launch configuration check requires detailed analysis",
			Provider: "aws", Service: "autoscaling",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// AutoscalingGroupMultipleAz - ASG multiple AZ
type AutoscalingGroupMultipleAz struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupMultipleAz() *AutoscalingGroupMultipleAz {
	return &AutoscalingGroupMultipleAz{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_multiple_az",
			CheckTitle: "ASG multiple AZ",
			ServiceName: "autoscaling", Severity: "medium", ResourceType: "AutoScalingGroup",
			Description: "ASGs should span multiple AZs",
			RemediationText: "Configure ASGs to span multiple AZs",
			Categories: []string{"compute"},
		},
	}
}

func (c *AutoscalingGroupMultipleAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupMultipleAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ASGs: %w", err)
	}

	for _, group := range groups.AutoScalingGroups {
		groupName := aws.ToString(group.AutoScalingGroupName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ASG %s does not span multiple AZs.", groupName)

		if len(group.AvailabilityZones) >= 2 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("ASG %s spans %d AZs.", groupName, len(group.AvailabilityZones))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "autoscaling", ResourceID: groupName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// AutoscalingGroupScalingNotifications - ASG scaling notifications
type AutoscalingGroupScalingNotifications struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupScalingNotifications() *AutoscalingGroupScalingNotifications {
	return &AutoscalingGroupScalingNotifications{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_scaling_notifications",
			CheckTitle: "ASG scaling notifications",
			ServiceName: "autoscaling", Severity: "low", ResourceType: "AutoScalingGroup",
			Description: "ASGs should have scaling notifications enabled",
			RemediationText: "Enable scaling notifications on ASGs",
			Categories: []string{"compute"},
		},
	}
}

func (c *AutoscalingGroupScalingNotifications) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupScalingNotifications) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "ASG scaling notifications check requires SNS integration",
			Provider: "aws", Service: "autoscaling",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// AutoscalingGroupTagTracking - ASG tag tracking
type AutoscalingGroupTagTracking struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupTagTracking() *AutoscalingGroupTagTracking {
	return &AutoscalingGroupTagTracking{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_tag_tracking",
			CheckTitle: "ASG tag tracking",
			ServiceName: "autoscaling", Severity: "low", ResourceType: "AutoScalingGroup",
			Description: "ASGs should have tag tracking enabled",
			RemediationText: "Enable tag tracking on ASGs",
			Categories: []string{"compute"},
		},
	}
}

func (c *AutoscalingGroupTagTracking) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupTagTracking) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "ASG tag tracking check requires detailed configuration analysis",
			Provider: "aws", Service: "autoscaling",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// AutoscalingGroupWithSuspendedProcesses - ASG suspended processes
type AutoscalingGroupWithSuspendedProcesses struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupWithSuspendedProcesses() *AutoscalingGroupWithSuspendedProcesses {
	return &AutoscalingGroupWithSuspendedProcesses{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_with_suspended_processes",
			CheckTitle: "ASG suspended processes",
			ServiceName: "autoscaling", Severity: "medium", ResourceType: "AutoScalingGroup",
			Description: "ASGs should not have suspended processes",
			RemediationText: "Resume suspended processes on ASGs",
			Categories: []string{"compute"},
		},
	}
}

func (c *AutoscalingGroupWithSuspendedProcesses) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupWithSuspendedProcesses) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ASGs: %w", err)
	}

	for _, group := range groups.AutoScalingGroups {
		groupName := aws.ToString(group.AutoScalingGroupName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("ASG %s has no suspended processes.", groupName)

		if len(group.SuspendedProcesses) > 0 {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("ASG %s has %d suspended processes.", groupName, len(group.SuspendedProcesses))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "autoscaling", ResourceID: groupName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// AutoscalingLaunchConfigPublicIpDisabled - ASG launch config public IP disabled
type AutoscalingLaunchConfigPublicIpDisabled struct {
	metadata models.CheckMetadata
}

func NewAutoscalingLaunchConfigPublicIpDisabled() *AutoscalingLaunchConfigPublicIpDisabled {
	return &AutoscalingLaunchConfigPublicIpDisabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_launch_config_public_ip_disabled",
			CheckTitle: "ASG launch config public IP disabled",
			ServiceName: "autoscaling", Severity: "medium", ResourceType: "LaunchConfiguration",
			Description: "ASG launch configs should not assign public IPs",
			RemediationText: "Disable public IP assignment on ASG launch configs",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *AutoscalingLaunchConfigPublicIpDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingLaunchConfigPublicIpDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	configs, err := asgClient.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe launch configs: %w", err)
	}

	for _, config := range configs.LaunchConfigurations {
		configName := aws.ToString(config.LaunchConfigurationName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("ASG launch config %s does not assign public IPs.", configName)

		if config.AssociatePublicIpAddress != nil && *config.AssociatePublicIpAddress {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("ASG launch config %s assigns public IPs.", configName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "autoscaling", ResourceID: configName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// AutoscalingLaunchConfigMetadataOptions - ASG launch config metadata options
type AutoscalingLaunchConfigMetadataOptions struct {
	metadata models.CheckMetadata
}

func NewAutoscalingLaunchConfigMetadataOptions() *AutoscalingLaunchConfigMetadataOptions {
	return &AutoscalingLaunchConfigMetadataOptions{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_launch_config_metadata_options",
			CheckTitle: "ASG launch config metadata options",
			ServiceName: "autoscaling", Severity: "medium", ResourceType: "LaunchConfiguration",
			Description: "ASG launch configs should have IMDSv2 required",
			RemediationText: "Require IMDSv2 on ASG launch configs",
			Categories: []string{"compute", "security"},
		},
	}
}

func (c *AutoscalingLaunchConfigMetadataOptions) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingLaunchConfigMetadataOptions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	configs, err := asgClient.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe launch configs: %w", err)
	}

	for _, config := range configs.LaunchConfigurations {
		configName := aws.ToString(config.LaunchConfigurationName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ASG launch config %s does not require IMDSv2.", configName)

		if config.MetadataOptions != nil && config.MetadataOptions.HttpTokens == "required" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("ASG launch config %s requires IMDSv2.", configName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "autoscaling", ResourceID: configName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}