package autoscaling

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

// AutoscalingFindSecretsLaunchConfiguration - verifica segredos no user data
type AutoscalingFindSecretsLaunchConfiguration struct {
	metadata models.CheckMetadata
}

func NewAutoscalingFindSecretsLaunchConfiguration() *AutoscalingFindSecretsLaunchConfiguration {
	return &AutoscalingFindSecretsLaunchConfiguration{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_find_secrets_ec2_launch_configuration",
			CheckTitle: "Ensure no secrets in EC2 launch configuration user data",
			Description: "Launch configuration user data should not contain secrets",
			Severity: "critical", ServiceName: "autoscaling", ResourceType: "LaunchConfiguration",
			RemediationText: "Remove secrets from launch configuration user data",
			Categories: []string{"autoscaling", "secrets", "user-data"},
		},
	}
}

func (c *AutoscalingFindSecretsLaunchConfiguration) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingFindSecretsLaunchConfiguration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	configs, err := asgClient.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
	if err != nil {
		return nil, err
	}

	secretPatterns := []string{"password", "secret", "api_key", "apikey", "token", "access_key", "private_key"}
	findings := []models.Finding{}

	for _, config := range configs.LaunchConfigurations {
		userData := aws.ToString(config.UserData)
		hasSecret := false
		for _, pattern := range secretPatterns {
			if strings.Contains(strings.ToLower(userData), pattern) {
				hasSecret = true
				break
			}
		}

		status := models.StatusPass
		msg := fmt.Sprintf("Launch config %s has no secrets in user data", aws.ToString(config.LaunchConfigurationName))
		if hasSecret {
			status = models.StatusFail
			msg = fmt.Sprintf("Launch config %s contains secrets in user data", aws.ToString(config.LaunchConfigurationName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(config.LaunchConfigurationName), Provider: "aws", Service: "autoscaling",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AutoscalingGroupCapacityRebalanceEnabled - verifica capacity rebalance
type AutoscalingGroupCapacityRebalanceEnabled struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupCapacityRebalanceEnabled() *AutoscalingGroupCapacityRebalanceEnabled {
	return &AutoscalingGroupCapacityRebalanceEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_capacity_rebalance_enabled",
			CheckTitle: "Ensure ASG has capacity rebalance enabled",
			Description: "ASGs should have capacity rebalance enabled for better availability",
			Severity: "medium", ServiceName: "autoscaling", ResourceType: "AutoScalingGroup",
			RemediationText: "Enable capacity rebalance on ASGs",
			Categories: []string{"autoscaling", "availability"},
		},
	}
}

func (c *AutoscalingGroupCapacityRebalanceEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupCapacityRebalanceEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range groups.AutoScalingGroups {
		status := models.StatusFail
		msg := fmt.Sprintf("ASG %s does not have capacity rebalance enabled", aws.ToString(group.AutoScalingGroupName))
		if group.CapacityRebalance != nil && *group.CapacityRebalance {
			status = models.StatusPass
			msg = fmt.Sprintf("ASG %s has capacity rebalance enabled", aws.ToString(group.AutoScalingGroupName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(group.AutoScalingGroupName), Provider: "aws", Service: "autoscaling",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AutoscalingGroupElbHealthCheckEnabled - verifica ELB health check
type AutoscalingGroupElbHealthCheckEnabled struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupElbHealthCheckEnabled() *AutoscalingGroupElbHealthCheckEnabled {
	return &AutoscalingGroupElbHealthCheckEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_elb_health_check_enabled",
			CheckTitle: "Ensure ASG with load balancer has ELB health checks enabled",
			Description: "ASGs associated with load balancers should use ELB health checks",
			Severity: "low", ServiceName: "autoscaling", ResourceType: "AutoScalingGroup",
			RemediationText: "Enable ELB health checks on ASGs",
			Categories: []string{"autoscaling", "health-check"},
		},
	}
}

func (c *AutoscalingGroupElbHealthCheckEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupElbHealthCheckEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range groups.AutoScalingGroups {
		// Verificar se tem load balancer associado
		if len(group.LoadBalancerNames) > 0 {
			status := models.StatusFail
			msg := fmt.Sprintf("ASG %s with load balancer does not have ELB health checks", aws.ToString(group.AutoScalingGroupName))
			if group.HealthCheckType != nil && *group.HealthCheckType == "ELB" {
				status = models.StatusPass
				msg = fmt.Sprintf("ASG %s has ELB health checks enabled", aws.ToString(group.AutoScalingGroupName))
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(group.AutoScalingGroupName), Provider: "aws", Service: "autoscaling",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// AutoscalingGroupLaunchConfigurationNoPublicIp - verifica IP público
type AutoscalingGroupLaunchConfigurationNoPublicIp struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupLaunchConfigurationNoPublicIp() *AutoscalingGroupLaunchConfigurationNoPublicIp {
	return &AutoscalingGroupLaunchConfigurationNoPublicIp{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_launch_configuration_no_public_ip",
			CheckTitle: "Ensure ASG launch configuration does not assign public IP",
			Description: "ASG launch configurations should not assign public IP addresses",
			Severity: "high", ServiceName: "autoscaling", ResourceType: "LaunchConfiguration",
			RemediationText: "Disable public IP assignment on ASG launch configurations",
			Categories: []string{"autoscaling", "networking"},
		},
	}
}

func (c *AutoscalingGroupLaunchConfigurationNoPublicIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupLaunchConfigurationNoPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	configs, err := asgClient.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, config := range configs.LaunchConfigurations {
		status := models.StatusPass
		msg := fmt.Sprintf("Launch config %s does not assign public IP", aws.ToString(config.LaunchConfigurationName))
		if config.AssociatePublicIpAddress != nil && *config.AssociatePublicIpAddress {
			status = models.StatusFail
			msg = fmt.Sprintf("Launch config %s assigns public IP", aws.ToString(config.LaunchConfigurationName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(config.LaunchConfigurationName), Provider: "aws", Service: "autoscaling",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AutoscalingGroupLaunchConfigurationRequiresImdsv2 - verifica IMDSv2
type AutoscalingGroupLaunchConfigurationRequiresImdsv2 struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupLaunchConfigurationRequiresImdsv2() *AutoscalingGroupLaunchConfigurationRequiresImdsv2 {
	return &AutoscalingGroupLaunchConfigurationRequiresImdsv2{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_launch_configuration_requires_imdsv2",
			CheckTitle: "Ensure ASG launch configuration requires IMDSv2",
			Description: "ASG launch configurations should require IMDSv2",
			Severity: "high", ServiceName: "autoscaling", ResourceType: "LaunchConfiguration",
			RemediationText: "Require IMDSv2 on ASG launch configurations",
			Categories: []string{"autoscaling", "metadata"},
		},
	}
}

func (c *AutoscalingGroupLaunchConfigurationRequiresImdsv2) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupLaunchConfigurationRequiresImdsv2) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	configs, err := asgClient.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, config := range configs.LaunchConfigurations {
		status := models.StatusFail
		msg := fmt.Sprintf("Launch config %s does not require IMDSv2", aws.ToString(config.LaunchConfigurationName))
		if config.MetadataOptions != nil && config.MetadataOptions.HttpTokens == "required" {
			status = models.StatusPass
			msg = fmt.Sprintf("Launch config %s requires IMDSv2", aws.ToString(config.LaunchConfigurationName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(config.LaunchConfigurationName), Provider: "aws", Service: "autoscaling",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AutoscalingGroupMultipleInstanceTypes - verifica múltiplos tipos de instância
type AutoscalingGroupMultipleInstanceTypes struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupMultipleInstanceTypes() *AutoscalingGroupMultipleInstanceTypes {
	return &AutoscalingGroupMultipleInstanceTypes{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_multiple_instance_types",
			CheckTitle: "Ensure ASG uses multiple instance types",
			Description: "ASGs should use multiple instance types across AZs for better availability",
			Severity: "medium", ServiceName: "autoscaling", ResourceType: "AutoScalingGroup",
			RemediationText: "Configure ASG with multiple instance types",
			Categories: []string{"autoscaling", "availability"},
		},
	}
}

func (c *AutoscalingGroupMultipleInstanceTypes) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupMultipleInstanceTypes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range groups.AutoScalingGroups {
		// Verificar se tem múltiplos tipos de instância
		instanceTypes := make(map[string]bool)
		for _, instance := range group.Instances {
			instanceTypes[aws.ToString(instance.InstanceType)] = true
		}

		status := models.StatusFail
		msg := fmt.Sprintf("ASG %s uses only one instance type", aws.ToString(group.AutoScalingGroupName))
		if len(instanceTypes) > 1 {
			status = models.StatusPass
			msg = fmt.Sprintf("ASG %s uses %d different instance types", aws.ToString(group.AutoScalingGroupName), len(instanceTypes))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(group.AutoScalingGroupName), Provider: "aws", Service: "autoscaling",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AutoscalingGroupUsingEc2LaunchTemplate - verifica uso de launch template
type AutoscalingGroupUsingEc2LaunchTemplate struct {
	metadata models.CheckMetadata
}

func NewAutoscalingGroupUsingEc2LaunchTemplate() *AutoscalingGroupUsingEc2LaunchTemplate {
	return &AutoscalingGroupUsingEc2LaunchTemplate{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "autoscaling_group_using_ec2_launch_template",
			CheckTitle: "Ensure ASG uses EC2 launch template",
			Description: "ASGs should use EC2 launch templates instead of launch configurations",
			Severity: "medium", ServiceName: "autoscaling", ResourceType: "AutoScalingGroup",
			RemediationText: "Migrate ASG to use EC2 launch template",
			Categories: []string{"autoscaling", "launch-template"},
		},
	}
}

func (c *AutoscalingGroupUsingEc2LaunchTemplate) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoscalingGroupUsingEc2LaunchTemplate) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(autoscalingProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement autoscalingProvider")
	}
	asgClient, err := p.AutoScaling(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := asgClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range groups.AutoScalingGroups {
		status := models.StatusFail
		msg := fmt.Sprintf("ASG %s does not use EC2 launch template", aws.ToString(group.AutoScalingGroupName))
		if group.LaunchTemplate != nil && group.LaunchTemplate.LaunchTemplateId != nil {
			status = models.StatusPass
			msg = fmt.Sprintf("ASG %s uses EC2 launch template", aws.ToString(group.AutoScalingGroupName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(group.AutoScalingGroupName), Provider: "aws", Service: "autoscaling",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
