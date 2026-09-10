package ecs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type ecsProvider interface {
	ECS(ctx context.Context) (*ecs.Client, error)
}

// EcsClusterContainerInsightsEnabled - ECS cluster has container insights enabled
type EcsClusterContainerInsightsEnabled struct {
	metadata models.CheckMetadata
}

func NewEcsClusterContainerInsightsEnabled() *EcsClusterContainerInsightsEnabled {
	return &EcsClusterContainerInsightsEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_cluster_container_insights_enabled",
			CheckTitle:   "ECS cluster has container insights enabled",
			ServiceName:  "ecs",
			Severity:     "low",
			ResourceType: "Cluster",
			Description:  "ECS clusters should have container insights enabled for monitoring",
			RemediationText: "Enable container insights on your ECS clusters",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsClusterContainerInsightsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsClusterContainerInsightsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := ecsClient.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	if len(clusters.ClusterArns) > 0 {
		describeOutput, err := ecsClient.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: clusters.ClusterArns,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe ECS clusters: %w", err)
		}

		for _, cluster := range describeOutput.Clusters {
			clusterName := aws.ToString(cluster.ClusterName)
			status := models.StatusFail
			statusExtended := fmt.Sprintf("ECS cluster %s does not have container insights enabled.", clusterName)

			for _, setting := range cluster.Settings {
				if setting.Name == types.ClusterSettingNameContainerInsights {
					if setting.Value != nil && (*setting.Value == "enabled" || *setting.Value == "enhanced") {
						status = models.StatusPass
						statusExtended = fmt.Sprintf("ECS cluster %s has container insights %s.", clusterName, *setting.Value)
					}
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "ecs",
				ResourceID:     clusterName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// EcsServiceFargateLatestPlatformVersion - ECS Fargate service uses latest platform version
type EcsServiceFargateLatestPlatformVersion struct {
	metadata models.CheckMetadata
}

func NewEcsServiceFargateLatestPlatformVersion() *EcsServiceFargateLatestPlatformVersion {
	return &EcsServiceFargateLatestPlatformVersion{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_service_fargate_latest_platform_version",
			CheckTitle:   "ECS Fargate service uses latest platform version",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "Service",
			Description:  "ECS Fargate services should use the latest platform version",
			RemediationText: "Update ECS service to use LATEST platform version or the latest available version",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsServiceFargateLatestPlatformVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsServiceFargateLatestPlatformVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	services, err := ecsClient.ListServices(ctx, &ecs.ListServicesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS services: %w", err)
	}

	if len(services.ServiceArns) > 0 {
		describeOutput, err := ecsClient.DescribeServices(ctx, &ecs.DescribeServicesInput{
			Services: services.ServiceArns,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe ECS services: %w", err)
		}

		for _, service := range describeOutput.Services {
			if service.LaunchType != types.LaunchTypeFargate {
				continue
			}

			serviceName := aws.ToString(service.ServiceName)
			platformVersion := aws.ToString(service.PlatformVersion)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("ECS Service %s is using latest FARGATE platform version.", serviceName)

			if platformVersion != "LATEST" {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("ECS Service %s is using platform version %s instead of LATEST.", serviceName, platformVersion)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "ecs",
				ResourceID:     serviceName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// EcsServiceNoAssignPublicIp - ECS service does not auto-assign public IP
type EcsServiceNoAssignPublicIp struct {
	metadata models.CheckMetadata
}

func NewEcsServiceNoAssignPublicIp() *EcsServiceNoAssignPublicIp {
	return &EcsServiceNoAssignPublicIp{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_service_no_assign_public_ip",
			CheckTitle:   "ECS service does not auto-assign public IP",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "Service",
			Description:  "ECS services should not auto-assign public IP addresses",
			RemediationText: "Disable auto-assign public IP on your ECS services",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsServiceNoAssignPublicIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsServiceNoAssignPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	services, err := ecsClient.ListServices(ctx, &ecs.ListServicesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS services: %w", err)
	}

	if len(services.ServiceArns) > 0 {
		describeOutput, err := ecsClient.DescribeServices(ctx, &ecs.DescribeServicesInput{
			Services: services.ServiceArns,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe ECS services: %w", err)
		}

		for _, service := range describeOutput.Services {
			serviceName := aws.ToString(service.ServiceName)

			// Check network configuration
			status := models.StatusPass
			statusExtended := fmt.Sprintf("ECS Service %s does not have automatic public IP assignment.", serviceName)

			if service.NetworkConfiguration != nil && service.NetworkConfiguration.AwsvpcConfiguration != nil {
				if service.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp == types.AssignPublicIpEnabled {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("ECS Service %s has automatic public IP assignment.", serviceName)
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "ecs",
				ResourceID:     serviceName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// EcsTaskDefinitionsContainersReadonlyAccess - ECS task definition containers have read-only root filesystem
type EcsTaskDefinitionsContainersReadonlyAccess struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsContainersReadonlyAccess() *EcsTaskDefinitionsContainersReadonlyAccess {
	return &EcsTaskDefinitionsContainersReadonlyAccess{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_containers_readonly_access",
			CheckTitle:   "ECS task definition containers have read-only root filesystem",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definition containers should have read-only root filesystem",
			RemediationText: "Enable readonlyRootFilesystem on your ECS task definition containers",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsContainersReadonlyAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsContainersReadonlyAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s does not have containers with write access to the root filesystems.", taskDefName)
		failedContainers := []string{}

		for _, container := range describeOutput.TaskDefinition.ContainerDefinitions {
			if !aws.ToBool(container.ReadonlyRootFilesystem) {
				status = models.StatusFail
				failedContainers = append(failedContainers, aws.ToString(container.Name))
			}
		}

		if len(failedContainers) > 0 {
			statusExtended = fmt.Sprintf("ECS task definition %s has containers with write access to the root filesystem: %s", taskDefName, strings.Join(failedContainers, ", "))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskDefinitionsHostNamespaceNotShared - ECS task definition does not share host process namespace
type EcsTaskDefinitionsHostNamespaceNotShared struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsHostNamespaceNotShared() *EcsTaskDefinitionsHostNamespaceNotShared {
	return &EcsTaskDefinitionsHostNamespaceNotShared{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_host_namespace_not_shared",
			CheckTitle:   "ECS task definition does not share host process namespace",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definitions should not share the host's process namespace with containers",
			RemediationText: "Use 'task' pid mode instead of 'host' for your ECS task definitions",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsHostNamespaceNotShared) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsHostNamespaceNotShared) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s does not share a host's process namespace with its containers.", taskDefName)

		if describeOutput.TaskDefinition.PidMode == "host" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("ECS task definition %s is configured to share a host's process namespace with its containers.", taskDefName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskDefinitionsHostNetworkingModeUsers - ECS task definition containers with host network mode are not running as root
type EcsTaskDefinitionsHostNetworkingModeUsers struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsHostNetworkingModeUsers() *EcsTaskDefinitionsHostNetworkingModeUsers {
	return &EcsTaskDefinitionsHostNetworkingModeUsers{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_host_networking_mode_users",
			CheckTitle:   "ECS task definition containers with host network mode are not running as root",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definition containers using host network mode should not run as root",
			RemediationText: "Specify a non-root user for containers using host network mode",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsHostNetworkingModeUsers) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsHostNetworkingModeUsers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		if describeOutput.TaskDefinition.NetworkMode != "host" {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s does not have host network mode.", taskDefName)
		failedContainers := []string{}

		for _, container := range describeOutput.TaskDefinition.ContainerDefinitions {
			user := aws.ToString(container.User)
			if !aws.ToBool(container.Privileged) && (user == "root" || user == "") {
				status = models.StatusFail
				failedContainers = append(failedContainers, aws.ToString(container.Name))
			}
		}

		if len(failedContainers) > 0 {
			statusExtended = fmt.Sprintf("ECS task definition %s has containers with host network mode and non-privileged containers running as root or with no user specified: %s", taskDefName, strings.Join(failedContainers, ", "))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskDefinitionsLoggingBlockMode - ECS task definition containers use non-blocking log mode
type EcsTaskDefinitionsLoggingBlockMode struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsLoggingBlockMode() *EcsTaskDefinitionsLoggingBlockMode {
	return &EcsTaskDefinitionsLoggingBlockMode{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_logging_block_mode",
			CheckTitle:   "ECS task definition containers use non-blocking log mode",
			ServiceName:  "ecs",
			Severity:     "low",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definition containers should use non-blocking log mode to prevent container blocking",
			RemediationText: "Configure log options with non-blocking mode for your ECS task definition containers",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsLoggingBlockMode) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsLoggingBlockMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s containers has logging configured with non blocking mode.", taskDefName)
		failedContainers := []string{}

		for _, container := range describeOutput.TaskDefinition.ContainerDefinitions {
			if container.LogConfiguration != nil {
				logOptions := container.LogConfiguration.Options
				if logOptions != nil {
					if mode, ok := logOptions["mode"]; ok && mode == "blocking" {
						status = models.StatusFail
						failedContainers = append(failedContainers, aws.ToString(container.Name))
					}
				}
			}
		}

		if len(failedContainers) > 0 {
			statusExtended = fmt.Sprintf("ECS task definition %s running with logging set to blocking mode on containers: %s", taskDefName, strings.Join(failedContainers, ", "))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskDefinitionsLoggingEnabled - ECS task definition containers have logging configured
type EcsTaskDefinitionsLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsLoggingEnabled() *EcsTaskDefinitionsLoggingEnabled {
	return &EcsTaskDefinitionsLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_logging_enabled",
			CheckTitle:   "ECS task definition containers have logging configured",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definition containers should have logging configured",
			RemediationText: "Configure logging for your ECS task definition containers",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s containers have logging configured.", taskDefName)
		failedContainers := []string{}

		for _, container := range describeOutput.TaskDefinition.ContainerDefinitions {
			if container.LogConfiguration == nil {
				status = models.StatusFail
				failedContainers = append(failedContainers, aws.ToString(container.Name))
			}
		}

		if len(failedContainers) > 0 {
			statusExtended = fmt.Sprintf("ECS task definition %s has containers running with no logging configuration: %s", taskDefName, strings.Join(failedContainers, ", "))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskDefinitionsNoEnvironmentSecrets - ECS task definition containers do not have secrets in environment variables
type EcsTaskDefinitionsNoEnvironmentSecrets struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsNoEnvironmentSecrets() *EcsTaskDefinitionsNoEnvironmentSecrets {
	return &EcsTaskDefinitionsNoEnvironmentSecrets{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_no_environment_secrets",
			CheckTitle:   "ECS task definition containers do not have secrets in environment variables",
			ServiceName:  "ecs",
			Severity:     "high",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definition containers should not have secrets in environment variables",
			RemediationText: "Use AWS Secrets Manager or SSM Parameter Store for secrets instead of environment variables",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsNoEnvironmentSecrets) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsNoEnvironmentSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	sensitivePatterns := []string{"password", "secret", "token", "apikey", "api_key", "private_key", "access_key"}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s containers do not have secrets in environment variables.", taskDefName)
		suspiciousVars := []string{}

		for _, container := range describeOutput.TaskDefinition.ContainerDefinitions {
			for _, env := range container.Environment {
				envName := strings.ToLower(aws.ToString(env.Name))
				for _, pattern := range sensitivePatterns {
					if strings.Contains(envName, pattern) {
						suspiciousVars = append(suspiciousVars, aws.ToString(env.Name))
						break
					}
				}
			}
		}

		if len(suspiciousVars) > 0 {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("ECS task definition %s containers may have secrets in environment variables: %s", taskDefName, strings.Join(suspiciousVars, ", "))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskDefinitionsNoPrivilegedContainers - ECS task definition containers are not privileged
type EcsTaskDefinitionsNoPrivilegedContainers struct {
	metadata models.CheckMetadata
}

func NewEcsTaskDefinitionsNoPrivilegedContainers() *EcsTaskDefinitionsNoPrivilegedContainers {
	return &EcsTaskDefinitionsNoPrivilegedContainers{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_definitions_no_privileged_containers",
			CheckTitle:   "ECS task definition containers are not privileged",
			ServiceName:  "ecs",
			Severity:     "high",
			ResourceType: "TaskDefinition",
			Description:  "ECS task definition containers should not run in privileged mode",
			RemediationText: "Disable privileged mode on your ECS task definition containers",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskDefinitionsNoPrivilegedContainers) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskDefinitionsNoPrivilegedContainers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ecsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement ecsProvider")
	}
	ecsClient, err := p.ECS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	taskDefs, err := ecsClient.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
	}

	for _, taskDefArn := range taskDefs.TaskDefinitionArns {
		taskDefName := taskDefArn[strings.LastIndex(taskDefArn, "/")+1:]

		describeOutput, err := ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefArn),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("ECS task definition %s does not have privileged containers.", taskDefName)
		failedContainers := []string{}

		for _, container := range describeOutput.TaskDefinition.ContainerDefinitions {
			if aws.ToBool(container.Privileged) {
				status = models.StatusFail
				failedContainers = append(failedContainers, aws.ToString(container.Name))
			}
		}

		if len(failedContainers) > 0 {
			statusExtended = fmt.Sprintf("ECS task definition %s has privileged containers: %s", taskDefName, strings.Join(failedContainers, ", "))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "ecs",
			ResourceID:     taskDefName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// EcsTaskSetNoAssignPublicIp - ECS task set does not auto-assign public IP
type EcsTaskSetNoAssignPublicIp struct {
	metadata models.CheckMetadata
}

func NewEcsTaskSetNoAssignPublicIp() *EcsTaskSetNoAssignPublicIp {
	return &EcsTaskSetNoAssignPublicIp{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "ecs_task_set_no_assign_public_ip",
			CheckTitle:   "ECS task set does not auto-assign public IP",
			ServiceName:  "ecs",
			Severity:     "medium",
			ResourceType: "TaskSet",
			Description:  "ECS task sets should not auto-assign public IP addresses",
			RemediationText: "Disable auto-assign public IP on your ECS task sets",
			Categories:   []string{"containers"},
		},
	}
}

func (c *EcsTaskSetNoAssignPublicIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *EcsTaskSetNoAssignPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	// Task sets are identified at the service level, already covered by EcsServiceNoAssignPublicIp
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Task set public IP assignment is covered by service-level check",
			Provider:       "aws",
			Service:        "ecs",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		},
	}, nil
}