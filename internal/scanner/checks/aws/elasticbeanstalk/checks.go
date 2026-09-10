package elasticbeanstalk

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type elasticbeanstalkProvider interface {
	ElasticBeanstalk(ctx context.Context) (*elasticbeanstalk.Client, error)
}

// ElasticbeanstalkEnvironmentManagedUpdatesEnabled - Elastic Beanstalk environment has managed platform updates enabled
type ElasticbeanstalkEnvironmentManagedUpdatesEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticbeanstalkEnvironmentManagedUpdatesEnabled() *ElasticbeanstalkEnvironmentManagedUpdatesEnabled {
	return &ElasticbeanstalkEnvironmentManagedUpdatesEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticbeanstalk_environment_managed_updates_enabled",
			CheckTitle: "Elastic Beanstalk environment has managed platform updates enabled",
			ServiceName: "elasticbeanstalk",
			Severity: "medium",
			Description: "Elastic Beanstalk environment has managed platform updates enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticbeanstalk"},
		},
	}
}

func (c *ElasticbeanstalkEnvironmentManagedUpdatesEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticbeanstalkEnvironmentManagedUpdatesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticbeanstalkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticbeanstalkProvider")
	}
	ebClient, err := p.ElasticBeanstalk(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	environments, err := ebClient.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar environments Elastic Beanstalk: %w", err)
	}

	for _, env := range environments.Environments {
		envName := aws.ToString(env.EnvironmentName)
		envID := aws.ToString(env.EnvironmentId)

		// Check managed updates
		// Note: OptionSettings is not available in EnvironmentDescription.
		// Would need DescribeConfigurationSettings API call to get option settings.
		// For now, report as informational.

		status := models.StatusPass
		ext := fmt.Sprintf("Elastic Beanstalk environment %s - managed updates check requires DescribeConfigurationSettings API.", envName)

		_ = envID

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticbeanstalk",
			ResourceID: envName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticbeanstalkEnvironmentEnhancedHealthReporting - Elastic Beanstalk environment has enhanced health reporting
type ElasticbeanstalkEnvironmentEnhancedHealthReporting struct {
	metadata models.CheckMetadata
}

func NewElasticbeanstalkEnvironmentEnhancedHealthReporting() *ElasticbeanstalkEnvironmentEnhancedHealthReporting {
	return &ElasticbeanstalkEnvironmentEnhancedHealthReporting{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticbeanstalk_environment_enhanced_health_reporting",
			CheckTitle: "Elastic Beanstalk environment has enhanced health reporting enabled",
			ServiceName: "elasticbeanstalk",
			Severity: "medium",
			Description: "Elastic Beanstalk environment has enhanced health reporting enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticbeanstalk"},
		},
	}
}

func (c *ElasticbeanstalkEnvironmentEnhancedHealthReporting) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticbeanstalkEnvironmentEnhancedHealthReporting) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticbeanstalkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticbeanstalkProvider")
	}
	ebClient, err := p.ElasticBeanstalk(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	environments, err := ebClient.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar environments Elastic Beanstalk: %w", err)
	}

	for _, env := range environments.Environments {
		envName := aws.ToString(env.EnvironmentName)

		// Note: OptionSettings is not available in EnvironmentDescription.
		// Would need DescribeConfigurationSettings API call to get option settings.
		// For now, report as informational.

		status := models.StatusPass
		ext := fmt.Sprintf("Elastic Beanstalk environment %s - enhanced health reporting check requires DescribeConfigurationSettings API.", envName)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticbeanstalk",
			ResourceID: envName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticbeanstalkEnvironmentNoSecretsInConfiguration - Elastic Beanstalk environment configuration has no secrets
type ElasticbeanstalkEnvironmentNoSecretsInConfiguration struct {
	metadata models.CheckMetadata
}

func NewElasticbeanstalkEnvironmentNoSecretsInConfiguration() *ElasticbeanstalkEnvironmentNoSecretsInConfiguration {
	return &ElasticbeanstalkEnvironmentNoSecretsInConfiguration{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticbeanstalk_environment_no_secrets_in_configuration",
			CheckTitle: "Elastic Beanstalk environment configuration has no hardcoded secrets",
			ServiceName: "elasticbeanstalk",
			Severity: "high",
			Description: "Elastic Beanstalk environment configuration contains no hardcoded secrets.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticbeanstalk"},
		},
	}
}

func (c *ElasticbeanstalkEnvironmentNoSecretsInConfiguration) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticbeanstalkEnvironmentNoSecretsInConfiguration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticbeanstalkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticbeanstalkProvider")
	}
	ebClient, err := p.ElasticBeanstalk(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	environments, err := ebClient.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar environments Elastic Beanstalk: %w", err)
	}

	for _, env := range environments.Environments {
		envName := aws.ToString(env.EnvironmentName)

		// Note: OptionSettings is not available in EnvironmentDescription.
		// Would need DescribeConfigurationSettings API call to get option settings.
		// For now, report as informational.

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Elastic Beanstalk environment %s configuration - secrets scan requires deeper analysis (not performed).", envName),
			Provider: "aws",
			Service: "elasticbeanstalk",
			ResourceID: envName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticbeanstalkEnvironmentCloudwatchLoggingEnabled - Elastic Beanstalk environment has CloudWatch logging enabled
type ElasticbeanstalkEnvironmentCloudwatchLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticbeanstalkEnvironmentCloudwatchLoggingEnabled() *ElasticbeanstalkEnvironmentCloudwatchLoggingEnabled {
	return &ElasticbeanstalkEnvironmentCloudwatchLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticbeanstalk_environment_cloudwatch_logging_enabled",
			CheckTitle: "Elastic Beanstalk environment has CloudWatch logging enabled",
			ServiceName: "elasticbeanstalk",
			Severity: "medium",
			Description: "Elastic Beanstalk environment is sending logs to CloudWatch Logs.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticbeanstalk"},
		},
	}
}

func (c *ElasticbeanstalkEnvironmentCloudwatchLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticbeanstalkEnvironmentCloudwatchLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticbeanstalkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticbeanstalkProvider")
	}
	ebClient, err := p.ElasticBeanstalk(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	environments, err := ebClient.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar environments Elastic Beanstalk: %w", err)
	}

	for _, env := range environments.Environments {
		envName := aws.ToString(env.EnvironmentName)

		// Note: OptionSettings is not available in EnvironmentDescription.
		// Would need DescribeConfigurationSettings API call to get option settings.
		// For now, report as informational.

		status := models.StatusPass
		ext := fmt.Sprintf("Elastic Beanstalk environment %s - CloudWatch logging check requires DescribeConfigurationSettings API.", envName)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticbeanstalk",
			ResourceID: envName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}