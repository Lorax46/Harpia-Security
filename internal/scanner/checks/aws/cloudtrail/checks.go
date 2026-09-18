package cloudtrail

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cloudtrailProvider interface {
	CloudTrail(ctx context.Context) (*cloudtrail.Client, error)
}

// LoggingCheck - verifica se CloudTrail está habilitado
type LoggingCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingCheck() *LoggingCheck {
	return &LoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_logging_enabled",
			CheckTitle:      "CloudTrail logging should be enabled",
			ServiceName:     "cloudtrail",
			Severity:        "critical",
			ResourceType:    "Trail",
			Description:     "CloudTrail logging should be enabled",
			RemediationText: "Enable CloudTrail logging",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *LoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	if len(trails.TrailList) == 0 {
		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          models.StatusFail,
			StatusExtended:  "No CloudTrail trails configured",
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      "cloudtrail",
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
		return findings, nil
	}

	for _, trail := range trails.TrailList {
		isLogging := false
		if trail.Name != nil {
			status, err := ctClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
				Name: trail.Name,
			})
			if err == nil && status != nil {
				isLogging = aws.ToBool(status.IsLogging)
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s is logging", aws.ToString(trail.Name))
		if !isLogging {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s is not logging", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// MultiRegionCheck - verifica se CloudTrail é multi-região
type MultiRegionCheck struct {
	metadata models.CheckMetadata
}

func NewMultiRegionCheck() *MultiRegionCheck {
	return &MultiRegionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_multi_region",
			CheckTitle:      "CloudTrail should be multi-region",
			ServiceName:     "cloudtrail",
			Severity:        "high",
			ResourceType:    "Trail",
			Description:     "CloudTrail should capture events from all regions",
			RemediationText: "Enable multi-region on CloudTrail",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *MultiRegionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MultiRegionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		isMultiRegion := aws.ToBool(trail.IsMultiRegionTrail)

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s is multi-region", aws.ToString(trail.Name))
		if !isMultiRegion {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s is not multi-region", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// LogFileValidationCheck - verifica validação de log
type LogFileValidationCheck struct {
	metadata models.CheckMetadata
}

func NewLogFileValidationCheck() *LogFileValidationCheck {
	return &LogFileValidationCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_log_file_validation",
			CheckTitle:      "CloudTrail log file validation should be enabled",
			ServiceName:     "cloudtrail",
			Severity:        "high",
			ResourceType:    "Trail",
			Description:     "CloudTrail log file validation should be enabled",
			RemediationText: "Enable CloudTrail log file validation",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *LogFileValidationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LogFileValidationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		hasValidation := aws.ToBool(trail.LogFileValidationEnabled)

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s has log file validation enabled", aws.ToString(trail.Name))
		if !hasValidation {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s does not have log file validation enabled", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// EncryptionCheck - verifica criptografia
type EncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewEncryptionCheck() *EncryptionCheck {
	return &EncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_encryption",
			CheckTitle:      "CloudTrail should use encryption",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "Trail",
			Description:     "CloudTrail logs should be encrypted",
			RemediationText: "Enable CloudTrail encryption",
			Categories:      []string{"cloudtrail", "encryption"},
		},
	}
}

func (c *EncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		hasEncryption := trail.KmsKeyId != nil && *trail.KmsKeyId != ""

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s uses encryption", aws.ToString(trail.Name))
		if !hasEncryption {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s does not use encryption", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// CloudWatchLogsCheck - verifica integração com CloudWatch Logs
type CloudWatchLogsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudWatchLogsCheck() *CloudWatchLogsCheck {
	return &CloudWatchLogsCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_cloudwatch_logs",
			CheckTitle:      "CloudTrail should be integrated with CloudWatch Logs",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "Trail",
			Description:     "CloudTrail should be integrated with CloudWatch Logs",
			RemediationText: "Enable CloudWatch Logs integration",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *CloudWatchLogsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudWatchLogsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		hasCloudWatch := trail.CloudWatchLogsLogGroupArn != nil && *trail.CloudWatchLogsLogGroupArn != ""

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s is integrated with CloudWatch Logs", aws.ToString(trail.Name))
		if !hasCloudWatch {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s is not integrated with CloudWatch Logs", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}
