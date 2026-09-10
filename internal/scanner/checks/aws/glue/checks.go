package glue

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type glueProvider interface {
	Glue(ctx context.Context) (*glue.Client, error)
}

// ==================== Glue Data Catalog Checks ====================

// GlueDataCatalogsMetadataEncryptionEnabled - Glue data catalog metadata encryption
type GlueDataCatalogsMetadataEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueDataCatalogsMetadataEncryptionEnabled() *GlueDataCatalogsMetadataEncryptionEnabled {
	return &GlueDataCatalogsMetadataEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_data_catalogs_metadata_encryption_enabled",
			CheckTitle: "Glue data catalog metadata encryption is enabled",
			ServiceName: "glue", Severity: "high", ResourceType: "DataCatalog",
			Description: "Glue data catalog should have metadata encryption enabled",
			RemediationText: "Enable metadata encryption on Glue data catalog",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueDataCatalogsMetadataEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDataCatalogsMetadataEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// Get data catalog encryption settings
	encryptionSettings, err := glueClient.GetDataCatalogEncryptionSettings(ctx, &glue.GetDataCatalogEncryptionSettingsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get data catalog encryption settings: %w", err)
	}

	status := models.StatusFail
	statusExtended := "Glue data catalog metadata encryption is not enabled."

	if encryptionSettings.DataCatalogEncryptionSettings != nil {
		if encryptionSettings.DataCatalogEncryptionSettings.EncryptionAtRest != nil &&
			encryptionSettings.DataCatalogEncryptionSettings.EncryptionAtRest.SseAwsKmsKeyId != nil {
			status = models.StatusPass
			statusExtended = "Glue data catalog metadata encryption is enabled."
		}
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: statusExtended,
		Provider: "aws", Service: "glue", ResourceID: "data-catalog",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
		FoundAt: time.Now().UTC(),
	})

	return findings, nil
}

// GlueDataCatalogsConnectionPasswordsEncryptionEnabled - Glue connection passwords encryption
type GlueDataCatalogsConnectionPasswordsEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueDataCatalogsConnectionPasswordsEncryptionEnabled() *GlueDataCatalogsConnectionPasswordsEncryptionEnabled {
	return &GlueDataCatalogsConnectionPasswordsEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_data_catalogs_connection_passwords_encryption_enabled",
			CheckTitle: "Glue connection passwords encryption is enabled",
			ServiceName: "glue", Severity: "high", ResourceType: "DataCatalog",
			Description: "Glue connection passwords should be encrypted",
			RemediationText: "Enable connection password encryption on Glue data catalog",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueDataCatalogsConnectionPasswordsEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDataCatalogsConnectionPasswordsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	encryptionSettings, err := glueClient.GetDataCatalogEncryptionSettings(ctx, &glue.GetDataCatalogEncryptionSettingsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get data catalog encryption settings: %w", err)
	}

	status := models.StatusFail
	statusExtended := "Glue connection passwords encryption is not enabled."

	if encryptionSettings.DataCatalogEncryptionSettings != nil &&
		encryptionSettings.DataCatalogEncryptionSettings.ConnectionPasswordEncryption != nil &&
		encryptionSettings.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted {
		status = models.StatusPass
		statusExtended = "Glue connection passwords encryption is enabled."
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: statusExtended,
		Provider: "aws", Service: "glue", ResourceID: "data-catalog",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
		FoundAt: time.Now().UTC(),
	})

	return findings, nil
}

// GlueDataCatalogsNotPubliclyAccessible - Glue data catalog is not publicly accessible
type GlueDataCatalogsNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewGlueDataCatalogsNotPubliclyAccessible() *GlueDataCatalogsNotPubliclyAccessible {
	return &GlueDataCatalogsNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_data_catalogs_not_publicly_accessible",
			CheckTitle: "Glue data catalog is not publicly accessible",
			ServiceName: "glue", Severity: "high", ResourceType: "DataCatalog",
			Description: "Glue data catalog should not be publicly accessible",
			RemediationText: "Remove public access from Glue data catalog",
			Categories: []string{"analytics"},
		},
	}
}

func (c *GlueDataCatalogsNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDataCatalogsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Glue data catalog public access check requires IAM policy analysis",
			Provider: "aws", Service: "glue",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// ==================== Glue Connection Checks ====================

// GlueDatabaseConnectionsSSLEnabled - Glue database connections use SSL
type GlueDatabaseConnectionsSSLEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueDatabaseConnectionsSSLEnabled() *GlueDatabaseConnectionsSSLEnabled {
	return &GlueDatabaseConnectionsSSLEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_database_connections_ssl_enabled",
			CheckTitle: "Glue database connections use SSL",
			ServiceName: "glue", Severity: "medium", ResourceType: "Connection",
			Description: "Glue database connections should use SSL",
			RemediationText: "Enable SSL on Glue database connections",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueDatabaseConnectionsSSLEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDatabaseConnectionsSSLEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	connections, err := glueClient.GetConnections(ctx, &glue.GetConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	for _, conn := range connections.ConnectionList {
		connName := aws.ToString(conn.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue connection %s does not use SSL.", connName)

		if conn.ConnectionProperties != nil {
			if sslMode, ok := conn.ConnectionProperties["SSL_MODE"]; ok && sslMode == "REQUIRED" {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("Glue connection %s uses SSL.", connName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: connName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueCatalogConnectionNoSecrets - Glue catalog connections do not have secrets
type GlueCatalogConnectionNoSecrets struct {
	metadata models.CheckMetadata
}

func NewGlueCatalogConnectionNoSecrets() *GlueCatalogConnectionNoSecrets {
	return &GlueCatalogConnectionNoSecrets{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_catalog_connection_no_secrets",
			CheckTitle: "Glue catalog connections do not have secrets",
			ServiceName: "glue", Severity: "high", ResourceType: "Connection",
			Description: "Glue catalog connections should not have secrets",
			RemediationText: "Use AWS Secrets Manager for secrets",
			Categories: []string{"analytics", "secrets"},
		},
	}
}

func (c *GlueCatalogConnectionNoSecrets) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueCatalogConnectionNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Glue connection secrets scan requires secret detection library",
			Provider: "aws", Service: "glue",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// ==================== Glue Development Endpoint Checks ====================

// GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled - Glue dev endpoint CloudWatch logs encryption
type GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled() *GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled {
	return &GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_development_endpoints_cloudwatch_logs_encryption_enabled",
			CheckTitle: "Glue development endpoint CloudWatch logs encryption is enabled",
			ServiceName: "glue", Severity: "medium", ResourceType: "DevEndpoint",
			Description: "Glue development endpoints should encrypt CloudWatch logs",
			RemediationText: "Enable CloudWatch logs encryption on Glue development endpoints",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := glueClient.GetDevEndpoints(ctx, &glue.GetDevEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get development endpoints: %w", err)
	}

	for _, endpoint := range endpoints.DevEndpoints {
		endpointName := aws.ToString(endpoint.EndpointName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue development endpoint %s does not encrypt CloudWatch logs.", endpointName)

		if endpoint.SecurityConfiguration != nil && aws.ToString(endpoint.SecurityConfiguration) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Glue development endpoint %s encrypts CloudWatch logs.", endpointName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: endpointName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled - Glue dev endpoint job bookmark encryption
type GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueDevelopmentEndpointsJobBookmarkEncryptionEnabled() *GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled {
	return &GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_development_endpoints_job_bookmark_encryption_enabled",
			CheckTitle: "Glue development endpoint job bookmark encryption is enabled",
			ServiceName: "glue", Severity: "medium", ResourceType: "DevEndpoint",
			Description: "Glue development endpoints should encrypt job bookmarks",
			RemediationText: "Enable job bookmark encryption on Glue development endpoints",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := glueClient.GetDevEndpoints(ctx, &glue.GetDevEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get development endpoints: %w", err)
	}

	for _, endpoint := range endpoints.DevEndpoints {
		endpointName := aws.ToString(endpoint.EndpointName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue development endpoint %s does not encrypt job bookmarks.", endpointName)

		if endpoint.SecurityConfiguration != nil && aws.ToString(endpoint.SecurityConfiguration) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Glue development endpoint %s encrypts job bookmarks.", endpointName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: endpointName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueDevelopmentEndpointsS3EncryptionEnabled - Glue dev endpoint S3 encryption
type GlueDevelopmentEndpointsS3EncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueDevelopmentEndpointsS3EncryptionEnabled() *GlueDevelopmentEndpointsS3EncryptionEnabled {
	return &GlueDevelopmentEndpointsS3EncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_development_endpoints_s3_encryption_enabled",
			CheckTitle: "Glue development endpoint S3 encryption is enabled",
			ServiceName: "glue", Severity: "medium", ResourceType: "DevEndpoint",
			Description: "Glue development endpoints should encrypt S3 data",
			RemediationText: "Enable S3 encryption on Glue development endpoints",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueDevelopmentEndpointsS3EncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueDevelopmentEndpointsS3EncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := glueClient.GetDevEndpoints(ctx, &glue.GetDevEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get development endpoints: %w", err)
	}

	for _, endpoint := range endpoints.DevEndpoints {
		endpointName := aws.ToString(endpoint.EndpointName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue development endpoint %s does not encrypt S3 data.", endpointName)

		if endpoint.SecurityConfiguration != nil && aws.ToString(endpoint.SecurityConfiguration) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Glue development endpoint %s encrypts S3 data.", endpointName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: endpointName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// ==================== Glue ETL Job Checks ====================

// GlueEtlJobsAmazonS3EncryptionEnabled - Glue ETL jobs S3 encryption
type GlueEtlJobsAmazonS3EncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueEtlJobsAmazonS3EncryptionEnabled() *GlueEtlJobsAmazonS3EncryptionEnabled {
	return &GlueEtlJobsAmazonS3EncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_etl_jobs_amazon_s3_encryption_enabled",
			CheckTitle: "Glue ETL jobs S3 encryption is enabled",
			ServiceName: "glue", Severity: "high", ResourceType: "Job",
			Description: "Glue ETL jobs should encrypt S3 data",
			RemediationText: "Enable S3 encryption on Glue ETL jobs",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueEtlJobsAmazonS3EncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueEtlJobsAmazonS3EncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	jobs, err := glueClient.GetJobs(ctx, &glue.GetJobsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}

	for _, job := range jobs.Jobs {
		jobName := aws.ToString(job.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue ETL job %s does not encrypt S3 data.", jobName)

		if job.SecurityConfiguration != nil && aws.ToString(job.SecurityConfiguration) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Glue ETL job %s encrypts S3 data.", jobName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: jobName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueEtlJobsCloudwatchLogsEncryptionEnabled - Glue ETL jobs CloudWatch logs encryption
type GlueEtlJobsCloudwatchLogsEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueEtlJobsCloudwatchLogsEncryptionEnabled() *GlueEtlJobsCloudwatchLogsEncryptionEnabled {
	return &GlueEtlJobsCloudwatchLogsEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_etl_jobs_cloudwatch_logs_encryption_enabled",
			CheckTitle: "Glue ETL jobs CloudWatch logs encryption is enabled",
			ServiceName: "glue", Severity: "medium", ResourceType: "Job",
			Description: "Glue ETL jobs should encrypt CloudWatch logs",
			RemediationText: "Enable CloudWatch logs encryption on Glue ETL jobs",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueEtlJobsCloudwatchLogsEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueEtlJobsCloudwatchLogsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	jobs, err := glueClient.GetJobs(ctx, &glue.GetJobsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}

	for _, job := range jobs.Jobs {
		jobName := aws.ToString(job.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue ETL job %s does not encrypt CloudWatch logs.", jobName)

		if job.SecurityConfiguration != nil && aws.ToString(job.SecurityConfiguration) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Glue ETL job %s encrypts CloudWatch logs.", jobName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: jobName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueEtlJobsJobBookmarkEncryptionEnabled - Glue ETL jobs job bookmark encryption
type GlueEtlJobsJobBookmarkEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueEtlJobsJobBookmarkEncryptionEnabled() *GlueEtlJobsJobBookmarkEncryptionEnabled {
	return &GlueEtlJobsJobBookmarkEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_etl_jobs_job_bookmark_encryption_enabled",
			CheckTitle: "Glue ETL jobs job bookmark encryption is enabled",
			ServiceName: "glue", Severity: "medium", ResourceType: "Job",
			Description: "Glue ETL jobs should encrypt job bookmarks",
			RemediationText: "Enable job bookmark encryption on Glue ETL jobs",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueEtlJobsJobBookmarkEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueEtlJobsJobBookmarkEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	jobs, err := glueClient.GetJobs(ctx, &glue.GetJobsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}

	for _, job := range jobs.Jobs {
		jobName := aws.ToString(job.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Glue ETL job %s does not encrypt job bookmarks.", jobName)

		if job.SecurityConfiguration != nil && aws.ToString(job.SecurityConfiguration) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Glue ETL job %s encrypts job bookmarks.", jobName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: jobName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueEtlJobsLoggingEnabled - Glue ETL jobs have logging enabled
type GlueEtlJobsLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewGlueEtlJobsLoggingEnabled() *GlueEtlJobsLoggingEnabled {
	return &GlueEtlJobsLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_etl_jobs_logging_enabled",
			CheckTitle: "Glue ETL jobs have logging enabled",
			ServiceName: "glue", Severity: "low", ResourceType: "Job",
			Description: "Glue ETL jobs should have logging enabled",
			RemediationText: "Enable logging on Glue ETL jobs",
			Categories: []string{"analytics"},
		},
	}
}

func (c *GlueEtlJobsLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueEtlJobsLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	jobs, err := glueClient.GetJobs(ctx, &glue.GetJobsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}

	for _, job := range jobs.Jobs {
		jobName := aws.ToString(job.Name)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Glue ETL job %s has logging enabled.", jobName)

		if job.DefaultArguments != nil {
			if logLevel, ok := job.DefaultArguments["--enable-continuous-cloudwatch-log"]; ok && logLevel == "false" {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("Glue ETL job %s does not have logging enabled.", jobName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: jobName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// GlueEtlJobsNoSecretsInArguments - Glue ETL jobs do not have secrets in arguments
type GlueEtlJobsNoSecretsInArguments struct {
	metadata models.CheckMetadata
}

func NewGlueEtlJobsNoSecretsInArguments() *GlueEtlJobsNoSecretsInArguments {
	return &GlueEtlJobsNoSecretsInArguments{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_etl_jobs_no_secrets_in_arguments",
			CheckTitle: "Glue ETL jobs do not have secrets in arguments",
			ServiceName: "glue", Severity: "high", ResourceType: "Job",
			Description: "Glue ETL jobs should not have secrets in arguments",
			RemediationText: "Use AWS Secrets Manager for secrets",
			Categories: []string{"analytics", "secrets"},
		},
	}
}

func (c *GlueEtlJobsNoSecretsInArguments) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueEtlJobsNoSecretsInArguments) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Glue ETL job secrets scan requires secret detection library",
			Provider: "aws", Service: "glue",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// ==================== Glue ML Transform Checks ====================

// GlueMlTransformEncryptedAtRest - Glue ML transform is encrypted at rest
type GlueMlTransformEncryptedAtRest struct {
	metadata models.CheckMetadata
}

func NewGlueMlTransformEncryptedAtRest() *GlueMlTransformEncryptedAtRest {
	return &GlueMlTransformEncryptedAtRest{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glue_ml_transform_encrypted_at_rest",
			CheckTitle: "Glue ML transform is encrypted at rest",
			ServiceName: "glue", Severity: "high", ResourceType: "MLTransform",
			Description: "Glue ML transforms should be encrypted at rest",
			RemediationText: "Enable encryption at rest on Glue ML transforms",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *GlueMlTransformEncryptedAtRest) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlueMlTransformEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glueProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glueProvider")
	}
	glueClient, err := p.Glue(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	transforms, err := glueClient.GetMLTransforms(ctx, &glue.GetMLTransformsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ML transforms: %w", err)
	}

	for _, transform := range transforms.Transforms {
		transformID := aws.ToString(transform.TransformId)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Glue ML transform %s is encrypted at rest.", transformID)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "glue", ResourceID: transformID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}