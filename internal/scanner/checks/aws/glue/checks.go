package glue

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// GlueCatalogConnectionNoSecrets - Glue Data Catalog connection has no secrets in connection properties
type GlueCatalogConnectionNoSecrets struct {
    metadata models.CheckMetadata
}

func NewGlueCatalogConnectionNoSecrets() *GlueCatalogConnectionNoSecrets {
    return &GlueCatalogConnectionNoSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_catalog_connection_no_secrets",
            CheckTitle: "Glue Data Catalog connection has no secrets in connection properties",
            ServiceName: "glue",
            Severity: "high",
            Description: "**AWS Glue Data Catalog connections** are inspected for **ConnectionProperties** values that resemble **secrets** (keys, tokens, passwords).  Such values indicate sensitive data is stored directly in connection configuration instead of being sourced securely from AWS Secrets Manager or Systems Manager Parameter Store.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueCatalogConnectionNoSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueCatalogConnectionNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueEtlJobsNoSecretsInArguments - Glue ETL job has no secrets in default arguments
type GlueEtlJobsNoSecretsInArguments struct {
    metadata models.CheckMetadata
}

func NewGlueEtlJobsNoSecretsInArguments() *GlueEtlJobsNoSecretsInArguments {
    return &GlueEtlJobsNoSecretsInArguments{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_etl_jobs_no_secrets_in_arguments",
            CheckTitle: "Glue ETL job has no secrets in default arguments",
            ServiceName: "glue",
            Severity: "critical",
            Description: "**AWS Glue ETL jobs** are inspected for **default arguments** (`DefaultArguments`) that resemble **secrets** (keys, tokens, passwords).  Such values indicate sensitive data is stored directly in job arguments instead of being sourced securely from AWS Secrets Manager or Systems Manager Parameter Store.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueEtlJobsNoSecretsInArguments) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueEtlJobsNoSecretsInArguments) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled - Glue development endpoint has CloudWatch Logs encryption enabled
type GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled() *GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled {
    return &GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_development_endpoints_cloudwatch_logs_encryption_enabled",
            CheckTitle: "Glue development endpoint has CloudWatch Logs encryption enabled",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue development endpoints** are assessed for an associated **security configuration** that enables **CloudWatch Logs encryption**. It confirms the endpoint references a configuration and that log encryption is not `DISABLED`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDataCatalogsMetadataEncryptionEnabled - Glue Data Catalog metadata is encrypted with KMS
type GlueDataCatalogsMetadataEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueDataCatalogsMetadataEncryptionEnabled() *GlueDataCatalogsMetadataEncryptionEnabled {
    return &GlueDataCatalogsMetadataEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_data_catalogs_metadata_encryption_enabled",
            CheckTitle: "Glue Data Catalog metadata is encrypted with KMS",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue Data Catalog** metadata is encrypted at rest when catalog settings use **SSE-KMS** with a KMS key.  Catalogs that do not configure `SSE-KMS` for metadata are considered unencrypted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDataCatalogsMetadataEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDataCatalogsMetadataEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueEtlJobsAmazonS3EncryptionEnabled - Glue job has S3 encryption enabled
type GlueEtlJobsAmazonS3EncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueEtlJobsAmazonS3EncryptionEnabled() *GlueEtlJobsAmazonS3EncryptionEnabled {
    return &GlueEtlJobsAmazonS3EncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_etl_jobs_amazon_s3_encryption_enabled",
            CheckTitle: "Glue job has S3 encryption enabled",
            ServiceName: "glue",
            Severity: "high",
            Description: "**AWS Glue ETL jobs** are validated to use **Amazon S3 at-rest encryption** (`SSE-S3` or `SSE-KMS`) when writing outputs, either through an attached security configuration or via job arguments. Jobs missing a security configuration or with S3 encryption disabled are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueEtlJobsAmazonS3EncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueEtlJobsAmazonS3EncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled - Glue development endpoint has Job Bookmark encryption enabled
type GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueDevelopmentEndpointsJobBookmarkEncryptionEnabled() *GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled {
    return &GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_development_endpoints_job_bookmark_encryption_enabled",
            CheckTitle: "Glue development endpoint has Job Bookmark encryption enabled",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue development endpoints** are assessed for an attached **security configuration** where **job bookmark encryption** is enabled. Endpoints lacking a security configuration are also identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDevelopmentEndpointsJobBookmarkEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueEtlJobsCloudwatchLogsEncryptionEnabled - Glue ETL job has CloudWatch Logs encryption enabled
type GlueEtlJobsCloudwatchLogsEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueEtlJobsCloudwatchLogsEncryptionEnabled() *GlueEtlJobsCloudwatchLogsEncryptionEnabled {
    return &GlueEtlJobsCloudwatchLogsEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_etl_jobs_cloudwatch_logs_encryption_enabled",
            CheckTitle: "Glue ETL job has CloudWatch Logs encryption enabled",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue ETL jobs** are evaluated for a **security configuration** with **CloudWatch Logs encryption** (`SSE-KMS`) enabled. Jobs without a security configuration, or with CloudWatch Logs encryption set to `DISABLED`, are highlighted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueEtlJobsCloudwatchLogsEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueEtlJobsCloudwatchLogsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDevelopmentEndpointsS3EncryptionEnabled - Glue development endpoint has S3 encryption enabled
type GlueDevelopmentEndpointsS3EncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueDevelopmentEndpointsS3EncryptionEnabled() *GlueDevelopmentEndpointsS3EncryptionEnabled {
    return &GlueDevelopmentEndpointsS3EncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_development_endpoints_s3_encryption_enabled",
            CheckTitle: "Glue development endpoint has S3 encryption enabled",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue development endpoints** are evaluated for an attached **security configuration** with **S3 encryption**. Endpoints lacking a security configuration, or with `s3_encryption` set to `DISABLED`, are flagged by this check.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDevelopmentEndpointsS3EncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDevelopmentEndpointsS3EncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDataCatalogsConnectionPasswordsEncryptionEnabled - Glue data catalog connection password is encrypted with a KMS key
type GlueDataCatalogsConnectionPasswordsEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueDataCatalogsConnectionPasswordsEncryptionEnabled() *GlueDataCatalogsConnectionPasswordsEncryptionEnabled {
    return &GlueDataCatalogsConnectionPasswordsEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_data_catalogs_connection_passwords_encryption_enabled",
            CheckTitle: "Glue data catalog connection password is encrypted with a KMS key",
            ServiceName: "glue",
            Severity: "high",
            Description: "**AWS Glue Data Catalog** settings for **connection password encryption** are evaluated to confirm an AWS KMS key is configured to encrypt passwords stored in connection properties.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDataCatalogsConnectionPasswordsEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDataCatalogsConnectionPasswordsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueEtlJobsJobBookmarkEncryptionEnabled - Glue ETL job has Job bookmark encryption enabled
type GlueEtlJobsJobBookmarkEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueEtlJobsJobBookmarkEncryptionEnabled() *GlueEtlJobsJobBookmarkEncryptionEnabled {
    return &GlueEtlJobsJobBookmarkEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_etl_jobs_job_bookmark_encryption_enabled",
            CheckTitle: "Glue ETL job has Job bookmark encryption enabled",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue ETL jobs** should link a **security configuration** with **job bookmark encryption** enabled. Bookmark encryption must not be `DISABLED` (e.g., use `CSE-KMS`). Jobs lacking a security configuration are treated as not protecting bookmark metadata.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueEtlJobsJobBookmarkEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueEtlJobsJobBookmarkEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueEtlJobsLoggingEnabled - Glue ETL job has continuous CloudWatch logging enabled
type GlueEtlJobsLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueEtlJobsLoggingEnabled() *GlueEtlJobsLoggingEnabled {
    return &GlueEtlJobsLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_etl_jobs_logging_enabled",
            CheckTitle: "Glue ETL job has continuous CloudWatch logging enabled",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue jobs** are assessed for **continuous CloudWatch logging**, confirming that runtime events and outputs are sent to **CloudWatch Logs** via the `--enable-continuous-cloudwatch-log` configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueEtlJobsLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueEtlJobsLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDatabaseConnectionsSslEnabled - Glue connection has SSL enabled
type GlueDatabaseConnectionsSslEnabled struct {
    metadata models.CheckMetadata
}

func NewGlueDatabaseConnectionsSslEnabled() *GlueDatabaseConnectionsSslEnabled {
    return &GlueDatabaseConnectionsSslEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_database_connections_ssl_enabled",
            CheckTitle: "Glue connection has SSL enabled",
            ServiceName: "glue",
            Severity: "high",
            Description: "**AWS Glue connections** require **TLS/SSL** for JDBC when the `JDBC_ENFORCE_SSL` property is set to `true`.  This evaluates connection definitions to confirm SSL is enforced for traffic to external data stores.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDatabaseConnectionsSslEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDatabaseConnectionsSslEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueDataCatalogsNotPubliclyAccessible - Glue Data Catalog is not publicly accessible via its resource policy
type GlueDataCatalogsNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewGlueDataCatalogsNotPubliclyAccessible() *GlueDataCatalogsNotPubliclyAccessible {
    return &GlueDataCatalogsNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_data_catalogs_not_publicly_accessible",
            CheckTitle: "Glue Data Catalog is not publicly accessible via its resource policy",
            ServiceName: "glue",
            Severity: "high",
            Description: "**AWS Glue Data Catalog** resource policies are assessed for configurations that expose the catalog to anyone, such as `Principal: *`, broad resource scopes, or permissive conditions.  The finding highlights catalogs made public through overly permissive resource-based access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueDataCatalogsNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueDataCatalogsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GlueMlTransformEncryptedAtRest - Glue ML Transform is encrypted at rest
type GlueMlTransformEncryptedAtRest struct {
    metadata models.CheckMetadata
}

func NewGlueMlTransformEncryptedAtRest() *GlueMlTransformEncryptedAtRest {
    return &GlueMlTransformEncryptedAtRest{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "glue_ml_transform_encrypted_at_rest",
            CheckTitle: "Glue ML Transform is encrypted at rest",
            ServiceName: "glue",
            Severity: "medium",
            Description: "**AWS Glue ML transforms** are evaluated for **encryption at rest** of transform user data using **KMS keys**. The finding highlights transforms where encryption is not configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"glue"},
        },
    }
}

func (c *GlueMlTransformEncryptedAtRest) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GlueMlTransformEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "glue",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

