package codebuild

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CodebuildProjectS3LogsEncrypted - CodeBuild project S3 logs are encrypted at rest
type CodebuildProjectS3LogsEncrypted struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectS3LogsEncrypted() *CodebuildProjectS3LogsEncrypted {
    return &CodebuildProjectS3LogsEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_s3_logs_encrypted",
            CheckTitle: "CodeBuild project S3 logs are encrypted at rest",
            ServiceName: "codebuild",
            Severity: "low",
            Description: "**CodeBuild projects** with **S3 log delivery** are evaluated for **encryption at rest** on their S3 log objects. Only projects that write logs to S3 are in scope.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectS3LogsEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectS3LogsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectLoggingEnabled - CodeBuild project has CloudWatch Logs or S3 logging enabled
type CodebuildProjectLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectLoggingEnabled() *CodebuildProjectLoggingEnabled {
    return &CodebuildProjectLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_logging_enabled",
            CheckTitle: "CodeBuild project has CloudWatch Logs or S3 logging enabled",
            ServiceName: "codebuild",
            Severity: "medium",
            Description: "**CodeBuild projects** are assessed for **logging configuration** to Amazon **CloudWatch Logs** or **S3**, identifying when at least one destination is `enabled` for build logs and events.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectOlder90Days - CodeBuild project has been invoked in the last 90 days
type CodebuildProjectOlder90Days struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectOlder90Days() *CodebuildProjectOlder90Days {
    return &CodebuildProjectOlder90Days{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_older_90_days",
            CheckTitle: "CodeBuild project has been invoked in the last 90 days",
            ServiceName: "codebuild",
            Severity: "medium",
            Description: "**AWS CodeBuild projects** are assessed for recent activity using the last build invocation timestamp. Projects not invoked within `90 days` or never built are treated as **inactive**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectOlder90Days) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectOlder90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectSourceRepoUrlNoSensitiveCredentials - CodeBuild project source repository URLs do not contain sensitive credentials
type CodebuildProjectSourceRepoUrlNoSensitiveCredentials struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectSourceRepoUrlNoSensitiveCredentials() *CodebuildProjectSourceRepoUrlNoSensitiveCredentials {
    return &CodebuildProjectSourceRepoUrlNoSensitiveCredentials{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_source_repo_url_no_sensitive_credentials",
            CheckTitle: "CodeBuild project source repository URLs do not contain sensitive credentials",
            ServiceName: "codebuild",
            Severity: "critical",
            Description: "**AWS CodeBuild projects** with **Bitbucket sources** are assessed to confirm repository URLs do not embed credentials (for example, `x-token-auth:<token>@` or `user:password@`). The assessment includes both the primary source and all secondary sources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectSourceRepoUrlNoSensitiveCredentials) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectSourceRepoUrlNoSensitiveCredentials) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildReportGroupExportEncrypted - CodeBuild report group exports to S3 are encrypted at rest
type CodebuildReportGroupExportEncrypted struct {
    metadata models.CheckMetadata
}

func NewCodebuildReportGroupExportEncrypted() *CodebuildReportGroupExportEncrypted {
    return &CodebuildReportGroupExportEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_report_group_export_encrypted",
            CheckTitle: "CodeBuild report group exports to S3 are encrypted at rest",
            ServiceName: "codebuild",
            Severity: "medium",
            Description: "**CodeBuild report groups** with export type `S3` are evaluated to confirm their exported test results are encrypted at rest with a **KMS key**.  Report groups configured with `NO_EXPORT` are out of scope.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildReportGroupExportEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildReportGroupExportEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectNotPubliclyAccessible - CodeBuild project visibility is private
type CodebuildProjectNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectNotPubliclyAccessible() *CodebuildProjectNotPubliclyAccessible {
    return &CodebuildProjectNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_not_publicly_accessible",
            CheckTitle: "CodeBuild project visibility is private",
            ServiceName: "codebuild",
            Severity: "high",
            Description: "**AWS CodeBuild project visibility** is assessed to identify projects exposed to the public. Projects with `project_visibility` set to `PUBLIC_READ` (or not `PRIVATE`) allow anyone to access build results, logs, and artifacts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectUsesAllowedGithubOrganizations - CodeBuild project using GitHub uses an allowed GitHub organization
type CodebuildProjectUsesAllowedGithubOrganizations struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectUsesAllowedGithubOrganizations() *CodebuildProjectUsesAllowedGithubOrganizations {
    return &CodebuildProjectUsesAllowedGithubOrganizations{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_uses_allowed_github_organizations",
            CheckTitle: "CodeBuild project using GitHub uses an allowed GitHub organization",
            ServiceName: "codebuild",
            Severity: "high",
            Description: "**CodeBuild projects** sourcing from **GitHub/GitHub Enterprise** with a service role that trusts CodeBuild are evaluated by deriving the repository's organization from its URL and comparing it to an **allowed organizations** list.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectUsesAllowedGithubOrganizations) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectUsesAllowedGithubOrganizations) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectNoSecretsInVariables - CodeBuild project has no sensitive credentials in plaintext environment variables
type CodebuildProjectNoSecretsInVariables struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectNoSecretsInVariables() *CodebuildProjectNoSecretsInVariables {
    return &CodebuildProjectNoSecretsInVariables{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_no_secrets_in_variables",
            CheckTitle: "CodeBuild project has no sensitive credentials in plaintext environment variables",
            ServiceName: "codebuild",
            Severity: "critical",
            Description: "**AWS CodeBuild projects** are inspected for **plaintext environment variables** (`PLAINTEXT`) that resemble **secrets** (keys, tokens, passwords).  Such values indicate sensitive data is stored directly in environment variables instead of being sourced securely.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectNoSecretsInVariables) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectNoSecretsInVariables) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectWebhookFiltersUseAnchoredPatterns - CodeBuild project webhook filters use anchored regex patterns
type CodebuildProjectWebhookFiltersUseAnchoredPatterns struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectWebhookFiltersUseAnchoredPatterns() *CodebuildProjectWebhookFiltersUseAnchoredPatterns {
    return &CodebuildProjectWebhookFiltersUseAnchoredPatterns{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_webhook_filters_use_anchored_patterns",
            CheckTitle: "CodeBuild project webhook filters use anchored regex patterns",
            ServiceName: "codebuild",
            Severity: "high",
            Description: "AWS CodeBuild webhook filters using `ACTOR_ACCOUNT_ID`, `HEAD_REF`, or `BASE_REF` have regex patterns anchored with `^` (start) and `$` (end) to enforce exact matching and prevent substring bypass attacks.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectWebhookFiltersUseAnchoredPatterns) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectWebhookFiltersUseAnchoredPatterns) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CodebuildProjectUserControlledBuildspec - CodeBuild project does not use a user-controlled buildspec file
type CodebuildProjectUserControlledBuildspec struct {
    metadata models.CheckMetadata
}

func NewCodebuildProjectUserControlledBuildspec() *CodebuildProjectUserControlledBuildspec {
    return &CodebuildProjectUserControlledBuildspec{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codebuild_project_user_controlled_buildspec",
            CheckTitle: "CodeBuild project does not use a user-controlled buildspec file",
            ServiceName: "codebuild",
            Severity: "medium",
            Description: "AWS CodeBuild projects are evaluated for use of a **user-controlled buildspec**, identified when the project references a repository file like `*.yml` or `*.yaml`. Projects using non file-based build instructions are treated as centrally managed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codebuild"},
        },
    }
}

func (c *CodebuildProjectUserControlledBuildspec) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodebuildProjectUserControlledBuildspec) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codebuild",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

