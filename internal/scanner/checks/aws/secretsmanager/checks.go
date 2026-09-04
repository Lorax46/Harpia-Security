package secretsmanager

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// SecretsmanagerSecretRotatedPeriodically - AWS Secrets Manager secret is rotated within the configured maximum number of days
type SecretsmanagerSecretRotatedPeriodically struct {
    metadata models.CheckMetadata
}

func NewSecretsmanagerSecretRotatedPeriodically() *SecretsmanagerSecretRotatedPeriodically {
    return &SecretsmanagerSecretRotatedPeriodically{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "secretsmanager_secret_rotated_periodically",
            CheckTitle: "AWS Secrets Manager secret is rotated within the configured maximum number of days",
            ServiceName: "secretsmanager",
            Severity: "medium",
            Description: "**AWS Secrets Manager secrets** are evaluated for **periodic rotation** within a configured window (default `90` days).  Secrets with no recorded rotation, or with rotation older than the allowed window, are identified for review.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"secretsmanager"},
        },
    }
}

func (c *SecretsmanagerSecretRotatedPeriodically) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecretsmanagerSecretRotatedPeriodically) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "secretsmanager",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SecretsmanagerSecretUnused - Secrets Manager secret has been accessed within the last 90 days
type SecretsmanagerSecretUnused struct {
    metadata models.CheckMetadata
}

func NewSecretsmanagerSecretUnused() *SecretsmanagerSecretUnused {
    return &SecretsmanagerSecretUnused{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "secretsmanager_secret_unused",
            CheckTitle: "Secrets Manager secret has been accessed within the last 90 days",
            ServiceName: "secretsmanager",
            Severity: "medium",
            Description: "**AWS Secrets Manager secrets** with no retrieval activity beyond a configured window (default `90` days) are identified as **unused** based on their most recent access timestamp",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"secretsmanager"},
        },
    }
}

func (c *SecretsmanagerSecretUnused) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecretsmanagerSecretUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "secretsmanager",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SecretsmanagerAutomaticRotationEnabled - Secrets Manager secret has rotation enabled
type SecretsmanagerAutomaticRotationEnabled struct {
    metadata models.CheckMetadata
}

func NewSecretsmanagerAutomaticRotationEnabled() *SecretsmanagerAutomaticRotationEnabled {
    return &SecretsmanagerAutomaticRotationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "secretsmanager_automatic_rotation_enabled",
            CheckTitle: "Secrets Manager secret has rotation enabled",
            ServiceName: "secretsmanager",
            Severity: "high",
            Description: "**AWS Secrets Manager secrets** are evaluated for **automatic rotation**; the check determines if a rotation schedule is enabled for each secret",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"secretsmanager"},
        },
    }
}

func (c *SecretsmanagerAutomaticRotationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecretsmanagerAutomaticRotationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "secretsmanager",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SecretsmanagerNotPubliclyAccessible - Secrets Manager secret resource policy does not allow public access
type SecretsmanagerNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewSecretsmanagerNotPubliclyAccessible() *SecretsmanagerNotPubliclyAccessible {
    return &SecretsmanagerNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "secretsmanager_not_publicly_accessible",
            CheckTitle: "Secrets Manager secret resource policy does not allow public access",
            ServiceName: "secretsmanager",
            Severity: "high",
            Description: "**AWS Secrets Manager secrets** are evaluated for **public exposure** through resource-based policies that grant broad access, such as `Principal: '*'`, which would allow any principal to perform actions on the secret.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"secretsmanager"},
        },
    }
}

func (c *SecretsmanagerNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecretsmanagerNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "secretsmanager",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SecretsmanagerHasRestrictiveResourcePolicy - Secrets Manager secret has a restrictive resource-based policy
type SecretsmanagerHasRestrictiveResourcePolicy struct {
    metadata models.CheckMetadata
}

func NewSecretsmanagerHasRestrictiveResourcePolicy() *SecretsmanagerHasRestrictiveResourcePolicy {
    return &SecretsmanagerHasRestrictiveResourcePolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "secretsmanager_has_restrictive_resource_policy",
            CheckTitle: "Secrets Manager secret has a restrictive resource-based policy",
            ServiceName: "secretsmanager",
            Severity: "high",
            Description: "**Secrets Manager secrets** are evaluated for **restrictive resource-based policies**: explicit **Deny** for unauthorized principals, **Organization** boundary via `PrincipalOrgID`, `aws:SourceAccount` for service access. Per-principal **NotAction** restrictions are optional (defense-in-depth). Regionalized service principals are supported.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"secretsmanager"},
        },
    }
}

func (c *SecretsmanagerHasRestrictiveResourcePolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SecretsmanagerHasRestrictiveResourcePolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "secretsmanager",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

