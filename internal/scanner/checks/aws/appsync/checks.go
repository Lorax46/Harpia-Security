package appsync

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AppsyncGraphqlApiNoApiKeyAuthentication - AWS AppSync GraphQL API does not use API key authentication
type AppsyncGraphqlApiNoApiKeyAuthentication struct {
    metadata models.CheckMetadata
}

func NewAppsyncGraphqlApiNoApiKeyAuthentication() *AppsyncGraphqlApiNoApiKeyAuthentication {
    return &AppsyncGraphqlApiNoApiKeyAuthentication{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "appsync_graphql_api_no_api_key_authentication",
            CheckTitle: "AWS AppSync GraphQL API does not use API key authentication",
            ServiceName: "appsync",
            Severity: "high",
            Description: "**AWS AppSync GraphQL APIs** are examined for the default authorization type. The finding indicates an API configured with `API_KEY` instead of IAM, Cognito, OIDC, or Lambda authorizers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"appsync"},
        },
    }
}

func (c *AppsyncGraphqlApiNoApiKeyAuthentication) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AppsyncGraphqlApiNoApiKeyAuthentication) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "appsync",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AppsyncFieldLevelLoggingEnabled - AWS AppSync API has field-level logging set to ALL or ERROR
type AppsyncFieldLevelLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewAppsyncFieldLevelLoggingEnabled() *AppsyncFieldLevelLoggingEnabled {
    return &AppsyncFieldLevelLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "appsync_field_level_logging_enabled",
            CheckTitle: "AWS AppSync API has field-level logging set to ALL or ERROR",
            ServiceName: "appsync",
            Severity: "medium",
            Description: "**AWS AppSync GraphQL APIs** have **field-level logging** configured at the resolver level. The check looks for log levels of `ERROR` or `ALL` to confirm field resolution events are recorded.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"appsync"},
        },
    }
}

func (c *AppsyncFieldLevelLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AppsyncFieldLevelLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "appsync",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

