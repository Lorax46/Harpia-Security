package apigatewayv2

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Apigatewayv2ApiAccessLoggingEnabled - API Gateway V2 API stage has access logging enabled
type Apigatewayv2ApiAccessLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayv2ApiAccessLoggingEnabled() *Apigatewayv2ApiAccessLoggingEnabled {
    return &Apigatewayv2ApiAccessLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigatewayv2_api_access_logging_enabled",
            CheckTitle: "API Gateway V2 API stage has access logging enabled",
            ServiceName: "apigatewayv2",
            Severity: "medium",
            Description: "**API Gateway v2** stages have **access logging** configured to capture request details and deliver them to a logging destination (e.g., CloudWatch Logs or Firehose). The evaluation looks for logging being enabled at each API stage.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigatewayv2"},
        },
    }
}

func (c *Apigatewayv2ApiAccessLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Apigatewayv2ApiAccessLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigatewayv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Apigatewayv2ApiAuthorizersEnabled - API Gateway V2 API has an authorizer configured
type Apigatewayv2ApiAuthorizersEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayv2ApiAuthorizersEnabled() *Apigatewayv2ApiAuthorizersEnabled {
    return &Apigatewayv2ApiAuthorizersEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigatewayv2_api_authorizers_enabled",
            CheckTitle: "API Gateway V2 API has an authorizer configured",
            ServiceName: "apigatewayv2",
            Severity: "medium",
            Description: "**API Gateway v2 APIs** use **authorizers** (JWT/Cognito or Lambda) to authenticate requests. This evaluates whether an API has an authorizer configured to control access to its routes.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigatewayv2"},
        },
    }
}

func (c *Apigatewayv2ApiAuthorizersEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Apigatewayv2ApiAuthorizersEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigatewayv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

