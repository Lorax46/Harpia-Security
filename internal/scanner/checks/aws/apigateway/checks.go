package apigateway

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// ApigatewayRestapiWafAclAttached - API Gateway stage has a WAF Web ACL attached
type ApigatewayRestapiWafAclAttached struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiWafAclAttached() *ApigatewayRestapiWafAclAttached {
    return &ApigatewayRestapiWafAclAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_waf_acl_attached",
            CheckTitle: "API Gateway stage has a WAF Web ACL attached",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "**Amazon API Gateway (REST API)** stages are assessed for an associated **AWS WAF web ACL**. The finding reflects whether a `web ACL` is linked at the stage level.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiWafAclAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiWafAclAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiPublicWithAuthorizer - API Gateway REST API with a public endpoint has an authorizer configured
type ApigatewayRestapiPublicWithAuthorizer struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiPublicWithAuthorizer() *ApigatewayRestapiPublicWithAuthorizer {
    return &ApigatewayRestapiPublicWithAuthorizer{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_public_with_authorizer",
            CheckTitle: "API Gateway REST API with a public endpoint has an authorizer configured",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "**API Gateway REST APIs** exposed to the Internet are evaluated for an attached **authorizer** that enforces caller identity (Lambda authorizer or Cognito user pool) on method invocations.  Focus is on whether public endpoints require authenticated requests rather than accepting anonymous calls.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiPublicWithAuthorizer) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiPublicWithAuthorizer) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiLoggingEnabled - API Gateway REST API stage has logging enabled
type ApigatewayRestapiLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiLoggingEnabled() *ApigatewayRestapiLoggingEnabled {
    return &ApigatewayRestapiLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_logging_enabled",
            CheckTitle: "API Gateway REST API stage has logging enabled",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "**API Gateway REST API stages** with **stage logging** enabled to emit execution or access logs to CloudWatch",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiAuthorizersEnabled - API Gateway REST API has an authorizer at API level or all methods are authorized
type ApigatewayRestapiAuthorizersEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiAuthorizersEnabled() *ApigatewayRestapiAuthorizersEnabled {
    return &ApigatewayRestapiAuthorizersEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_authorizers_enabled",
            CheckTitle: "API Gateway REST API has an authorizer at API level or all methods are authorized",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "**API Gateway REST APIs** are evaluated for **access control**: an **API-level authorizer** is present, or all resource methods use an authorization mechanism. Methods marked `NONE` indicate unauthenticated access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiAuthorizersEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiAuthorizersEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayDomainNamePqcTlsEnabled - API Gateway custom domain names use a post-quantum TLS security policy
type ApigatewayDomainNamePqcTlsEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayDomainNamePqcTlsEnabled() *ApigatewayDomainNamePqcTlsEnabled {
    return &ApigatewayDomainNamePqcTlsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_domain_name_pqc_tls_enabled",
            CheckTitle: "API Gateway custom domain names use a post-quantum TLS security policy",
            ServiceName: "apigateway",
            Severity: "low",
            Description: "**API Gateway custom domain names** for REST APIs are assessed for use of a **post-quantum (PQ) TLS security policy** such as `SecurityPolicy_TLS13_1_2_PQ_2025_09`. Custom domains with legacy policies such as `TLS_1_0` or `TLS_1_2` lack hybrid ML-KEM key exchange, leaving captured traffic vulnerable to future quantum decryption.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayDomainNamePqcTlsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayDomainNamePqcTlsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiClientCertificateEnabled - API Gateway REST API stage has client certificate enabled
type ApigatewayRestapiClientCertificateEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiClientCertificateEnabled() *ApigatewayRestapiClientCertificateEnabled {
    return &ApigatewayRestapiClientCertificateEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_client_certificate_enabled",
            CheckTitle: "API Gateway REST API stage has client certificate enabled",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "**API Gateway stage** has a **client certificate** configured so HTTP/S integrations can perform **mutual TLS** and authenticate API Gateway to the backend",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiClientCertificateEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiClientCertificateEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiPublic - API Gateway REST API endpoint is private
type ApigatewayRestapiPublic struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiPublic() *ApigatewayRestapiPublic {
    return &ApigatewayRestapiPublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_public",
            CheckTitle: "API Gateway REST API endpoint is private",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "**Amazon API Gateway REST APIs** are evaluated for endpoint exposure: **internet-accessible** endpoints versus **private VPC-only** access via interface VPC endpoints (`AWS PrivateLink`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiPublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiCacheEncrypted - API Gateway REST API stage cache data is encrypted at rest
type ApigatewayRestapiCacheEncrypted struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiCacheEncrypted() *ApigatewayRestapiCacheEncrypted {
    return &ApigatewayRestapiCacheEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_cache_encrypted",
            CheckTitle: "API Gateway REST API stage cache data is encrypted at rest",
            ServiceName: "apigateway",
            Severity: "medium",
            Description: "API Gateway REST API stages with caching have **cache data encrypted at rest**. The evaluation targets stages where caching is enabled and verifies that stored responses are protected via the `Encrypt cache data` setting.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiCacheEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiCacheEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiTracingEnabled - API Gateway REST API stage has X-Ray tracing enabled
type ApigatewayRestapiTracingEnabled struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiTracingEnabled() *ApigatewayRestapiTracingEnabled {
    return &ApigatewayRestapiTracingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_tracing_enabled",
            CheckTitle: "API Gateway REST API stage has X-Ray tracing enabled",
            ServiceName: "apigateway",
            Severity: "low",
            Description: "**API Gateway REST API stages** have **AWS X-Ray active tracing** enabled to sample incoming requests and produce distributed traces across connected services.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiTracingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiTracingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ApigatewayRestapiNoSecretsInStageVariables - API Gateway REST API stage variables should not contain secrets
type ApigatewayRestapiNoSecretsInStageVariables struct {
    metadata models.CheckMetadata
}

func NewApigatewayRestapiNoSecretsInStageVariables() *ApigatewayRestapiNoSecretsInStageVariables {
    return &ApigatewayRestapiNoSecretsInStageVariables{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "apigateway_restapi_no_secrets_in_stage_variables",
            CheckTitle: "API Gateway REST API stage variables should not contain secrets",
            ServiceName: "apigateway",
            Severity: "high",
            Description: "Checks API Gateway REST API stage variables for hardcoded secrets such as passwords, API keys, and tokens. Stage variables should reference AWS Secrets Manager or Parameter Store rather than containing plaintext credentials.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"apigateway"},
        },
    }
}

func (c *ApigatewayRestapiNoSecretsInStageVariables) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ApigatewayRestapiNoSecretsInStageVariables) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "apigateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

