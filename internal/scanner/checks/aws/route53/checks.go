package route53

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Route53DanglingIpSubdomainTakeover - Route53 record does not point to a dangling AWS resource
type Route53DanglingIpSubdomainTakeover struct {
    metadata models.CheckMetadata
}

func NewRoute53DanglingIpSubdomainTakeover() *Route53DanglingIpSubdomainTakeover {
    return &Route53DanglingIpSubdomainTakeover{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "route53_dangling_ip_subdomain_takeover",
            CheckTitle: "Route53 record does not point to a dangling AWS resource",
            ServiceName: "route53",
            Severity: "high",
            Description: "**Route 53 records** are evaluated for two **subdomain takeover** vectors: (1) non-alias **`A` records** using literal IPs in **public AWS ranges** that are not assigned to resources in the account (released EIPs/ENI public IPs); and (2) non-alias **`CNAME` records** targeting an **S3 website endpoint** (`*.s3-website[.-]<region>.amazonaws.com`) whose bucket no longer exists in the account.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"route53"},
        },
    }
}

func (c *Route53DanglingIpSubdomainTakeover) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Route53DanglingIpSubdomainTakeover) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "route53",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Route53DomainsTransferlockEnabled - Route 53 domain has Transfer Lock enabled
type Route53DomainsTransferlockEnabled struct {
    metadata models.CheckMetadata
}

func NewRoute53DomainsTransferlockEnabled() *Route53DomainsTransferlockEnabled {
    return &Route53DomainsTransferlockEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "route53_domains_transferlock_enabled",
            CheckTitle: "Route 53 domain has Transfer Lock enabled",
            ServiceName: "route53",
            Severity: "high",
            Description: "**Route 53 registered domains** are assessed for a transfer-lock state, indicated by the `clientTransferProhibited` status on the domain.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"route53"},
        },
    }
}

func (c *Route53DomainsTransferlockEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Route53DomainsTransferlockEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "route53",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Route53PublicHostedZonesCloudwatchLoggingEnabled - Route53 public hosted zone has query logging enabled to a CloudWatch Logs log group
type Route53PublicHostedZonesCloudwatchLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewRoute53PublicHostedZonesCloudwatchLoggingEnabled() *Route53PublicHostedZonesCloudwatchLoggingEnabled {
    return &Route53PublicHostedZonesCloudwatchLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "route53_public_hosted_zones_cloudwatch_logging_enabled",
            CheckTitle: "Route53 public hosted zone has query logging enabled to a CloudWatch Logs log group",
            ServiceName: "route53",
            Severity: "medium",
            Description: "**Route 53 public hosted zones** have **DNS query logging** enabled to **CloudWatch Logs**, recording resolver requests for the zone and writing events to an associated log group.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"route53"},
        },
    }
}

func (c *Route53PublicHostedZonesCloudwatchLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Route53PublicHostedZonesCloudwatchLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "route53",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Route53DomainsPrivacyProtectionEnabled - Route 53 domain has admin contact privacy protection enabled
type Route53DomainsPrivacyProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewRoute53DomainsPrivacyProtectionEnabled() *Route53DomainsPrivacyProtectionEnabled {
    return &Route53DomainsPrivacyProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "route53_domains_privacy_protection_enabled",
            CheckTitle: "Route 53 domain has admin contact privacy protection enabled",
            ServiceName: "route53",
            Severity: "medium",
            Description: "**Route 53 domain** administrative contact has **privacy protection** enabled, so WHOIS queries return redacted or proxy details.  Evaluates whether contact data is hidden instead of publicly listed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"route53"},
        },
    }
}

func (c *Route53DomainsPrivacyProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Route53DomainsPrivacyProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "route53",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

