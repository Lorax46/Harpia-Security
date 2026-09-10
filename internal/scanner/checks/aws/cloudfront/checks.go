package cloudfront

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CloudfrontDistributionsGeoRestrictionsEnabled - CloudFront distribution has Geo restrictions enabled
type CloudfrontDistributionsGeoRestrictionsEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsGeoRestrictionsEnabled() *CloudfrontDistributionsGeoRestrictionsEnabled {
    return &CloudfrontDistributionsGeoRestrictionsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_geo_restrictions_enabled",
            CheckTitle: "CloudFront distribution has Geo restrictions enabled",
            ServiceName: "cloudfront",
            Severity: "low",
            Description: "**CloudFront distributions** have **geographic restrictions** configured to limit access by country using an allowlist or blocklist (`RestrictionType` not `none`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsGeoRestrictionsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsGeoRestrictionsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsHttpsEnabled - CloudFront distribution has viewer protocol policy set to HTTPS only or redirect to HTTPS
type CloudfrontDistributionsHttpsEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsHttpsEnabled() *CloudfrontDistributionsHttpsEnabled {
    return &CloudfrontDistributionsHttpsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_https_enabled",
            CheckTitle: "CloudFront distribution has viewer protocol policy set to HTTPS only or redirect to HTTPS",
            ServiceName: "cloudfront",
            Severity: "medium",
            Description: "CloudFront distributions require viewer connections over **HTTPS** when the default cache behavior `viewer_protocol_policy` is `https-only` or `redirect-to-https`. Configurations that use `allow-all` permit HTTP.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsHttpsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsHttpsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsUsingDeprecatedSslProtocols - CloudFront distribution does not use SSLv3, TLSv1, or TLSv1.1 for origin connections
type CloudfrontDistributionsUsingDeprecatedSslProtocols struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsUsingDeprecatedSslProtocols() *CloudfrontDistributionsUsingDeprecatedSslProtocols {
    return &CloudfrontDistributionsUsingDeprecatedSslProtocols{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_using_deprecated_ssl_protocols",
            CheckTitle: "CloudFront distribution does not use SSLv3, TLSv1, or TLSv1.1 for origin connections",
            ServiceName: "cloudfront",
            Severity: "low",
            Description: "CloudFront distributions have origins whose `OriginSslProtocols` allow **deprecated SSL/TLS versions** (`SSLv3`, `TLSv1`, `TLSv1.1`) for CloudFront-to-origin HTTPS connections.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsUsingDeprecatedSslProtocols) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsUsingDeprecatedSslProtocols) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsUsingWaf - CloudFront distribution uses an AWS WAF web ACL
type CloudfrontDistributionsUsingWaf struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsUsingWaf() *CloudfrontDistributionsUsingWaf {
    return &CloudfrontDistributionsUsingWaf{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_using_waf",
            CheckTitle: "CloudFront distribution uses an AWS WAF web ACL",
            ServiceName: "cloudfront",
            Severity: "medium",
            Description: "**CloudFront distributions** are assessed for an associated **AWS WAF** web ACL that inspects and filters HTTP/S requests at the edge.  The finding highlights distributions without this web ACL association.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsUsingWaf) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsUsingWaf) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsCustomSslCertificate - CloudFront distribution uses a custom SSL/TLS certificate
type CloudfrontDistributionsCustomSslCertificate struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsCustomSslCertificate() *CloudfrontDistributionsCustomSslCertificate {
    return &CloudfrontDistributionsCustomSslCertificate{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_custom_ssl_certificate",
            CheckTitle: "CloudFront distribution uses a custom SSL/TLS certificate",
            ServiceName: "cloudfront",
            Severity: "medium",
            Description: "CloudFront distributions are configured with a **custom SSL/TLS certificate** rather than the default `*.cloudfront.net` certificate for viewer connections.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsCustomSslCertificate) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsCustomSslCertificate) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsDefaultRootObject - CloudFront distribution has a default root object configured
type CloudfrontDistributionsDefaultRootObject struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsDefaultRootObject() *CloudfrontDistributionsDefaultRootObject {
    return &CloudfrontDistributionsDefaultRootObject{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_default_root_object",
            CheckTitle: "CloudFront distribution has a default root object configured",
            ServiceName: "cloudfront",
            Severity: "high",
            Description: "CloudFront distributions are evaluated for a configured **default root object** that maps `/` requests to a specific file such as `index.html`, rather than forwarding root requests directly to the origin.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsDefaultRootObject) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsDefaultRootObject) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsLoggingEnabled - CloudFront distribution has logging enabled
type CloudfrontDistributionsLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsLoggingEnabled() *CloudfrontDistributionsLoggingEnabled {
    return &CloudfrontDistributionsLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_logging_enabled",
            CheckTitle: "CloudFront distribution has logging enabled",
            ServiceName: "cloudfront",
            Severity: "medium",
            Description: "**CloudFront distributions** record viewer requests using **standard access logs** (S3), **real-time log configurations**, or **Standard Logging v2** via CloudWatch Logs delivery sources.  The finding evaluates whether at least one logging mechanism is active so request metadata is captured for each distribution.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsPqcTlsEnabled - CloudFront distributions enforce a post-quantum TLS 1.3 security policy
type CloudfrontDistributionsPqcTlsEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsPqcTlsEnabled() *CloudfrontDistributionsPqcTlsEnabled {
    return &CloudfrontDistributionsPqcTlsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_pqc_tls_enabled",
            CheckTitle: "CloudFront distributions enforce a post-quantum TLS 1.3 security policy",
            ServiceName: "cloudfront",
            Severity: "low",
            Description: "**CloudFront distributions** are assessed for use of a **TLS 1.3-only security policy** (`TLSv1.3_2025`). CloudFront's quantum-safe key exchanges (`X25519MLKEM768`, `SecP256r1MLKEM768`) only work with TLS 1.3. Distributions that allow TLS 1.2 (or older) fallback to classical key exchanges and are exposed to `harvest-now, decrypt-later` attacks.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsPqcTlsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsPqcTlsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsOriginTrafficEncrypted - CloudFront distribution encrypts traffic to custom origins
type CloudfrontDistributionsOriginTrafficEncrypted struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsOriginTrafficEncrypted() *CloudfrontDistributionsOriginTrafficEncrypted {
    return &CloudfrontDistributionsOriginTrafficEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_origin_traffic_encrypted",
            CheckTitle: "CloudFront distribution encrypts traffic to custom origins",
            ServiceName: "cloudfront",
            Severity: "medium",
            Description: "**CloudFront distributions** are evaluated for **TLS to origins**. The check ensures custom origins use `origin_protocol_policy`=`https-only`, or `match-viewer` only when the viewer protocol policy disallows HTTP. For S3 origins, it inspects the viewer protocol policy and flags `allow-all` as permitting non-encrypted paths.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsOriginTrafficEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsOriginTrafficEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsMultipleOriginFailoverConfigured - CloudFront distribution has origin failover configured with at least two origins
type CloudfrontDistributionsMultipleOriginFailoverConfigured struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsMultipleOriginFailoverConfigured() *CloudfrontDistributionsMultipleOriginFailoverConfigured {
    return &CloudfrontDistributionsMultipleOriginFailoverConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_multiple_origin_failover_configured",
            CheckTitle: "CloudFront distribution has origin failover configured with at least two origins",
            ServiceName: "cloudfront",
            Severity: "low",
            Description: "**CloudFront distributions** are evaluated for an **origin group** configured with at least `2` origins to support automatic origin failover.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsMultipleOriginFailoverConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsMultipleOriginFailoverConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsFieldLevelEncryptionEnabled - CloudFront distribution has Field Level Encryption enabled
type CloudfrontDistributionsFieldLevelEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsFieldLevelEncryptionEnabled() *CloudfrontDistributionsFieldLevelEncryptionEnabled {
    return &CloudfrontDistributionsFieldLevelEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_field_level_encryption_enabled",
            CheckTitle: "CloudFront distribution has Field Level Encryption enabled",
            ServiceName: "cloudfront",
            Severity: "low",
            Description: "CloudFront distributions have the default cache behavior associated with **Field-Level Encryption** via `field_level_encryption_id`, targeting specified request fields for edge encryption.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsFieldLevelEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsFieldLevelEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsS3OriginAccessControl - CloudFront distribution uses Origin Access Control (OAC) for all S3 origins
type CloudfrontDistributionsS3OriginAccessControl struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsS3OriginAccessControl() *CloudfrontDistributionsS3OriginAccessControl {
    return &CloudfrontDistributionsS3OriginAccessControl{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_s3_origin_access_control",
            CheckTitle: "CloudFront distribution uses Origin Access Control (OAC) for all S3 origins",
            ServiceName: "cloudfront",
            Severity: "medium",
            Description: "**CloudFront distributions** with **Amazon S3 origins** are expected to use **Origin Access Control** (`OAC`) on each S3 origin.  The evaluation inspects distributions that include `s3_origin_config` and identifies S3 origins that lack an associated OAC.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsS3OriginAccessControl) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsS3OriginAccessControl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsHttpsSniEnabled - CloudFront distribution serves HTTPS requests using SNI
type CloudfrontDistributionsHttpsSniEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsHttpsSniEnabled() *CloudfrontDistributionsHttpsSniEnabled {
    return &CloudfrontDistributionsHttpsSniEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_https_sni_enabled",
            CheckTitle: "CloudFront distribution serves HTTPS requests using SNI",
            ServiceName: "cloudfront",
            Severity: "low",
            Description: "**CloudFront distributions** that use **custom SSL/TLS certificates** are configured to serve **HTTPS** using **Server Name Indication** (`ssl_support_method: sni-only`). It evaluates SNI use rather than dedicated IP during the TLS handshake.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsHttpsSniEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsHttpsSniEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudfrontDistributionsS3OriginNonExistentBucket - CloudFront distribution S3 origins reference existing buckets
type CloudfrontDistributionsS3OriginNonExistentBucket struct {
    metadata models.CheckMetadata
}

func NewCloudfrontDistributionsS3OriginNonExistentBucket() *CloudfrontDistributionsS3OriginNonExistentBucket {
    return &CloudfrontDistributionsS3OriginNonExistentBucket{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudfront_distributions_s3_origin_non_existent_bucket",
            CheckTitle: "CloudFront distribution S3 origins reference existing buckets",
            ServiceName: "cloudfront",
            Severity: "high",
            Description: "**CloudFront distributions** with `S3OriginConfig` should reference existing **S3 bucket origins** (excluding static website hosting).  Identifies origins where the configured bucket name does not exist.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudfront"},
        },
    }
}

func (c *CloudfrontDistributionsS3OriginNonExistentBucket) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudfrontDistributionsS3OriginNonExistentBucket) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudfront",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

