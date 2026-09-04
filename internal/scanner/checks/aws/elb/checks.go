package elb

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// ElbDesyncMitigationMode - Classic Load Balancer desync mitigation mode is defensive or strictest
type ElbDesyncMitigationMode struct {
    metadata models.CheckMetadata
}

func NewElbDesyncMitigationMode() *ElbDesyncMitigationMode {
    return &ElbDesyncMitigationMode{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_desync_mitigation_mode",
            CheckTitle: "Classic Load Balancer desync mitigation mode is defensive or strictest",
            ServiceName: "elb",
            Severity: "medium",
            Description: "**Classic Load Balancer** `desync_mitigation_mode` is evaluated to determine whether it is configured as **`defensive`** or **`strictest`**. Any other mode (such as `monitor`) is identified for attention.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbDesyncMitigationMode) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbDesyncMitigationMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbSslListenersUseAcmCertificate - Classic Load Balancer HTTPS/SSL listeners use ACM-issued certificates
type ElbSslListenersUseAcmCertificate struct {
    metadata models.CheckMetadata
}

func NewElbSslListenersUseAcmCertificate() *ElbSslListenersUseAcmCertificate {
    return &ElbSslListenersUseAcmCertificate{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_ssl_listeners_use_acm_certificate",
            CheckTitle: "Classic Load Balancer HTTPS/SSL listeners use ACM-issued certificates",
            ServiceName: "elb",
            Severity: "medium",
            Description: "Classic Load Balancer HTTPS/SSL listeners use **AWS Certificate Manager** certificates that are **Amazon-issued** (certificate type `AMAZON_ISSUED`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbSslListenersUseAcmCertificate) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbSslListenersUseAcmCertificate) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbInsecureSslCiphers - Elastic Load Balancer HTTPS listeners, if present, use the ELBSecurityPolicy-TLS-1-2-2017-01 policy
type ElbInsecureSslCiphers struct {
    metadata models.CheckMetadata
}

func NewElbInsecureSslCiphers() *ElbInsecureSslCiphers {
    return &ElbInsecureSslCiphers{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_insecure_ssl_ciphers",
            CheckTitle: "Elastic Load Balancer HTTPS listeners, if present, use the ELBSecurityPolicy-TLS-1-2-2017-01 policy",
            ServiceName: "elb",
            Severity: "medium",
            Description: "Elastic Load Balancer HTTPS listeners are assessed for use of a **strong TLS policy**. Listeners associated with `ELBSecurityPolicy-TLS-1-2-2017-01` are considered to negotiate only modern protocols and ciphers, avoiding legacy SSL/TLS and weak suites.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbInsecureSslCiphers) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbInsecureSslCiphers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbConnectionDrainingEnabled - Classic Load Balancer has connection draining enabled
type ElbConnectionDrainingEnabled struct {
    metadata models.CheckMetadata
}

func NewElbConnectionDrainingEnabled() *ElbConnectionDrainingEnabled {
    return &ElbConnectionDrainingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_connection_draining_enabled",
            CheckTitle: "Classic Load Balancer has connection draining enabled",
            ServiceName: "elb",
            Severity: "medium",
            Description: "**Classic Load Balancer** has **connection draining** enabled, so deregistering or unhealthy instances stop receiving new requests while existing connections are allowed to complete within the configured drain window.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbConnectionDrainingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbConnectionDrainingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbInternetFacing - Elastic Load Balancer is not internet-facing
type ElbInternetFacing struct {
    metadata models.CheckMetadata
}

func NewElbInternetFacing() *ElbInternetFacing {
    return &ElbInternetFacing{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_internet_facing",
            CheckTitle: "Elastic Load Balancer is not internet-facing",
            ServiceName: "elb",
            Severity: "medium",
            Description: "Elastic Load Balancers are evaluated for the `scheme` to determine whether they are **internet-facing** or internal, indicating if the endpoint is publicly reachable via a public DNS name.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbInternetFacing) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbInternetFacing) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbIsInMultipleAz - Classic Load Balancer is in multiple Availability Zones
type ElbIsInMultipleAz struct {
    metadata models.CheckMetadata
}

func NewElbIsInMultipleAz() *ElbIsInMultipleAz {
    return &ElbIsInMultipleAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_is_in_multiple_az",
            CheckTitle: "Classic Load Balancer is in multiple Availability Zones",
            ServiceName: "elb",
            Severity: "medium",
            Description: "**Classic Load Balancer** spans at least the configured number of **Availability Zones**.  The evaluation identifies load balancers enabled in fewer AZs than the specified minimum.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbIsInMultipleAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbIsInMultipleAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbLoggingEnabled - Elastic Load Balancer has access logs to S3 configured
type ElbLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewElbLoggingEnabled() *ElbLoggingEnabled {
    return &ElbLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_logging_enabled",
            CheckTitle: "Elastic Load Balancer has access logs to S3 configured",
            ServiceName: "elb",
            Severity: "medium",
            Description: "**Elastic Load Balancers** have **access logs** configured to deliver request metadata (client IPs, paths, status, TLS details) to **Amazon S3**",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbCrossZoneLoadBalancingEnabled - Classic Load Balancer has cross-zone load balancing enabled
type ElbCrossZoneLoadBalancingEnabled struct {
    metadata models.CheckMetadata
}

func NewElbCrossZoneLoadBalancingEnabled() *ElbCrossZoneLoadBalancingEnabled {
    return &ElbCrossZoneLoadBalancingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_cross_zone_load_balancing_enabled",
            CheckTitle: "Classic Load Balancer has cross-zone load balancing enabled",
            ServiceName: "elb",
            Severity: "medium",
            Description: "Classic Load Balancer with **cross-zone load balancing** distributes requests across registered targets in all enabled Availability Zones.  This evaluates whether that setting is `enabled`, instead of restricting distribution to targets within only the same zone.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbCrossZoneLoadBalancingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbCrossZoneLoadBalancingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ElbSslListeners - Elastic Load Balancer has only HTTPS or SSL listeners
type ElbSslListeners struct {
    metadata models.CheckMetadata
}

func NewElbSslListeners() *ElbSslListeners {
    return &ElbSslListeners{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elb_ssl_listeners",
            CheckTitle: "Elastic Load Balancer has only HTTPS or SSL listeners",
            ServiceName: "elb",
            Severity: "medium",
            Description: "**Elastic Load Balancers** are assessed for client-facing listener protocols. Only `HTTPS` or `SSL` are considered encrypted; any `HTTP` or `TCP` listener indicates plaintext between clients and the load balancer.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elb"},
        },
    }
}

func (c *ElbSslListeners) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ElbSslListeners) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

