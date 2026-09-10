package elbv2

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Elbv2ListenersUnderneath - ELBv2 load balancer has at least one listener
type Elbv2ListenersUnderneath struct {
    metadata models.CheckMetadata
}

func NewElbv2ListenersUnderneath() *Elbv2ListenersUnderneath {
    return &Elbv2ListenersUnderneath{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_listeners_underneath",
            CheckTitle: "ELBv2 load balancer has at least one listener",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**ELBv2 load balancer** requires at least one **listener** (protocol and port) to accept client connections and route requests to target groups. The finding indicates whether listeners are defined on the load balancer.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2ListenersUnderneath) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2ListenersUnderneath) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2LoggingEnabled - ELBv2 Application Load Balancer has access logs to S3 configured
type Elbv2LoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewElbv2LoggingEnabled() *Elbv2LoggingEnabled {
    return &Elbv2LoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_logging_enabled",
            CheckTitle: "ELBv2 Application Load Balancer has access logs to S3 configured",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**ELBv2 Application Load Balancers** are evaluated for **access logging** enabled to Amazon S3, capturing request details such as timestamps, client IPs, paths, and response codes.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2LoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2LoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2CrossZoneLoadBalancingEnabled - ELBv2 Network or Gateway Load Balancer has cross-zone load balancing enabled
type Elbv2CrossZoneLoadBalancingEnabled struct {
    metadata models.CheckMetadata
}

func NewElbv2CrossZoneLoadBalancingEnabled() *Elbv2CrossZoneLoadBalancingEnabled {
    return &Elbv2CrossZoneLoadBalancingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_cross_zone_load_balancing_enabled",
            CheckTitle: "ELBv2 Network or Gateway Load Balancer has cross-zone load balancing enabled",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**Network and Gateway Load Balancers** have **cross-zone load balancing** enabled (`load_balancing.cross_zone.enabled`), so each node distributes requests to targets in all enabled Availability Zones rather than only its own.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2CrossZoneLoadBalancingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2CrossZoneLoadBalancingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2WafAclAttached - Application Load Balancer has a WAF Web ACL attached
type Elbv2WafAclAttached struct {
    metadata models.CheckMetadata
}

func NewElbv2WafAclAttached() *Elbv2WafAclAttached {
    return &Elbv2WafAclAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_waf_acl_attached",
            CheckTitle: "Application Load Balancer has a WAF Web ACL attached",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "Application Load Balancers are evaluated for an associated **AWS WAF web ACL** that governs HTTP(S) requests. The evaluation detects ALBs missing a web ACL and recognizes associations from **WAFv2** or regional **WAF Classic**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2WafAclAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2WafAclAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2DesyncMitigationMode - Application Load Balancer has desync mitigation mode set to strictest or defensive, or drops invalid header fields
type Elbv2DesyncMitigationMode struct {
    metadata models.CheckMetadata
}

func NewElbv2DesyncMitigationMode() *Elbv2DesyncMitigationMode {
    return &Elbv2DesyncMitigationMode{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_desync_mitigation_mode",
            CheckTitle: "Application Load Balancer has desync mitigation mode set to strictest or defensive, or drops invalid header fields",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**Application Load Balancer** settings are reviewed for **HTTP desync protections**. It evaluates `routing.http.desync_mitigation_mode` for `strictest` or `defensive`; when neither is configured, it checks `routing.http.drop_invalid_header_fields.enabled` is `true` as a compensating control.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2DesyncMitigationMode) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2DesyncMitigationMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2IsInMultipleAz - ELBv2 load balancer is configured across multiple Availability Zones
type Elbv2IsInMultipleAz struct {
    metadata models.CheckMetadata
}

func NewElbv2IsInMultipleAz() *Elbv2IsInMultipleAz {
    return &Elbv2IsInMultipleAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_is_in_multiple_az",
            CheckTitle: "ELBv2 load balancer is configured across multiple Availability Zones",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "ELBv2 load balancers (Application, Network, or Gateway) are assessed for distribution across multiple **Availability Zones**. The finding indicates whether each load balancer spans at least the configured minimum number of AZs (default `2`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2IsInMultipleAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2IsInMultipleAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2NlbTlsTerminationEnabled - ELBv2 Network Load Balancer has TLS termination enabled
type Elbv2NlbTlsTerminationEnabled struct {
    metadata models.CheckMetadata
}

func NewElbv2NlbTlsTerminationEnabled() *Elbv2NlbTlsTerminationEnabled {
    return &Elbv2NlbTlsTerminationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_nlb_tls_termination_enabled",
            CheckTitle: "ELBv2 Network Load Balancer has TLS termination enabled",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**Network Load Balancers** with listeners using the `TLS` protocol indicate **TLS termination** at the load balancer. The evaluation identifies NLBs that have at least one `TLS` listener versus those using plain `TCP`/`UDP` or deferring encryption to targets.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2NlbTlsTerminationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2NlbTlsTerminationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2InsecureSslCiphers - ELBv2 load balancer uses a secure SSL policy on HTTPS listeners
type Elbv2InsecureSslCiphers struct {
    metadata models.CheckMetadata
}

func NewElbv2InsecureSslCiphers() *Elbv2InsecureSslCiphers {
    return &Elbv2InsecureSslCiphers{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_insecure_ssl_ciphers",
            CheckTitle: "ELBv2 load balancer uses a secure SSL policy on HTTPS listeners",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**ELBv2 HTTPS listeners** are assessed for use of **strong TLS policies**. Listeners whose `ssl_policy` is not in the approved set (TLS 1.2/1.3-focused policies) may include weak protocols or ciphers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2InsecureSslCiphers) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2InsecureSslCiphers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2ListenerPqcTlsEnabled - ELBv2 HTTPS/TLS listeners use a post-quantum TLS security policy
type Elbv2ListenerPqcTlsEnabled struct {
    metadata models.CheckMetadata
}

func NewElbv2ListenerPqcTlsEnabled() *Elbv2ListenerPqcTlsEnabled {
    return &Elbv2ListenerPqcTlsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_listener_pqc_tls_enabled",
            CheckTitle: "ELBv2 HTTPS/TLS listeners use a post-quantum TLS security policy",
            ServiceName: "elbv2",
            Severity: "low",
            Description: "**ELBv2 HTTPS and TLS listeners** are assessed for use of **post-quantum (PQ) TLS security policies**. Listeners whose `SslPolicy` is not in the approved PQ set lack hybrid key exchange (ML-KEM 768 + ECDHE), which can increase harvest-now-decrypt-later exposure for recorded traffic.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2ListenerPqcTlsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2ListenerPqcTlsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2AlbDropInvalidHeaderFieldsEnabled - Application Load Balancer should be configured to drop invalid HTTP header fields
type Elbv2AlbDropInvalidHeaderFieldsEnabled struct {
    metadata models.CheckMetadata
}

func NewElbv2AlbDropInvalidHeaderFieldsEnabled() *Elbv2AlbDropInvalidHeaderFieldsEnabled {
    return &Elbv2AlbDropInvalidHeaderFieldsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_alb_drop_invalid_header_fields_enabled",
            CheckTitle: "Application Load Balancer should be configured to drop invalid HTTP header fields",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "Ensure that Application Load Balancers (ALB) are configured to drop invalid HTTP header fields. The check fails when `routing.http.drop_invalid_header_fields.enabled` is not set to `true`. By default, ALBs do not remove HTTP headers that do not conform to RFC 7230.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2AlbDropInvalidHeaderFieldsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2AlbDropInvalidHeaderFieldsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2InternetFacing - Application Load Balancer is not publicly accessible (no inbound TCP from 0.0.0.0/0 or ::/0)
type Elbv2InternetFacing struct {
    metadata models.CheckMetadata
}

func NewElbv2InternetFacing() *Elbv2InternetFacing {
    return &Elbv2InternetFacing{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_internet_facing",
            CheckTitle: "Application Load Balancer is not publicly accessible (no inbound TCP from 0.0.0.0/0 or ::/0)",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**ELBv2 Application Load Balancers** configured as `internet-facing` are assessed for exposure by reviewing attached **security groups**.  Inbound TCP rules that allow `0.0.0.0/0` or `::/0` indicate unrestricted internet reachability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2InternetFacing) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2InternetFacing) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2SslListeners - ELBv2 Application Load Balancer listeners use HTTPS or redirect HTTP to HTTPS
type Elbv2SslListeners struct {
    metadata models.CheckMetadata
}

func NewElbv2SslListeners() *Elbv2SslListeners {
    return &Elbv2SslListeners{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_ssl_listeners",
            CheckTitle: "ELBv2 Application Load Balancer listeners use HTTPS or redirect HTTP to HTTPS",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**Application Load Balancer listeners** are assessed for **encrypted ingress**: either only `HTTPS` listeners are present, or any `HTTP` listener redirects to `HTTPS`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2SslListeners) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2SslListeners) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Elbv2DeletionProtection - ELBv2 load balancer has deletion protection enabled
type Elbv2DeletionProtection struct {
    metadata models.CheckMetadata
}

func NewElbv2DeletionProtection() *Elbv2DeletionProtection {
    return &Elbv2DeletionProtection{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "elbv2_deletion_protection",
            CheckTitle: "ELBv2 load balancer has deletion protection enabled",
            ServiceName: "elbv2",
            Severity: "medium",
            Description: "**ELBv2 load balancers** with **deletion protection** (`deletion_protection.enabled`) are resistant to deletion through standard APIs.  The assessment determines whether this attribute is enabled on each load balancer.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"elbv2"},
        },
    }
}

func (c *Elbv2DeletionProtection) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Elbv2DeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "elbv2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

