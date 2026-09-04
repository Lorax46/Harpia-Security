package opensearch

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion - Amazon OpenSearch Service domain is updated to the latest service software version
type OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion() *OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion {
    return &OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_updated_to_the_latest_service_software_version",
            CheckTitle: "Amazon OpenSearch Service domain is updated to the latest service software version",
            ServiceName: "opensearch",
            Severity: "high",
            Description: "**OpenSearch Service domains** are assessed for pending **service software updates**. This focuses on internal platform updates, distinct from engine version upgrades.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsFaultTolerantDataNodes - OpenSearch domain has at least 3 data nodes and Zone Awareness enabled
type OpensearchServiceDomainsFaultTolerantDataNodes struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsFaultTolerantDataNodes() *OpensearchServiceDomainsFaultTolerantDataNodes {
    return &OpensearchServiceDomainsFaultTolerantDataNodes{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_fault_tolerant_data_nodes",
            CheckTitle: "OpenSearch domain has at least 3 data nodes and Zone Awareness enabled",
            ServiceName: "opensearch",
            Severity: "medium",
            Description: "**Amazon OpenSearch domains** are assessed for fault tolerance: **>= 3 data nodes** (`instance_count >= 3`) and **Zone Awareness** (`zone_awareness_enabled = true`) to distribute data across Availability Zones.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsFaultTolerantDataNodes) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsFaultTolerantDataNodes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsCloudwatchLoggingEnabled - Amazon OpenSearch Service domain publishes search and index slow logs to CloudWatch Logs
type OpensearchServiceDomainsCloudwatchLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsCloudwatchLoggingEnabled() *OpensearchServiceDomainsCloudwatchLoggingEnabled {
    return &OpensearchServiceDomainsCloudwatchLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_cloudwatch_logging_enabled",
            CheckTitle: "Amazon OpenSearch Service domain publishes search and index slow logs to CloudWatch Logs",
            ServiceName: "opensearch",
            Severity: "low",
            Description: "**Amazon OpenSearch Service** domains have **slow log publishing** enabled for both **search** and **indexing** operations to CloudWatch Logs (`SEARCH_SLOW_LOGS` and `INDEX_SLOW_LOGS`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsCloudwatchLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsCloudwatchLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsInternalUserDatabaseEnabled - Amazon OpenSearch Service domain has internal user database disabled
type OpensearchServiceDomainsInternalUserDatabaseEnabled struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsInternalUserDatabaseEnabled() *OpensearchServiceDomainsInternalUserDatabaseEnabled {
    return &OpensearchServiceDomainsInternalUserDatabaseEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_internal_user_database_enabled",
            CheckTitle: "Amazon OpenSearch Service domain has internal user database disabled",
            ServiceName: "opensearch",
            Severity: "medium",
            Description: "**Amazon OpenSearch Service domains** are evaluated for the **internal user database** setting (`InternalUserDatabaseEnabled`). The finding identifies domains that rely on built-in HTTP basic users instead of external identity providers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsInternalUserDatabaseEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsInternalUserDatabaseEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsHttpsCommunicationsEnforced - OpenSearch domain has HTTPS enforcement enabled
type OpensearchServiceDomainsHttpsCommunicationsEnforced struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsHttpsCommunicationsEnforced() *OpensearchServiceDomainsHttpsCommunicationsEnforced {
    return &OpensearchServiceDomainsHttpsCommunicationsEnforced{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_https_communications_enforced",
            CheckTitle: "OpenSearch domain has HTTPS enforcement enabled",
            ServiceName: "opensearch",
            Severity: "high",
            Description: "Amazon OpenSearch Service domains with **HTTPS enforcement** require encrypted connections. This assessment identifies domains missing `Require HTTPS for all traffic`, indicating that unencrypted HTTP is accepted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsHttpsCommunicationsEnforced) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsHttpsCommunicationsEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsNodeToNodeEncryptionEnabled - Amazon OpenSearch Service domain has node-to-node encryption enabled
type OpensearchServiceDomainsNodeToNodeEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsNodeToNodeEncryptionEnabled() *OpensearchServiceDomainsNodeToNodeEncryptionEnabled {
    return &OpensearchServiceDomainsNodeToNodeEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_node_to_node_encryption_enabled",
            CheckTitle: "Amazon OpenSearch Service domain has node-to-node encryption enabled",
            ServiceName: "opensearch",
            Severity: "high",
            Description: "**Amazon OpenSearch domains** with **node-to-node encryption** use TLS to protect traffic between cluster nodes. The finding evaluates the domain's `node_to_node_encryption` configuration for intra-cluster communications.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsNodeToNodeEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsNodeToNodeEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsEncryptionAtRestEnabled - Amazon OpenSearch Service domain has encryption at rest enabled
type OpensearchServiceDomainsEncryptionAtRestEnabled struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsEncryptionAtRestEnabled() *OpensearchServiceDomainsEncryptionAtRestEnabled {
    return &OpensearchServiceDomainsEncryptionAtRestEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_encryption_at_rest_enabled",
            CheckTitle: "Amazon OpenSearch Service domain has encryption at rest enabled",
            ServiceName: "opensearch",
            Severity: "critical",
            Description: "**Amazon OpenSearch Service domains** are evaluated for `encryption at rest` using AWS KMS (`AES-256`) across stored data, including indexes, swap files, and automated snapshots.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsEncryptionAtRestEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsEncryptionAtRestEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsFaultTolerantMasterNodes - OpenSearch domain has at least 3 dedicated master nodes
type OpensearchServiceDomainsFaultTolerantMasterNodes struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsFaultTolerantMasterNodes() *OpensearchServiceDomainsFaultTolerantMasterNodes {
    return &OpensearchServiceDomainsFaultTolerantMasterNodes{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_fault_tolerant_master_nodes",
            CheckTitle: "OpenSearch domain has at least 3 dedicated master nodes",
            ServiceName: "opensearch",
            Severity: "medium",
            Description: "**Amazon OpenSearch domains** have **dedicated master nodes** enabled with a master node count of at least `3` to support stable cluster coordination and elections",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsFaultTolerantMasterNodes) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsFaultTolerantMasterNodes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsAccessControlEnabled - Amazon OpenSearch Service domain has fine-grained access control enabled
type OpensearchServiceDomainsAccessControlEnabled struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsAccessControlEnabled() *OpensearchServiceDomainsAccessControlEnabled {
    return &OpensearchServiceDomainsAccessControlEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_access_control_enabled",
            CheckTitle: "Amazon OpenSearch Service domain has fine-grained access control enabled",
            ServiceName: "opensearch",
            Severity: "high",
            Description: "**Amazon OpenSearch Service domains** are evaluated for **fine-grained access control** being enabled in `advanced-security-options`, ensuring role-based authorization at index, document, and field levels for API and Dashboards access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsAccessControlEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsAccessControlEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsNotPubliclyAccessible - Amazon OpenSearch Service domain is not publicly accessible
type OpensearchServiceDomainsNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsNotPubliclyAccessible() *OpensearchServiceDomainsNotPubliclyAccessible {
    return &OpensearchServiceDomainsNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_not_publicly_accessible",
            CheckTitle: "Amazon OpenSearch Service domain is not publicly accessible",
            ServiceName: "opensearch",
            Severity: "critical",
            Description: "**Amazon OpenSearch domains** are assessed for **public exposure** via their resource-based access policies. Domains inside a VPC are treated as **privately reachable**; domains with overly permissive policies that allow broad, unauthenticated access are identified as **publicly accessible**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsAuditLoggingEnabled - Amazon OpenSearch Service domain has audit logging enabled
type OpensearchServiceDomainsAuditLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsAuditLoggingEnabled() *OpensearchServiceDomainsAuditLoggingEnabled {
    return &OpensearchServiceDomainsAuditLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_audit_logging_enabled",
            CheckTitle: "Amazon OpenSearch Service domain has audit logging enabled",
            ServiceName: "opensearch",
            Severity: "high",
            Description: "**Amazon OpenSearch Service domains** have **audit logs** enabled via `AUDIT_LOGS`",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsAuditLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsAuditLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// OpensearchServiceDomainsUseCognitoAuthenticationForKibana - Amazon OpenSearch Service domain has either Amazon Cognito or SAML authentication enabled for Kibana
type OpensearchServiceDomainsUseCognitoAuthenticationForKibana struct {
    metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsUseCognitoAuthenticationForKibana() *OpensearchServiceDomainsUseCognitoAuthenticationForKibana {
    return &OpensearchServiceDomainsUseCognitoAuthenticationForKibana{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "opensearch_service_domains_use_cognito_authentication_for_kibana",
            CheckTitle: "Amazon OpenSearch Service domain has either Amazon Cognito or SAML authentication enabled for Kibana",
            ServiceName: "opensearch",
            Severity: "medium",
            Description: "**OpenSearch Service domains** use **Amazon Cognito** or **SAML** to authenticate access to Kibana/OpenSearch Dashboards.  The evaluation identifies domains where either provider is enabled for Dashboards access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"opensearch"},
        },
    }
}

func (c *OpensearchServiceDomainsUseCognitoAuthenticationForKibana) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *OpensearchServiceDomainsUseCognitoAuthenticationForKibana) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "opensearch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

