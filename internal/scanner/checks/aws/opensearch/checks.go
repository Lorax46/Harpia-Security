package opensearch

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type opensearchProvider interface {
	OpenSearch(ctx context.Context) (*opensearch.Client, error)
}

// OpensearchServiceDomainsAuditLoggingEnabled - OpenSearch audit logging enabled
type OpensearchServiceDomainsAuditLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsAuditLoggingEnabled() *OpensearchServiceDomainsAuditLoggingEnabled {
	return &OpensearchServiceDomainsAuditLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_audit_logging_enabled",
			CheckTitle: "OpenSearch audit logging is enabled",
			ServiceName: "opensearch", Severity: "medium", ResourceType: "Domain",
			Description: "OpenSearch domains should have audit logging enabled",
			RemediationText: "Enable audit logging on OpenSearch domains",
			Categories: []string{"analytics", "logging"},
		},
	}
}

func (c *OpensearchServiceDomainsAuditLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsAuditLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have audit logging enabled.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.LogPublishingOptions != nil {
			if options, ok := details.DomainStatus.LogPublishingOptions["AUDIT_LOGS"]; ok {
				if options.Enabled != nil && *options.Enabled {
					status = models.StatusPass
					statusExtended = fmt.Sprintf("OpenSearch domain %s has audit logging enabled.", domainName)
				}
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsEncryptionAtRestEnabled - OpenSearch encryption at rest
type OpensearchServiceDomainsEncryptionAtRestEnabled struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsEncryptionAtRestEnabled() *OpensearchServiceDomainsEncryptionAtRestEnabled {
	return &OpensearchServiceDomainsEncryptionAtRestEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_encryption_at_rest_enabled",
			CheckTitle: "OpenSearch encryption at rest is enabled",
			ServiceName: "opensearch", Severity: "high", ResourceType: "Domain",
			Description: "OpenSearch domains should have encryption at rest enabled",
			RemediationText: "Enable encryption at rest on OpenSearch domains",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *OpensearchServiceDomainsEncryptionAtRestEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsEncryptionAtRestEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have encryption at rest enabled.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.EncryptionAtRestOptions != nil {
			if details.DomainStatus.EncryptionAtRestOptions.Enabled != nil && *details.DomainStatus.EncryptionAtRestOptions.Enabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s has encryption at rest enabled.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsCloudwatchLoggingEnabled - OpenSearch CloudWatch logging
type OpensearchServiceDomainsCloudwatchLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsCloudwatchLoggingEnabled() *OpensearchServiceDomainsCloudwatchLoggingEnabled {
	return &OpensearchServiceDomainsCloudwatchLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_cloudwatch_logging_enabled",
			CheckTitle: "OpenSearch CloudWatch logging is enabled",
			ServiceName: "opensearch", Severity: "medium", ResourceType: "Domain",
			Description: "OpenSearch domains should have CloudWatch logging enabled",
			RemediationText: "Enable CloudWatch logging on OpenSearch domains",
			Categories: []string{"analytics", "logging"},
		},
	}
}

func (c *OpensearchServiceDomainsCloudwatchLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsCloudwatchLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have CloudWatch logging enabled.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.LogPublishingOptions != nil {
			if options, ok := details.DomainStatus.LogPublishingOptions["SEARCH_SLOW_LOGS"]; ok {
				if options.Enabled != nil && *options.Enabled {
					status = models.StatusPass
					statusExtended = fmt.Sprintf("OpenSearch domain %s has CloudWatch logging enabled.", domainName)
				}
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsHttpsCommunicationsEnforced - OpenSearch HTTPS enforced
type OpensearchServiceDomainsHttpsCommunicationsEnforced struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsHttpsCommunicationsEnforced() *OpensearchServiceDomainsHttpsCommunicationsEnforced {
	return &OpensearchServiceDomainsHttpsCommunicationsEnforced{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_https_communications_enforced",
			CheckTitle: "OpenSearch HTTPS communications enforced",
			ServiceName: "opensearch", Severity: "high", ResourceType: "Domain",
			Description: "OpenSearch domains should enforce HTTPS communications",
			RemediationText: "Enforce HTTPS on OpenSearch domains",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *OpensearchServiceDomainsHttpsCommunicationsEnforced) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsHttpsCommunicationsEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not enforce HTTPS.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.DomainEndpointOptions != nil {
			if details.DomainStatus.DomainEndpointOptions.EnforceHTTPS != nil && *details.DomainStatus.DomainEndpointOptions.EnforceHTTPS {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s enforces HTTPS.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsNodeToNodeEncryptionEnabled - OpenSearch node-to-node encryption
type OpensearchServiceDomainsNodeToNodeEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsNodeToNodeEncryptionEnabled() *OpensearchServiceDomainsNodeToNodeEncryptionEnabled {
	return &OpensearchServiceDomainsNodeToNodeEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_node_to_node_encryption_enabled",
			CheckTitle: "OpenSearch node-to-node encryption is enabled",
			ServiceName: "opensearch", Severity: "high", ResourceType: "Domain",
			Description: "OpenSearch domains should have node-to-node encryption enabled",
			RemediationText: "Enable node-to-node encryption on OpenSearch domains",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *OpensearchServiceDomainsNodeToNodeEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsNodeToNodeEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have node-to-node encryption enabled.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.NodeToNodeEncryptionOptions != nil {
			if details.DomainStatus.NodeToNodeEncryptionOptions.Enabled != nil && *details.DomainStatus.NodeToNodeEncryptionOptions.Enabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s has node-to-node encryption enabled.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsNotPubliclyAccessible - OpenSearch not publicly accessible
type OpensearchServiceDomainsNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsNotPubliclyAccessible() *OpensearchServiceDomainsNotPubliclyAccessible {
	return &OpensearchServiceDomainsNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_not_publicly_accessible",
			CheckTitle: "OpenSearch domains are not publicly accessible",
			ServiceName: "opensearch", Severity: "high", ResourceType: "Domain",
			Description: "OpenSearch domains should not be publicly accessible",
			RemediationText: "Configure OpenSearch domains to be in VPC",
			Categories: []string{"analytics", "networking"},
		},
	}
}

func (c *OpensearchServiceDomainsNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("OpenSearch domain %s is not publicly accessible.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.VPCOptions != nil {
			if details.DomainStatus.VPCOptions.VPCId == nil || aws.ToString(details.DomainStatus.VPCOptions.VPCId) == "" {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("OpenSearch domain %s is publicly accessible.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsAccessControlEnabled - OpenSearch access control enabled
type OpensearchServiceDomainsAccessControlEnabled struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsAccessControlEnabled() *OpensearchServiceDomainsAccessControlEnabled {
	return &OpensearchServiceDomainsAccessControlEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_access_control_enabled",
			CheckTitle: "OpenSearch access control is enabled",
			ServiceName: "opensearch", Severity: "medium", ResourceType: "Domain",
			Description: "OpenSearch domains should have fine-grained access control enabled",
			RemediationText: "Enable fine-grained access control on OpenSearch domains",
			Categories: []string{"analytics", "identity"},
		},
	}
}

func (c *OpensearchServiceDomainsAccessControlEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsAccessControlEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have fine-grained access control enabled.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.AdvancedSecurityOptions != nil {
			if details.DomainStatus.AdvancedSecurityOptions.Enabled != nil && *details.DomainStatus.AdvancedSecurityOptions.Enabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s has fine-grained access control enabled.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsFaultTolerantDataNodes - OpenSearch fault-tolerant data nodes
type OpensearchServiceDomainsFaultTolerantDataNodes struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsFaultTolerantDataNodes() *OpensearchServiceDomainsFaultTolerantDataNodes {
	return &OpensearchServiceDomainsFaultTolerantDataNodes{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_fault_tolerant_data_nodes",
			CheckTitle: "OpenSearch fault-tolerant data nodes",
			ServiceName: "opensearch", Severity: "medium", ResourceType: "Domain",
			Description: "OpenSearch domains should have fault-tolerant data nodes",
			RemediationText: "Configure fault-tolerant data nodes on OpenSearch domains",
			Categories: []string{"analytics"},
		},
	}
}

func (c *OpensearchServiceDomainsFaultTolerantDataNodes) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsFaultTolerantDataNodes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have fault-tolerant data nodes.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.ClusterConfig != nil {
			if details.DomainStatus.ClusterConfig.InstanceCount != nil && *details.DomainStatus.ClusterConfig.InstanceCount >= 2 {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s has fault-tolerant data nodes.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsFaultTolerantMasterNodes - OpenSearch fault-tolerant master nodes
type OpensearchServiceDomainsFaultTolerantMasterNodes struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsFaultTolerantMasterNodes() *OpensearchServiceDomainsFaultTolerantMasterNodes {
	return &OpensearchServiceDomainsFaultTolerantMasterNodes{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_fault_tolerant_master_nodes",
			CheckTitle: "OpenSearch fault-tolerant master nodes",
			ServiceName: "opensearch", Severity: "medium", ResourceType: "Domain",
			Description: "OpenSearch domains should have fault-tolerant master nodes",
			RemediationText: "Configure fault-tolerant master nodes on OpenSearch domains",
			Categories: []string{"analytics"},
		},
	}
}

func (c *OpensearchServiceDomainsFaultTolerantMasterNodes) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsFaultTolerantMasterNodes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have fault-tolerant master nodes.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.ClusterConfig != nil {
			if details.DomainStatus.ClusterConfig.DedicatedMasterEnabled != nil && *details.DomainStatus.ClusterConfig.DedicatedMasterEnabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s has fault-tolerant master nodes.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsInternalUserDatabaseEnabled - OpenSearch internal user database
type OpensearchServiceDomainsInternalUserDatabaseEnabled struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsInternalUserDatabaseEnabled() *OpensearchServiceDomainsInternalUserDatabaseEnabled {
	return &OpensearchServiceDomainsInternalUserDatabaseEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_internal_user_database_enabled",
			CheckTitle: "OpenSearch internal user database is enabled",
			ServiceName: "opensearch", Severity: "low", ResourceType: "Domain",
			Description: "OpenSearch domains should have internal user database enabled",
			RemediationText: "Enable internal user database on OpenSearch domains",
			Categories: []string{"analytics", "identity"},
		},
	}
}

func (c *OpensearchServiceDomainsInternalUserDatabaseEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsInternalUserDatabaseEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not have internal user database enabled.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.AdvancedSecurityOptions != nil {
			if details.DomainStatus.AdvancedSecurityOptions.InternalUserDatabaseEnabled != nil && *details.DomainStatus.AdvancedSecurityOptions.InternalUserDatabaseEnabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s has internal user database enabled.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion - OpenSearch latest version
type OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion() *OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion {
	return &OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_updated_to_the_latest_service_software_version",
			CheckTitle: "OpenSearch domains updated to latest version",
			ServiceName: "opensearch", Severity: "low", ResourceType: "Domain",
			Description: "OpenSearch domains should be updated to the latest version",
			RemediationText: "Update OpenSearch domains to the latest version",
			Categories: []string{"analytics"},
		},
	}
}

func (c *OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("OpenSearch domain %s is updated to the latest version.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.ServiceSoftwareOptions != nil {
			updateStatus := details.DomainStatus.ServiceSoftwareOptions.UpdateStatus
			if updateStatus != "" && updateStatus != "UPDATE_COMPLETED" {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("OpenSearch domain %s is not updated to the latest version (status: %s).", domainName, string(updateStatus))
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// OpensearchServiceDomainsUseCognitoAuthenticationForKibana - OpenSearch Cognito auth
type OpensearchServiceDomainsUseCognitoAuthenticationForKibana struct {
	metadata models.CheckMetadata
}

func NewOpensearchServiceDomainsUseCognitoAuthenticationForKibana() *OpensearchServiceDomainsUseCognitoAuthenticationForKibana {
	return &OpensearchServiceDomainsUseCognitoAuthenticationForKibana{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "opensearch_service_domains_use_cognito_authentication_for_kibana",
			CheckTitle: "OpenSearch uses Cognito authentication for Kibana",
			ServiceName: "opensearch", Severity: "medium", ResourceType: "Domain",
			Description: "OpenSearch domains should use Cognito authentication for Kibana",
			RemediationText: "Enable Cognito authentication for Kibana on OpenSearch domains",
			Categories: []string{"analytics", "identity"},
		},
	}
}

func (c *OpensearchServiceDomainsUseCognitoAuthenticationForKibana) Metadata() models.CheckMetadata { return c.metadata }

func (c *OpensearchServiceDomainsUseCognitoAuthenticationForKibana) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(opensearchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement opensearchProvider")
	}
	osClient, err := p.OpenSearch(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domains, err := osClient.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("OpenSearch domain %s does not use Cognito authentication for Kibana.", domainName)

		details, err := osClient.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err == nil && details.DomainStatus != nil && details.DomainStatus.CognitoOptions != nil {
			if details.DomainStatus.CognitoOptions.Enabled != nil && *details.DomainStatus.CognitoOptions.Enabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("OpenSearch domain %s uses Cognito authentication for Kibana.", domainName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "opensearch", ResourceID: domainName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}