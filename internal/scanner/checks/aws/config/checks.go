package config

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// ConfigRecorderAllRegionsEnabled - AWS Config recorder is enabled and not in failure state or disabled
type ConfigRecorderAllRegionsEnabled struct {
    metadata models.CheckMetadata
}

func NewConfigRecorderAllRegionsEnabled() *ConfigRecorderAllRegionsEnabled {
    return &ConfigRecorderAllRegionsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "config_recorder_all_regions_enabled",
            CheckTitle: "AWS Config recorder is enabled and not in failure state or disabled",
            ServiceName: "config",
            Severity: "medium",
            Description: "**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"config"},
        },
    }
}

func (c *ConfigRecorderAllRegionsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ConfigRecorderAllRegionsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "config",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ConfigDelegatedAdminAndOrgAggregatorAllRegions - AWS Config has a delegated administrator and an organization aggregator covering all AWS regions
type ConfigDelegatedAdminAndOrgAggregatorAllRegions struct {
    metadata models.CheckMetadata
}

func NewConfigDelegatedAdminAndOrgAggregatorAllRegions() *ConfigDelegatedAdminAndOrgAggregatorAllRegions {
    return &ConfigDelegatedAdminAndOrgAggregatorAllRegions{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "config_delegated_admin_and_org_aggregator_all_regions",
            CheckTitle: "AWS Config has a delegated administrator and an organization aggregator covering all AWS regions",
            ServiceName: "config",
            Severity: "high",
            Description: "**AWS Config** has a delegated administrator registered via AWS Organizations and at least one Configuration Aggregator with an OrganizationAggregationSource that covers all AWS regions, ensuring centralized org-wide configuration visibility.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"config"},
        },
    }
}

func (c *ConfigDelegatedAdminAndOrgAggregatorAllRegions) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ConfigDelegatedAdminAndOrgAggregatorAllRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "config",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// ConfigRecorderUsingAwsServiceRole - AWS Config recorder uses the AWSServiceRoleForConfig service-linked role
type ConfigRecorderUsingAwsServiceRole struct {
    metadata models.CheckMetadata
}

func NewConfigRecorderUsingAwsServiceRole() *ConfigRecorderUsingAwsServiceRole {
    return &ConfigRecorderUsingAwsServiceRole{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "config_recorder_using_aws_service_role",
            CheckTitle: "AWS Config recorder uses the AWSServiceRoleForConfig service-linked role",
            ServiceName: "config",
            Severity: "medium",
            Description: "**AWS Config recorders** are evaluated for use of the service‑linked IAM role `AWSServiceRoleForConfig` linked to `config.amazonaws.com` rather than a custom role.  The evaluation inspects active recorders and their role ARN to confirm the AWS‑managed service‑linked role is in use.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"config"},
        },
    }
}

func (c *ConfigRecorderUsingAwsServiceRole) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *ConfigRecorderUsingAwsServiceRole) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "config",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

