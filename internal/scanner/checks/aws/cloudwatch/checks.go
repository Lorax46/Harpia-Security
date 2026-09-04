package cloudwatch

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled - CloudWatch Logs metric filter and alarm exist for AWS Config configuration changes
type CloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled() *CloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled {
    return &CloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for AWS Config configuration changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "CloudTrail logs in **CloudWatch Logs** are inspected for a metric filter and alarm that track **AWS Config configuration changes**, specifically `StopConfigurationRecorder`, `DeleteDeliveryChannel`, `PutDeliveryChannel`, and `PutConfigurationRecorder` events from `config.amazonaws.com`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterAndAlarmForAwsConfigConfigurationChangesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogGroupRetentionPolicySpecificDaysEnabled - CloudWatch log group has a retention policy of at least the configured minimum days or never expires
type CloudwatchLogGroupRetentionPolicySpecificDaysEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogGroupRetentionPolicySpecificDaysEnabled() *CloudwatchLogGroupRetentionPolicySpecificDaysEnabled {
    return &CloudwatchLogGroupRetentionPolicySpecificDaysEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_group_retention_policy_specific_days_enabled",
            CheckTitle: "CloudWatch log group has a retention policy of at least the configured minimum days or never expires",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudWatch Log Groups** are assessed for a retention period at or above the configured threshold (e.g., `365` days) or for being set to **never expire**. Log groups with shorter retention are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogGroupRetentionPolicySpecificDaysEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogGroupRetentionPolicySpecificDaysEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterAwsOrganizationsChanges - CloudWatch Logs metric filter and alarm exist for AWS Organizations changes
type CloudwatchLogMetricFilterAwsOrganizationsChanges struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAwsOrganizationsChanges() *CloudwatchLogMetricFilterAwsOrganizationsChanges {
    return &CloudwatchLogMetricFilterAwsOrganizationsChanges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_aws_organizations_changes",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for AWS Organizations changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudWatch Logs** metric filters and alarms monitor **AWS Organizations** change events recorded by CloudTrail, including actions like `CreateAccount`, `AttachPolicy`, `MoveAccount`, and `UpdateOrganizationalUnit`.  The evaluation looks for a filter on the trail log group matching `organizations.amazonaws.com` events and an alarm linked to that metric.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterAwsOrganizationsChanges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterAwsOrganizationsChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogGroupNoSecretsInLogs - CloudWatch log group contains no secrets in its log events
type CloudwatchLogGroupNoSecretsInLogs struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogGroupNoSecretsInLogs() *CloudwatchLogGroupNoSecretsInLogs {
    return &CloudwatchLogGroupNoSecretsInLogs{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_group_no_secrets_in_logs",
            CheckTitle: "CloudWatch log group contains no secrets in its log events",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudWatch Logs** log groups are analyzed for potential **secrets** embedded in log events across their streams. Detection flags patterns resembling credentials (API keys, passwords, tokens, keys) and reports the secret types and where they appear within the log group.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogGroupNoSecretsInLogs) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogGroupNoSecretsInLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterAuthenticationFailures - Account has a CloudWatch Logs metric filter and alarm for AWS Management Console authentication failures
type CloudwatchLogMetricFilterAuthenticationFailures struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAuthenticationFailures() *CloudwatchLogMetricFilterAuthenticationFailures {
    return &CloudwatchLogMetricFilterAuthenticationFailures{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_authentication_failures",
            CheckTitle: "Account has a CloudWatch Logs metric filter and alarm for AWS Management Console authentication failures",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "CloudWatch Logs metric filter and alarm for **AWS Management Console authentication failures**, sourced from CloudTrail (`eventName=ConsoleLogin`, `errorMessage='Failed authentication'`).  Identifies whether these failures are converted into a metric and actively monitored by an alarm.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterAuthenticationFailures) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterAuthenticationFailures) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchChangesToNetworkGatewaysAlarmConfigured - CloudWatch Logs metric filter and alarm exist for changes to network gateways
type CloudwatchChangesToNetworkGatewaysAlarmConfigured struct {
    metadata models.CheckMetadata
}

func NewCloudwatchChangesToNetworkGatewaysAlarmConfigured() *CloudwatchChangesToNetworkGatewaysAlarmConfigured {
    return &CloudwatchChangesToNetworkGatewaysAlarmConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_changes_to_network_gateways_alarm_configured",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for changes to network gateways",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "CloudWatch log metric filters and alarms for **network gateway changes** are identified by matching CloudTrail events such as `CreateCustomerGateway`, `DeleteCustomerGateway`, `AttachInternetGateway`, `CreateInternetGateway`, `DeleteInternetGateway`, and `DetachInternetGateway` in log groups that receive trail logs.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchChangesToNetworkGatewaysAlarmConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchChangesToNetworkGatewaysAlarmConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchChangesToVpcsAlarmConfigured - AWS account has a CloudWatch Logs metric filter and alarm for VPC changes
type CloudwatchChangesToVpcsAlarmConfigured struct {
    metadata models.CheckMetadata
}

func NewCloudwatchChangesToVpcsAlarmConfigured() *CloudwatchChangesToVpcsAlarmConfigured {
    return &CloudwatchChangesToVpcsAlarmConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_changes_to_vpcs_alarm_configured",
            CheckTitle: "AWS account has a CloudWatch Logs metric filter and alarm for VPC changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudTrail events** for **VPC configuration changes** are captured in CloudWatch Logs with a metric filter and an associated alarm. The filter targets actions like `CreateVpc`, `DeleteVpc`, `ModifyVpcAttribute`, and VPC peering operations to surface when network topology is altered.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchChangesToVpcsAlarmConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchChangesToVpcsAlarmConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchChangesToNetworkAclsAlarmConfigured - CloudWatch log metric filter and alarm exist for Network ACL (NACL) change events
type CloudwatchChangesToNetworkAclsAlarmConfigured struct {
    metadata models.CheckMetadata
}

func NewCloudwatchChangesToNetworkAclsAlarmConfigured() *CloudwatchChangesToNetworkAclsAlarmConfigured {
    return &CloudwatchChangesToNetworkAclsAlarmConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_changes_to_network_acls_alarm_configured",
            CheckTitle: "CloudWatch log metric filter and alarm exist for Network ACL (NACL) change events",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "CloudTrail records for **Network ACL changes** are matched by a CloudWatch Logs metric filter with an associated alarm for events like `CreateNetworkAcl`, `CreateNetworkAclEntry`, `DeleteNetworkAcl`, `DeleteNetworkAclEntry`, `ReplaceNetworkAclEntry`, and `ReplaceNetworkAclAssociation`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchChangesToNetworkAclsAlarmConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchChangesToNetworkAclsAlarmConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled - Bedrock AgentCore log groups have a CloudWatch Logs data protection policy activated
type CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled() *CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled {
    return &CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_group_agentcore_data_protection_policy_enabled",
            CheckTitle: "Bedrock AgentCore log groups have a CloudWatch Logs data protection policy activated",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "Log groups holding **Bedrock AgentCore** agent telemetry have an active CloudWatch Logs **data protection policy**, so sensitive data an agent writes to its own logs is masked at ingestion. A policy attached to the log group or inherited from an account-level policy both satisfy this.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterSecurityGroupChanges - CloudWatch Logs metric filter and alarm exist for security group changes
type CloudwatchLogMetricFilterSecurityGroupChanges struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterSecurityGroupChanges() *CloudwatchLogMetricFilterSecurityGroupChanges {
    return &CloudwatchLogMetricFilterSecurityGroupChanges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_security_group_changes",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for security group changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudTrail** events for **security group configuration changes** are monitored using a **CloudWatch Logs metric filter** with an associated **alarm**. The filter targets actions like `AuthorizeSecurityGroupIngress/Egress`, `RevokeSecurityGroupIngress/Egress`, `CreateSecurityGroup`, and `DeleteSecurityGroup` to surface any security group modifications.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterSecurityGroupChanges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterSecurityGroupChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogGroupNotPubliclyAccessible - CloudWatch Log Group is not publicly accessible
type CloudwatchLogGroupNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogGroupNotPubliclyAccessible() *CloudwatchLogGroupNotPubliclyAccessible {
    return &CloudwatchLogGroupNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_group_not_publicly_accessible",
            CheckTitle: "CloudWatch Log Group is not publicly accessible",
            ServiceName: "cloudwatch",
            Severity: "high",
            Description: "**CloudWatch Log Groups** with resource policies that grant access to any principal are identified. Statements using `Principal:'*'` or wildcard `Resource` that reference a log group ARN indicate that the log group is exposed through a public policy.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogGroupNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogGroupNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterUnauthorizedApiCalls - CloudWatch Logs metric filter and alarm exist for unauthorized API calls
type CloudwatchLogMetricFilterUnauthorizedApiCalls struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterUnauthorizedApiCalls() *CloudwatchLogMetricFilterUnauthorizedApiCalls {
    return &CloudwatchLogMetricFilterUnauthorizedApiCalls{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_unauthorized_api_calls",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for unauthorized API calls",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudWatch Logs** for CloudTrail include a metric filter that matches unauthorized API errors (`$.errorCode='*UnauthorizedOperation'` or `$.errorCode='AccessDenied*'`) and a linked alarm that triggers when events match the filter.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterUnauthorizedApiCalls) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterUnauthorizedApiCalls) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk - Account has a CloudWatch log metric filter and alarm for disabling or scheduled deletion of customer-managed KMS keys
type CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk() *CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk {
    return &CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
            CheckTitle: "Account has a CloudWatch log metric filter and alarm for disabling or scheduled deletion of customer-managed KMS keys",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "CloudTrail events delivered to CloudWatch are evaluated for a **metric filter and alarm** that monitor **KMS CMK state changes**, specifically `DisableKey` and `ScheduleKeyDeletion` from `kms.amazonaws.com`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchChangesToNetworkRouteTablesAlarmConfigured - Account monitors VPC route table changes with a CloudWatch Logs metric filter and alarm
type CloudwatchChangesToNetworkRouteTablesAlarmConfigured struct {
    metadata models.CheckMetadata
}

func NewCloudwatchChangesToNetworkRouteTablesAlarmConfigured() *CloudwatchChangesToNetworkRouteTablesAlarmConfigured {
    return &CloudwatchChangesToNetworkRouteTablesAlarmConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_changes_to_network_route_tables_alarm_configured",
            CheckTitle: "Account monitors VPC route table changes with a CloudWatch Logs metric filter and alarm",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**VPC route table changes** are captured from **CloudTrail logs** by a **CloudWatch Logs metric filter** with an associated **alarm** for events like `CreateRoute`, `CreateRouteTable`, `ReplaceRoute`, `ReplaceRouteTableAssociation`, `DeleteRoute`, `DeleteRouteTable`, and `DisassociateRouteTable`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchChangesToNetworkRouteTablesAlarmConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchChangesToNetworkRouteTablesAlarmConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterPolicyChanges - CloudWatch Logs metric filter and alarm exist for IAM policy changes
type CloudwatchLogMetricFilterPolicyChanges struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterPolicyChanges() *CloudwatchLogMetricFilterPolicyChanges {
    return &CloudwatchLogMetricFilterPolicyChanges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_policy_changes",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for IAM policy changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "CloudWatch uses a metric filter and alarm to track **IAM policy changes** recorded by CloudTrail (e.g., `CreatePolicy`, `DeletePolicy`, version changes, inline policy edits, policy attach/detach). This finding reflects whether that filter and an associated alarm are present on the trail's log group.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterPolicyChanges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterPolicyChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterForS3BucketPolicyChanges - CloudWatch log metric filter and alarm exist for S3 bucket policy changes
type CloudwatchLogMetricFilterForS3BucketPolicyChanges struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterForS3BucketPolicyChanges() *CloudwatchLogMetricFilterForS3BucketPolicyChanges {
    return &CloudwatchLogMetricFilterForS3BucketPolicyChanges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes",
            CheckTitle: "CloudWatch log metric filter and alarm exist for S3 bucket policy changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudTrail** logs are assessed for a **CloudWatch metric filter** matching S3 bucket configuration changes (ACL, policy, CORS, lifecycle, replication; e.g., `PutBucketPolicy`, `DeleteBucketPolicy`) and for an associated **CloudWatch alarm**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterForS3BucketPolicyChanges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterForS3BucketPolicyChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchAlarmActionsAlarmStateConfigured - CloudWatch metric alarm has actions configured for the ALARM state
type CloudwatchAlarmActionsAlarmStateConfigured struct {
    metadata models.CheckMetadata
}

func NewCloudwatchAlarmActionsAlarmStateConfigured() *CloudwatchAlarmActionsAlarmStateConfigured {
    return &CloudwatchAlarmActionsAlarmStateConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_alarm_actions_alarm_state_configured",
            CheckTitle: "CloudWatch metric alarm has actions configured for the ALARM state",
            ServiceName: "cloudwatch",
            Severity: "high",
            Description: "Amazon CloudWatch metric alarms are evaluated for **actions** configured for the `ALARM` state. The finding flags alarms that have no action to execute when their monitored metric crosses its threshold.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchAlarmActionsAlarmStateConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchAlarmActionsAlarmStateConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterSignInWithoutMfa - CloudWatch log metric filter and alarm exist for Management Console sign-in without MFA
type CloudwatchLogMetricFilterSignInWithoutMfa struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterSignInWithoutMfa() *CloudwatchLogMetricFilterSignInWithoutMfa {
    return &CloudwatchLogMetricFilterSignInWithoutMfa{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_sign_in_without_mfa",
            CheckTitle: "CloudWatch log metric filter and alarm exist for Management Console sign-in without MFA",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudTrail logs** in CloudWatch are assessed for a metric filter and alarm that detect console logins where `$.eventName = ConsoleLogin` and `$.additionalEventData.MFAUsed != 'Yes'`.  This reflects whether alerting exists for sign-ins that occur without **MFA**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterSignInWithoutMfa) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterSignInWithoutMfa) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterRootUsage - Account has a CloudWatch Logs metric filter and alarm for root account usage
type CloudwatchLogMetricFilterRootUsage struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterRootUsage() *CloudwatchLogMetricFilterRootUsage {
    return &CloudwatchLogMetricFilterRootUsage{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_root_usage",
            CheckTitle: "Account has a CloudWatch Logs metric filter and alarm for root account usage",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudTrail** logs in CloudWatch include a metric filter for **root account activity** (`{ $.userIdentity.type = 'Root' && $.userIdentity.invokedBy NOT EXISTS && $.eventType != 'AwsServiceEvent' }`) and a linked CloudWatch alarm that triggers when the filter matches.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterRootUsage) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterRootUsage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchAlarmActionsEnabled - CloudWatch metric alarm has actions enabled
type CloudwatchAlarmActionsEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchAlarmActionsEnabled() *CloudwatchAlarmActionsEnabled {
    return &CloudwatchAlarmActionsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_alarm_actions_enabled",
            CheckTitle: "CloudWatch metric alarm has actions enabled",
            ServiceName: "cloudwatch",
            Severity: "high",
            Description: "**CloudWatch metric alarms** are evaluated for **alarm actions** activation (`actions_enabled: true`), enabling state changes to invoke configured notifications or automated responses.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchAlarmActionsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchAlarmActionsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchCrossAccountSharingDisabled - CloudWatch does not allow cross-account sharing
type CloudwatchCrossAccountSharingDisabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchCrossAccountSharingDisabled() *CloudwatchCrossAccountSharingDisabled {
    return &CloudwatchCrossAccountSharingDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_cross_account_sharing_disabled",
            CheckTitle: "CloudWatch does not allow cross-account sharing",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**Amazon CloudWatch** cross-account sharing via the `CloudWatch-CrossAccountSharingRole` allows other AWS accounts to view your metrics, dashboards, and alarms. The presence of this role indicates that sharing is active.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchCrossAccountSharingDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchCrossAccountSharingDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogGroupKmsEncryptionEnabled - CloudWatch log group is encrypted with an AWS KMS key
type CloudwatchLogGroupKmsEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogGroupKmsEncryptionEnabled() *CloudwatchLogGroupKmsEncryptionEnabled {
    return &CloudwatchLogGroupKmsEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_group_kms_encryption_enabled",
            CheckTitle: "CloudWatch log group is encrypted with an AWS KMS key",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudWatch log groups** are assessed for **at-rest encryption** by checking if an **AWS KMS key** is associated with the log group via `kmsKeyId`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogGroupKmsEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogGroupKmsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled - CloudWatch Logs metric filter and alarm exist for CloudTrail configuration changes
type CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled() *CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled {
    return &CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
            CheckTitle: "CloudWatch Logs metric filter and alarm exist for CloudTrail configuration changes",
            ServiceName: "cloudwatch",
            Severity: "medium",
            Description: "**CloudTrail logs** include a **metric filter** for trail configuration events (`CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, `StopLogging`) with an associated **CloudWatch alarm** to alert on matches.  Evaluates the presence of this filter-and-alarm monitoring.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudwatch"},
        },
    }
}

func (c *CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudwatch",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

