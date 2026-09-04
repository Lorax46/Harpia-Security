package guardduty

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// GuarddutyEc2MalwareProtectionEnabled - GuardDuty detector has Malware Protection for EC2 enabled
type GuarddutyEc2MalwareProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyEc2MalwareProtectionEnabled() *GuarddutyEc2MalwareProtectionEnabled {
    return &GuarddutyEc2MalwareProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_ec2_malware_protection_enabled",
            CheckTitle: "GuardDuty detector has Malware Protection for EC2 enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "**GuardDuty detectors** with **Malware Protection for EC2** enabled perform agentless scans of EBS volumes attached to **EC2 instances** and container workloads. Scans can be triggered by suspicious activity or run on-demand to identify malicious files within restored volume snapshots.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyEc2MalwareProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyEc2MalwareProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyEksRuntimeMonitoringEnabled - GuardDuty detector has EKS Runtime Monitoring enabled
type GuarddutyEksRuntimeMonitoringEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyEksRuntimeMonitoringEnabled() *GuarddutyEksRuntimeMonitoringEnabled {
    return &GuarddutyEksRuntimeMonitoringEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_eks_runtime_monitoring_enabled",
            CheckTitle: "GuardDuty detector has EKS Runtime Monitoring enabled",
            ServiceName: "guardduty",
            Severity: "medium",
            Description: "GuardDuty detectors are evaluated for **EKS Runtime Monitoring** being enabled for Amazon EKS. The configuration is at the detector level and relates to visibility into *process, file, and network* activity on EKS nodes and containers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyEksRuntimeMonitoringEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyEksRuntimeMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyDelegatedAdminEnabledAllRegions - GuardDuty has delegated admin configured and is enabled in all regions with organization auto-enable
type GuarddutyDelegatedAdminEnabledAllRegions struct {
    metadata models.CheckMetadata
}

func NewGuarddutyDelegatedAdminEnabledAllRegions() *GuarddutyDelegatedAdminEnabledAllRegions {
    return &GuarddutyDelegatedAdminEnabledAllRegions{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_delegated_admin_enabled_all_regions",
            CheckTitle: "GuardDuty has delegated admin configured and is enabled in all regions with organization auto-enable",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "**Amazon GuardDuty** has a delegated administrator configured at the organization level, detectors are enabled in all opted-in regions, and organization auto-enable is active for new member accounts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyDelegatedAdminEnabledAllRegions) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyDelegatedAdminEnabledAllRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyLambdaProtectionEnabled - GuardDuty detector has Lambda Protection enabled
type GuarddutyLambdaProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyLambdaProtectionEnabled() *GuarddutyLambdaProtectionEnabled {
    return &GuarddutyLambdaProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_lambda_protection_enabled",
            CheckTitle: "GuardDuty detector has Lambda Protection enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "**Amazon GuardDuty detectors** with **Lambda Protection** enabled analyze **Lambda invocation network activity logs** across your account.  Evaluation determines whether the detector has `Lambda Protection` turned on.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyLambdaProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyLambdaProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyIsEnabled - GuardDuty detector is enabled and not suspended
type GuarddutyIsEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyIsEnabled() *GuarddutyIsEnabled {
    return &GuarddutyIsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_is_enabled",
            CheckTitle: "GuardDuty detector is enabled and not suspended",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "**Amazon GuardDuty** detector existence and health are evaluated per Region. It identifies where GuardDuty isn't enabled for the account, where a detector has no status, or where a detector is configured but `suspended`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyIsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyIsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyEksAuditLogEnabled - GuardDuty detector has EKS Audit Log Monitoring enabled
type GuarddutyEksAuditLogEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyEksAuditLogEnabled() *GuarddutyEksAuditLogEnabled {
    return &GuarddutyEksAuditLogEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_eks_audit_log_enabled",
            CheckTitle: "GuardDuty detector has EKS Audit Log Monitoring enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "**Amazon GuardDuty detectors** are evaluated for **EKS Audit Log Monitoring** (`EKS_AUDIT_LOGS`) being enabled to analyze Kubernetes audit activity from your **Amazon EKS** clusters.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyEksAuditLogEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyEksAuditLogEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyRdsProtectionEnabled - GuardDuty detector has RDS Protection enabled
type GuarddutyRdsProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyRdsProtectionEnabled() *GuarddutyRdsProtectionEnabled {
    return &GuarddutyRdsProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_rds_protection_enabled",
            CheckTitle: "GuardDuty detector has RDS Protection enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "Active **Amazon GuardDuty detectors** are assessed for **RDS Protection** being enabled, allowing analysis of RDS and Aurora login activity to profile and flag anomalous access patterns.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyRdsProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyRdsProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyRuntimeMonitoringEnabled - GuardDuty detector has Runtime Monitoring enabled
type GuarddutyRuntimeMonitoringEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyRuntimeMonitoringEnabled() *GuarddutyRuntimeMonitoringEnabled {
    return &GuarddutyRuntimeMonitoringEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_runtime_monitoring_enabled",
            CheckTitle: "GuardDuty detector has Runtime Monitoring enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "GuardDuty detectors are evaluated for unified **Runtime Monitoring** being enabled. The configuration is at the detector level and relates to visibility into *process execution, file access, and network connections* on Amazon EC2 instances, Amazon ECS on AWS Fargate tasks, and Amazon EKS nodes and containers. The legacy EKS-only feature covers Amazon EKS alone and does not satisfy this check.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyRuntimeMonitoringEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyRuntimeMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyNoHighSeverityFindings - GuardDuty detector has no high severity findings
type GuarddutyNoHighSeverityFindings struct {
    metadata models.CheckMetadata
}

func NewGuarddutyNoHighSeverityFindings() *GuarddutyNoHighSeverityFindings {
    return &GuarddutyNoHighSeverityFindings{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_no_high_severity_findings",
            CheckTitle: "GuardDuty detector has no high severity findings",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "**GuardDuty detectors** are evaluated for the presence of **High-severity findings**. This surfaces whether any detector currently has findings labeled `High` by GuardDuty.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyNoHighSeverityFindings) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyNoHighSeverityFindings) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyS3ProtectionEnabled - GuardDuty detector has S3 Protection enabled
type GuarddutyS3ProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyS3ProtectionEnabled() *GuarddutyS3ProtectionEnabled {
    return &GuarddutyS3ProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_s3_protection_enabled",
            CheckTitle: "GuardDuty detector has S3 Protection enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "Amazon GuardDuty detectors are evaluated for **S3 Protection**, which analyzes CloudTrail S3 data events to monitor **object-level API activity** (`GetObject`, `PutObject`, `DeleteObject`) across S3 buckets in the account and Region.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyS3ProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyS3ProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyAiProtectionEnabled - GuardDuty detector has AI Protection enabled
type GuarddutyAiProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewGuarddutyAiProtectionEnabled() *GuarddutyAiProtectionEnabled {
    return &GuarddutyAiProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_ai_protection_enabled",
            CheckTitle: "GuardDuty detector has AI Protection enabled",
            ServiceName: "guardduty",
            Severity: "high",
            Description: "Active **Amazon GuardDuty detectors** are assessed for **AI Protection** being enabled, which analyzes AWS CloudTrail data events from Amazon Bedrock, Amazon Bedrock AgentCore and Amazon SageMaker AI to flag anomalous model invocations, cost harvesting and prompt injection. Detectors that do not report the feature return `MANUAL`, because absence means the Region does not offer it.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyAiProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyAiProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// GuarddutyCentrallyManaged - GuardDuty detector is managed by an administrator account or is the administrator with member accounts
type GuarddutyCentrallyManaged struct {
    metadata models.CheckMetadata
}

func NewGuarddutyCentrallyManaged() *GuarddutyCentrallyManaged {
    return &GuarddutyCentrallyManaged{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "guardduty_centrally_managed",
            CheckTitle: "GuardDuty detector is managed by an administrator account or is the administrator with member accounts",
            ServiceName: "guardduty",
            Severity: "medium",
            Description: "Amazon GuardDuty detectors are under **centralized management** when linked to a delegated administrator account, or when the detector's account serves as the **administrator** with associated member accounts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"guardduty"},
        },
    }
}

func (c *GuarddutyCentrallyManaged) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *GuarddutyCentrallyManaged) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "guardduty",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

