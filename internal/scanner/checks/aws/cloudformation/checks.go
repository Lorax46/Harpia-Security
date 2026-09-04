package cloudformation

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CloudformationStackCdktoolkitBootstrapVersion - CDKToolkit CloudFormation stack has Bootstrap version 21 or higher
type CloudformationStackCdktoolkitBootstrapVersion struct {
    metadata models.CheckMetadata
}

func NewCloudformationStackCdktoolkitBootstrapVersion() *CloudformationStackCdktoolkitBootstrapVersion {
    return &CloudformationStackCdktoolkitBootstrapVersion{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudformation_stack_cdktoolkit_bootstrap_version",
            CheckTitle: "CDKToolkit CloudFormation stack has Bootstrap version 21 or higher",
            ServiceName: "cloudformation",
            Severity: "high",
            Description: "**CloudFormation CDKToolkit** stack's `BootstrapVersion` is compared to a recommended minimum (default `21`). A lower value indicates the environment uses legacy bootstrap resources and IAM roles from older templates.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudformation"},
        },
    }
}

func (c *CloudformationStackCdktoolkitBootstrapVersion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudformationStackCdktoolkitBootstrapVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudformation",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudformationStacksTerminationProtectionEnabled - CloudFormation stack has termination protection enabled
type CloudformationStacksTerminationProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewCloudformationStacksTerminationProtectionEnabled() *CloudformationStacksTerminationProtectionEnabled {
    return &CloudformationStacksTerminationProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudformation_stacks_termination_protection_enabled",
            CheckTitle: "CloudFormation stack has termination protection enabled",
            ServiceName: "cloudformation",
            Severity: "medium",
            Description: "**AWS CloudFormation root stacks** are evaluated for **termination protection**. The detection identifies whether `termination protection` is enabled to block stack deletions on non-nested stacks.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudformation"},
        },
    }
}

func (c *CloudformationStacksTerminationProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudformationStacksTerminationProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudformation",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CloudformationStackOutputsFindSecrets - CloudFormation stack outputs do not contain secrets
type CloudformationStackOutputsFindSecrets struct {
    metadata models.CheckMetadata
}

func NewCloudformationStackOutputsFindSecrets() *CloudformationStackOutputsFindSecrets {
    return &CloudformationStackOutputsFindSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cloudformation_stack_outputs_find_secrets",
            CheckTitle: "CloudFormation stack outputs do not contain secrets",
            ServiceName: "cloudformation",
            Severity: "critical",
            Description: "**CloudFormation stack Outputs** are analyzed for hardcoded secrets-passwords, API keys, tokens-using pattern-based detection across output values. A finding indicates potential secret strings present within `Outputs` of the template or stack.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cloudformation"},
        },
    }
}

func (c *CloudformationStackOutputsFindSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CloudformationStackOutputsFindSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cloudformation",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

