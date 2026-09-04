package iam

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// IamRootHardwareMfaEnabled - Root account has a hardware MFA device enabled
type IamRootHardwareMfaEnabled struct {
    metadata models.CheckMetadata
}

func NewIamRootHardwareMfaEnabled() *IamRootHardwareMfaEnabled {
    return &IamRootHardwareMfaEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_root_hardware_mfa_enabled",
            CheckTitle: "Root account has a hardware MFA device enabled",
            ServiceName: "iam",
            Severity: "critical",
            Description: "**AWS root user** credentials are assessed for **MFA status** and device type. The check detects whether MFA is absent or implemented with a **virtual device** instead of **hardware MFA** on the root user, and notes when centralized root credential management is in effect.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRootHardwareMfaEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRootHardwareMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRootCredentialsManagementEnabled - AWS Organization has centralized root credentials management enabled
type IamRootCredentialsManagementEnabled struct {
    metadata models.CheckMetadata
}

func NewIamRootCredentialsManagementEnabled() *IamRootCredentialsManagementEnabled {
    return &IamRootCredentialsManagementEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_root_credentials_management_enabled",
            CheckTitle: "AWS Organization has centralized root credentials management enabled",
            ServiceName: "iam",
            Severity: "high",
            Description: "**AWS Organizations** uses **centralized root credentials management** to control root user credentials across member accounts.  This finding evaluates whether the organization has enabled the `RootCredentialsManagement` feature to centrally govern presence and recovery of root passwords, access keys, signing certificates, and MFA.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRootCredentialsManagementEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRootCredentialsManagementEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRoleAccessNotStaleToBedrock - Regular Bedrock access ensures IAM roles retain only actively used permissions
type IamRoleAccessNotStaleToBedrock struct {
    metadata models.CheckMetadata
}

func NewIamRoleAccessNotStaleToBedrock() *IamRoleAccessNotStaleToBedrock {
    return &IamRoleAccessNotStaleToBedrock{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_role_access_not_stale_to_bedrock",
            CheckTitle: "Regular Bedrock access ensures IAM roles retain only actively used permissions",
            ServiceName: "iam",
            Severity: "medium",
            Description: "IAM roles granted **Bedrock** permissions are evaluated for recent service usage.  Roles whose last Bedrock access exceeds the configured threshold (default **60 days**) or that have **never** accessed Bedrock are flagged, indicating stale permissions that should be reviewed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRoleAccessNotStaleToBedrock) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRoleAccessNotStaleToBedrock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserConsoleAccessUnused - IAM user console access is disabled, used within the configured inactivity period, or never used
type IamUserConsoleAccessUnused struct {
    metadata models.CheckMetadata
}

func NewIamUserConsoleAccessUnused() *IamUserConsoleAccessUnused {
    return &IamUserConsoleAccessUnused{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_console_access_unused",
            CheckTitle: "IAM user console access is disabled, used within the configured inactivity period, or never used",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM users** with console access are evaluated by `password_last_used`. Inactivity beyond `max_console_access_days` (default `45`) marks **stale console access**.  *Users without console access are excluded*.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserConsoleAccessUnused) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserConsoleAccessUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyNoWildcardMarketplaceSubscribe - Custom IAM policy does not allow 'aws-marketplace:Subscribe' on all resources
type IamPolicyNoWildcardMarketplaceSubscribe struct {
    metadata models.CheckMetadata
}

func NewIamPolicyNoWildcardMarketplaceSubscribe() *IamPolicyNoWildcardMarketplaceSubscribe {
    return &IamPolicyNoWildcardMarketplaceSubscribe{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_no_wildcard_marketplace_subscribe",
            CheckTitle: "Custom IAM policy does not allow 'aws-marketplace:Subscribe' on all resources",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**Customer-managed IAM policies** are examined for statements that grant `aws-marketplace:Subscribe` on all resources (`*`). This action controls the ability to subscribe to AWS Marketplace products, including **Amazon Bedrock foundation models**, and should be scoped to specific product ARNs to enforce least privilege.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyNoWildcardMarketplaceSubscribe) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyNoWildcardMarketplaceSubscribe) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamInlinePolicyNoFullAccessToCloudtrail - Inline IAM policy does not allow 'cloudtrail:*' privileges
type IamInlinePolicyNoFullAccessToCloudtrail struct {
    metadata models.CheckMetadata
}

func NewIamInlinePolicyNoFullAccessToCloudtrail() *IamInlinePolicyNoFullAccessToCloudtrail {
    return &IamInlinePolicyNoFullAccessToCloudtrail{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_inline_policy_no_full_access_to_cloudtrail",
            CheckTitle: "Inline IAM policy does not allow 'cloudtrail:*' privileges",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM inline policies** are evaluated for statements that grant **full CloudTrail permissions** (`cloudtrail:*`) to all resources.  The finding flags identity policies that provide unrestricted control over CloudTrail operations.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamInlinePolicyNoFullAccessToCloudtrail) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamInlinePolicyNoFullAccessToCloudtrail) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicyMinimumLength14 - IAM password policy requires passwords to be at least 14 characters long
type IamPasswordPolicyMinimumLength14 struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicyMinimumLength14() *IamPasswordPolicyMinimumLength14 {
    return &IamPasswordPolicyMinimumLength14{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_minimum_length_14",
            CheckTitle: "IAM password policy requires passwords to be at least 14 characters long",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM password policy** is assessed for the **minimum password length** setting, confirming it meets `>= 14` characters for IAM console users.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicyMinimumLength14) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicyMinimumLength14) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamInlinePolicyAllowsPrivilegeEscalation - IAM inline policy does not allow privilege escalation
type IamInlinePolicyAllowsPrivilegeEscalation struct {
    metadata models.CheckMetadata
}

func NewIamInlinePolicyAllowsPrivilegeEscalation() *IamInlinePolicyAllowsPrivilegeEscalation {
    return &IamInlinePolicyAllowsPrivilegeEscalation{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_inline_policy_allows_privilege_escalation",
            CheckTitle: "IAM inline policy does not allow privilege escalation",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM inline policies** are evaluated for permission combinations that enable **privilege escalation**, such as `sts:AssumeRole`, `iam:PassRole`, attaching/editing policies, or broad wildcards. The result highlights inline policies that allow a principal to obtain higher effective access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamInlinePolicyAllowsPrivilegeEscalation) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamInlinePolicyAllowsPrivilegeEscalation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamCustomerAttachedPolicyNoAdministrativePrivileges - Attached IAM customer-managed policy does not allow '*:*' administrative privileges
type IamCustomerAttachedPolicyNoAdministrativePrivileges struct {
    metadata models.CheckMetadata
}

func NewIamCustomerAttachedPolicyNoAdministrativePrivileges() *IamCustomerAttachedPolicyNoAdministrativePrivileges {
    return &IamCustomerAttachedPolicyNoAdministrativePrivileges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_customer_attached_policy_no_administrative_privileges",
            CheckTitle: "Attached IAM customer-managed policy does not allow '*:*' administrative privileges",
            ServiceName: "iam",
            Severity: "high",
            Description: "Attached **customer-managed IAM policies** are evaluated for statements granting full admin access via `Action: '*'`, `Resource: '*'`, i.e., `*:*`. Only policies you created and attached to identities are considered.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamCustomerAttachedPolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamCustomerAttachedPolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamCheckSamlProvidersSts - IAM SAML provider exists in the account
type IamCheckSamlProvidersSts struct {
    metadata models.CheckMetadata
}

func NewIamCheckSamlProvidersSts() *IamCheckSamlProvidersSts {
    return &IamCheckSamlProvidersSts{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_check_saml_providers_sts",
            CheckTitle: "IAM SAML provider exists in the account",
            ServiceName: "iam",
            Severity: "low",
            Description: "**IAM SAML providers** enable **federated role assumption** via STS `AssumeRoleWithSAML`.  This evaluates whether such providers exist in the account.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamCheckSamlProvidersSts) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamCheckSamlProvidersSts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRotateAccessKey90Days - IAM user does not have active access keys older than 90 days
type IamRotateAccessKey90Days struct {
    metadata models.CheckMetadata
}

func NewIamRotateAccessKey90Days() *IamRotateAccessKey90Days {
    return &IamRotateAccessKey90Days{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_rotate_access_key_90_days",
            CheckTitle: "IAM user does not have active access keys older than 90 days",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM user access keys** are assessed via the credential report. For each active key, the `last_rotated` timestamp is compared to `90 days`; keys exceeding this age are identified. Users without keys or with only recent rotations are noted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRotateAccessKey90Days) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRotateAccessKey90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserHardwareMfaEnabled - IAM user has hardware MFA enabled
type IamUserHardwareMfaEnabled struct {
    metadata models.CheckMetadata
}

func NewIamUserHardwareMfaEnabled() *IamUserHardwareMfaEnabled {
    return &IamUserHardwareMfaEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_hardware_mfa_enabled",
            CheckTitle: "IAM user has hardware MFA enabled",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM users** are evaluated for **hardware MFA** enrollment, identifying physical tokens or security keys and distinguishing them from *virtual* or *SMS* MFA, as well as users without any MFA.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserHardwareMfaEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserHardwareMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicyLowercase - IAM password policy requires at least one lowercase letter
type IamPasswordPolicyLowercase struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicyLowercase() *IamPasswordPolicyLowercase {
    return &IamPasswordPolicyLowercase{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_lowercase",
            CheckTitle: "IAM password policy requires at least one lowercase letter",
            ServiceName: "iam",
            Severity: "low",
            Description: "**IAM password policy** requires at least one **lowercase** character in user passwords via the `Require lowercase` setting",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicyLowercase) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicyLowercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyAttachedOnlyToGroupOrRoles - IAM user has no inline or attached policies
type IamPolicyAttachedOnlyToGroupOrRoles struct {
    metadata models.CheckMetadata
}

func NewIamPolicyAttachedOnlyToGroupOrRoles() *IamPolicyAttachedOnlyToGroupOrRoles {
    return &IamPolicyAttachedOnlyToGroupOrRoles{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_attached_only_to_group_or_roles",
            CheckTitle: "IAM user has no inline or attached policies",
            ServiceName: "iam",
            Severity: "low",
            Description: "**IAM users** have identity-based policies attached directly (managed or inline) instead of inheriting permissions via **groups** or **roles**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyAttachedOnlyToGroupOrRoles) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyAttachedOnlyToGroupOrRoles) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRootMfaEnabled - Root account has MFA enabled
type IamRootMfaEnabled struct {
    metadata models.CheckMetadata
}

func NewIamRootMfaEnabled() *IamRootMfaEnabled {
    return &IamRootMfaEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_root_mfa_enabled",
            CheckTitle: "Root account has MFA enabled",
            ServiceName: "iam",
            Severity: "critical",
            Description: "**AWS root user** with active credentials is assessed for **MFA activation**. The evaluation considers whether the root identity has a password or access keys and whether **MFA is enabled**.  *If centralized root access is enabled in Organizations, the presence of individual root credentials is also noted.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRootMfaEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRootMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamNoCustomPolicyPermissiveRoleAssumption - Custom IAM policy does not allow STS role assumption on wildcard resources
type IamNoCustomPolicyPermissiveRoleAssumption struct {
    metadata models.CheckMetadata
}

func NewIamNoCustomPolicyPermissiveRoleAssumption() *IamNoCustomPolicyPermissiveRoleAssumption {
    return &IamNoCustomPolicyPermissiveRoleAssumption{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_no_custom_policy_permissive_role_assumption",
            CheckTitle: "Custom IAM policy does not allow STS role assumption on wildcard resources",
            ServiceName: "iam",
            Severity: "high",
            Description: "**Custom IAM policies** with `Allow` statements that grant `sts:AssumeRole` (or `sts:*`/`*`) to a wildcard `Resource`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamNoCustomPolicyPermissiveRoleAssumption) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamNoCustomPolicyPermissiveRoleAssumption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamNoExpiredServerCertificatesStored - IAM server certificate is not expired
type IamNoExpiredServerCertificatesStored struct {
    metadata models.CheckMetadata
}

func NewIamNoExpiredServerCertificatesStored() *IamNoExpiredServerCertificatesStored {
    return &IamNoExpiredServerCertificatesStored{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_no_expired_server_certificates_stored",
            CheckTitle: "IAM server certificate is not expired",
            ServiceName: "iam",
            Severity: "high",
            Description: "IAM server certificates stored in **AWS IAM** are evaluated for **expiration** by comparing their validity period to the current time. Certificates with a `NotAfter` date in the past are identified as expired.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamNoExpiredServerCertificatesStored) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamNoExpiredServerCertificatesStored) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicyUppercase - IAM password policy requires at least one uppercase letter
type IamPasswordPolicyUppercase struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicyUppercase() *IamPasswordPolicyUppercase {
    return &IamPasswordPolicyUppercase{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_uppercase",
            CheckTitle: "IAM password policy requires at least one uppercase letter",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM account password policy** enforces the presence of **at least one uppercase letter** (`A-Z`) in IAM user passwords.  *This evaluates whether the uppercase complexity rule is enabled for console passwords.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicyUppercase) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicyUppercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRoleCrossServiceConfusedDeputyPrevention - IAM service role prevents cross-service confused deputy attack
type IamRoleCrossServiceConfusedDeputyPrevention struct {
    metadata models.CheckMetadata
}

func NewIamRoleCrossServiceConfusedDeputyPrevention() *IamRoleCrossServiceConfusedDeputyPrevention {
    return &IamRoleCrossServiceConfusedDeputyPrevention{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_role_cross_service_confused_deputy_prevention",
            CheckTitle: "IAM service role prevents cross-service confused deputy attack",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM service role** trust policies restrict **AWS service principals** to expected sources using global condition keys like `aws:SourceArn` or `aws:SourceAccount`, avoiding overly broad `sts:AssumeRole` trust relationships.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRoleCrossServiceConfusedDeputyPrevention) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRoleCrossServiceConfusedDeputyPrevention) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamCustomerUnattachedPolicyNoAdministrativePrivileges - Unattached customer managed IAM policy does not allow '*:*' administrative privileges
type IamCustomerUnattachedPolicyNoAdministrativePrivileges struct {
    metadata models.CheckMetadata
}

func NewIamCustomerUnattachedPolicyNoAdministrativePrivileges() *IamCustomerUnattachedPolicyNoAdministrativePrivileges {
    return &IamCustomerUnattachedPolicyNoAdministrativePrivileges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_customer_unattached_policy_no_administrative_privileges",
            CheckTitle: "Unattached customer managed IAM policy does not allow '*:*' administrative privileges",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**Customer-managed IAM policies** that are **unattached** are evaluated for statements granting **full administrative access** using `*:*` wildcards.  The focus is on policies whose documents include unrestricted actions on all resources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamCustomerUnattachedPolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamCustomerUnattachedPolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamInlinePolicyNoWildcardMarketplaceSubscribe - Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources
type IamInlinePolicyNoWildcardMarketplaceSubscribe struct {
    metadata models.CheckMetadata
}

func NewIamInlinePolicyNoWildcardMarketplaceSubscribe() *IamInlinePolicyNoWildcardMarketplaceSubscribe {
    return &IamInlinePolicyNoWildcardMarketplaceSubscribe{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_inline_policy_no_wildcard_marketplace_subscribe",
            CheckTitle: "Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM inline policies** are analyzed to identify statements that grant `aws-marketplace:Subscribe` on all resources (`*`). This action controls the ability to subscribe to AWS Marketplace products, including **Amazon Bedrock foundation models**, and should be scoped to specific product ARNs to enforce least privilege.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamInlinePolicyNoWildcardMarketplaceSubscribe) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamInlinePolicyNoWildcardMarketplaceSubscribe) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyAllowsPrivilegeEscalation - Customer managed IAM policy does not allow actions that can lead to privilege escalation
type IamPolicyAllowsPrivilegeEscalation struct {
    metadata models.CheckMetadata
}

func NewIamPolicyAllowsPrivilegeEscalation() *IamPolicyAllowsPrivilegeEscalation {
    return &IamPolicyAllowsPrivilegeEscalation{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_allows_privilege_escalation",
            CheckTitle: "Customer managed IAM policy does not allow actions that can lead to privilege escalation",
            ServiceName: "iam",
            Severity: "high",
            Description: "**Customer-managed IAM policies** are evaluated for **permissions that enable privilege escalation**, including creating or updating policies, altering role trust, attaching higher-privilege policies, or using `iam:PassRole` to obtain broader access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyAllowsPrivilegeEscalation) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyAllowsPrivilegeEscalation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicyNumber - IAM password policy requires at least one number
type IamPasswordPolicyNumber struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicyNumber() *IamPasswordPolicyNumber {
    return &IamPasswordPolicyNumber{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_number",
            CheckTitle: "IAM password policy requires at least one number",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM account password policy** requires at least one **numeric character** (`0-9`) in IAM user passwords",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicyNumber) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicyNumber) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicySymbol - IAM password policy requires at least one symbol
type IamPasswordPolicySymbol struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicySymbol() *IamPasswordPolicySymbol {
    return &IamPasswordPolicySymbol{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_symbol",
            CheckTitle: "IAM password policy requires at least one symbol",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM account password policy** includes the `Require at least one non-alphanumeric character` rule for IAM user passwords",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicySymbol) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicySymbol) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamGroupAdministratorAccessPolicy - IAM group does not have AdministratorAccess policy attached
type IamGroupAdministratorAccessPolicy struct {
    metadata models.CheckMetadata
}

func NewIamGroupAdministratorAccessPolicy() *IamGroupAdministratorAccessPolicy {
    return &IamGroupAdministratorAccessPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_group_administrator_access_policy",
            CheckTitle: "IAM group does not have AdministratorAccess policy attached",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM groups** are assessed for the AWS-managed `AdministratorAccess` policy attachment.  The finding reports any group that has this policy among its attached permissions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamGroupAdministratorAccessPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamGroupAdministratorAccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamAwsAttachedPolicyNoAdministrativePrivileges - Attached AWS-managed IAM policy does not allow '*:*' administrative privileges
type IamAwsAttachedPolicyNoAdministrativePrivileges struct {
    metadata models.CheckMetadata
}

func NewIamAwsAttachedPolicyNoAdministrativePrivileges() *IamAwsAttachedPolicyNoAdministrativePrivileges {
    return &IamAwsAttachedPolicyNoAdministrativePrivileges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_aws_attached_policy_no_administrative_privileges",
            CheckTitle: "Attached AWS-managed IAM policy does not allow '*:*' administrative privileges",
            ServiceName: "iam",
            Severity: "critical",
            Description: "**IAM AWS-managed policies** attached to identities are inspected for statements that allow `Action:'*'` on `Resource:'*'`-i.e., full administrative `*:*` permissions",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamAwsAttachedPolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamAwsAttachedPolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamAvoidRootUsage - AWS account root user has not been used in the last day
type IamAvoidRootUsage struct {
    metadata models.CheckMetadata
}

func NewIamAvoidRootUsage() *IamAvoidRootUsage {
    return &IamAvoidRootUsage{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_avoid_root_usage",
            CheckTitle: "AWS account root user has not been used in the last day",
            ServiceName: "iam",
            Severity: "high",
            Description: "**AWS IAM root user** activity is assessed by inspecting `last-used` timestamps for the root password and access keys. The finding indicates when the root identity has been used recently for console or programmatic access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamAvoidRootUsage) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamAvoidRootUsage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserAccessNotStaleToSagemaker - Regular SageMaker access ensures IAM users retain only actively used permissions
type IamUserAccessNotStaleToSagemaker struct {
    metadata models.CheckMetadata
}

func NewIamUserAccessNotStaleToSagemaker() *IamUserAccessNotStaleToSagemaker {
    return &IamUserAccessNotStaleToSagemaker{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_access_not_stale_to_sagemaker",
            CheckTitle: "Regular SageMaker access ensures IAM users retain only actively used permissions",
            ServiceName: "iam",
            Severity: "medium",
            Description: "IAM users granted **SageMaker** permissions are evaluated for recent service usage.  Users whose last SageMaker access exceeds the configured threshold (default **90 days**) or that have **never** accessed SageMaker are flagged, indicating stale permissions that should be reviewed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserAccessNotStaleToSagemaker) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserAccessNotStaleToSagemaker) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicyReuse24 - IAM password policy prevents reuse of the last 24 passwords
type IamPasswordPolicyReuse24 struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicyReuse24() *IamPasswordPolicyReuse24 {
    return &IamPasswordPolicyReuse24{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_reuse_24",
            CheckTitle: "IAM password policy prevents reuse of the last 24 passwords",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM account password policy** uses **password reuse prevention** set to `24` remembered passwords (maximum history) for IAM users",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicyReuse24) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicyReuse24) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserNoSetupInitialAccessKey - IAM user does not have active access keys that have never been used
type IamUserNoSetupInitialAccessKey struct {
    metadata models.CheckMetadata
}

func NewIamUserNoSetupInitialAccessKey() *IamUserNoSetupInitialAccessKey {
    return &IamUserNoSetupInitialAccessKey{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_no_setup_initial_access_key",
            CheckTitle: "IAM user does not have active access keys that have never been used",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM users** with a console password and active **access keys** that have `last_used` as `N/A` are identified.  This highlights accounts where programmatic credentials exist but have never been exercised.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserNoSetupInitialAccessKey) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserNoSetupInitialAccessKey) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserAdministratorAccessPolicy - IAM user does not have AdministratorAccess policy attached
type IamUserAdministratorAccessPolicy struct {
    metadata models.CheckMetadata
}

func NewIamUserAdministratorAccessPolicy() *IamUserAdministratorAccessPolicy {
    return &IamUserAdministratorAccessPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_administrator_access_policy",
            CheckTitle: "IAM user does not have AdministratorAccess policy attached",
            ServiceName: "iam",
            Severity: "critical",
            Description: "**IAM users** are evaluated for a direct attachment of the AWS managed policy `AdministratorAccess`. The finding identifies identities where this policy appears among the user's attached policies.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserAdministratorAccessPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserAdministratorAccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRoleCrossAccountReadonlyaccessPolicy - IAM role does not grant ReadOnlyAccess to external AWS accounts
type IamRoleCrossAccountReadonlyaccessPolicy struct {
    metadata models.CheckMetadata
}

func NewIamRoleCrossAccountReadonlyaccessPolicy() *IamRoleCrossAccountReadonlyaccessPolicy {
    return &IamRoleCrossAccountReadonlyaccessPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_role_cross_account_readonlyaccess_policy",
            CheckTitle: "IAM role does not grant ReadOnlyAccess to external AWS accounts",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM roles** are assessed for the AWS-managed **ReadOnlyAccess** policy combined with a trust policy that allows **external AWS principals** or `*`. This identifies roles that expose broad read permissions to other accounts.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRoleCrossAccountReadonlyaccessPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRoleCrossAccountReadonlyaccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyNoAgentcoreWorkloadAccessTokenWildcard - Custom IAM policy scopes Bedrock AgentCore workload access token retrieval to workload identity ARNs
type IamPolicyNoAgentcoreWorkloadAccessTokenWildcard struct {
    metadata models.CheckMetadata
}

func NewIamPolicyNoAgentcoreWorkloadAccessTokenWildcard() *IamPolicyNoAgentcoreWorkloadAccessTokenWildcard {
    return &IamPolicyNoAgentcoreWorkloadAccessTokenWildcard{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_no_agentcore_workload_access_token_wildcard",
            CheckTitle: "Custom IAM policy scopes Bedrock AgentCore workload access token retrieval to workload identity ARNs",
            ServiceName: "iam",
            Severity: "high",
            Description: "**Customer-managed IAM policies** are examined for `Allow` statements granting `bedrock-agentcore:GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT` or `GetWorkloadAccessTokenForUserId` over resources that reach a workload identity other than the caller's own -- `*`, or an AgentCore ARN whose resource field wildcards past `workload-identity-directory`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyNoAgentcoreWorkloadAccessTokenWildcard) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyNoAgentcoreWorkloadAccessTokenWildcard) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamInlinePolicyNoFullAccessToKms - Inline IAM policy does not allow kms:* privileges
type IamInlinePolicyNoFullAccessToKms struct {
    metadata models.CheckMetadata
}

func NewIamInlinePolicyNoFullAccessToKms() *IamInlinePolicyNoFullAccessToKms {
    return &IamInlinePolicyNoFullAccessToKms{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_inline_policy_no_full_access_to_kms",
            CheckTitle: "Inline IAM policy does not allow kms:* privileges",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM inline policies** are analyzed to identify statements that grant **unrestricted AWS KMS access** via the wildcard action `kms:*`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamInlinePolicyNoFullAccessToKms) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamInlinePolicyNoFullAccessToKms) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRoleAdministratoraccessPolicy - IAM role does not have AdministratorAccess policy attached
type IamRoleAdministratoraccessPolicy struct {
    metadata models.CheckMetadata
}

func NewIamRoleAdministratoraccessPolicy() *IamRoleAdministratoraccessPolicy {
    return &IamRoleAdministratoraccessPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_role_administratoraccess_policy",
            CheckTitle: "IAM role does not have AdministratorAccess policy attached",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM roles** (excluding service roles) are evaluated for attachment of the AWS-managed `AdministratorAccess` policy.  Attachment indicates the role holds unrestricted permissions across services and resources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRoleAdministratoraccessPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRoleAdministratoraccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyNoFullAccessToCloudtrail - Customer managed IAM policy does not allow cloudtrail:* privileges
type IamPolicyNoFullAccessToCloudtrail struct {
    metadata models.CheckMetadata
}

func NewIamPolicyNoFullAccessToCloudtrail() *IamPolicyNoFullAccessToCloudtrail {
    return &IamPolicyNoFullAccessToCloudtrail{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_no_full_access_to_cloudtrail",
            CheckTitle: "Customer managed IAM policy does not allow cloudtrail:* privileges",
            ServiceName: "iam",
            Severity: "medium",
            Description: "Custom IAM policies are reviewed for statements that grant **full CloudTrail access** via the `cloudtrail:*` wildcard, indicating unrestricted permission to all CloudTrail actions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyNoFullAccessToCloudtrail) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyNoFullAccessToCloudtrail) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyNoFullAccessToKms - Custom IAM policy does not allow 'kms:*' privileges
type IamPolicyNoFullAccessToKms struct {
    metadata models.CheckMetadata
}

func NewIamPolicyNoFullAccessToKms() *IamPolicyNoFullAccessToKms {
    return &IamPolicyNoFullAccessToKms{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_no_full_access_to_kms",
            CheckTitle: "Custom IAM policy does not allow 'kms:*' privileges",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**Customer-managed IAM policies** are examined for statements that grant **AWS KMS** full access using `kms:*`. The focus is on policies allowing service-wide actions rather than narrowly scoped, key-specific permissions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyNoFullAccessToKms) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyNoFullAccessToKms) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyCloudshellAdminNotAttached - No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached
type IamPolicyCloudshellAdminNotAttached struct {
    metadata models.CheckMetadata
}

func NewIamPolicyCloudshellAdminNotAttached() *IamPolicyCloudshellAdminNotAttached {
    return &IamPolicyCloudshellAdminNotAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_cloudshell_admin_not_attached",
            CheckTitle: "No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM identities** with the AWS managed policy `AWSCloudShellFullAccess` attached are identified across users, groups, and roles.  This indicates principals are granted `cloudshell:*` on `*`, enabling full CloudShell features, including environment startup and file transfer.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyCloudshellAdminNotAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyCloudshellAdminNotAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamRoleServiceTrustRestrictsSourceToAccount - IAM role trust policy confines AWS service principals to a specific source account
type IamRoleServiceTrustRestrictsSourceToAccount struct {
    metadata models.CheckMetadata
}

func NewIamRoleServiceTrustRestrictsSourceToAccount() *IamRoleServiceTrustRestrictsSourceToAccount {
    return &IamRoleServiceTrustRestrictsSourceToAccount{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_role_service_trust_restricts_source_to_account",
            CheckTitle: "IAM role trust policy confines AWS service principals to a specific source account",
            ServiceName: "iam",
            Severity: "medium",
            Description: "Trust-policy statements letting an **AWS service principal** call `sts:AssumeRole` confine the request source to one account -- via `aws:SourceAccount`, an account-bearing `aws:SourceArn`, or an organization-scoped source. Scope: statements whose condition binds no account, and trust policies that are not a plain service role. Unconditional service roles go to the related check.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamRoleServiceTrustRestrictsSourceToAccount) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamRoleServiceTrustRestrictsSourceToAccount) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserWithTemporaryCredentials - IAM user does not use long-lived credentials to access services other than IAM or STS
type IamUserWithTemporaryCredentials struct {
    metadata models.CheckMetadata
}

func NewIamUserWithTemporaryCredentials() *IamUserWithTemporaryCredentials {
    return &IamUserWithTemporaryCredentials{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_with_temporary_credentials",
            CheckTitle: "IAM user does not use long-lived credentials to access services other than IAM or STS",
            ServiceName: "iam",
            Severity: "high",
            Description: "IAM users are assessed for activity using **long-lived access keys**. Use of static credentials to access services other than IAM or STS indicates reliance on permanent keys instead of **temporary role-based credentials**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserWithTemporaryCredentials) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserWithTemporaryCredentials) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPolicyPassroleToBedrockAgentcoreRestricted - Custom IAM policy restricts iam:PassRole to Bedrock AgentCore to specific roles
type IamPolicyPassroleToBedrockAgentcoreRestricted struct {
    metadata models.CheckMetadata
}

func NewIamPolicyPassroleToBedrockAgentcoreRestricted() *IamPolicyPassroleToBedrockAgentcoreRestricted {
    return &IamPolicyPassroleToBedrockAgentcoreRestricted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_policy_passrole_to_bedrock_agentcore_restricted",
            CheckTitle: "Custom IAM policy restricts iam:PassRole to Bedrock AgentCore to specific roles",
            ServiceName: "iam",
            Severity: "high",
            Description: "**Customer-managed IAM policies** are examined for `Allow` statements granting `iam:PassRole` over every role -- `Resource` `*`, or an IAM ARN whose resource field is nothing but wildcards -- where the passed role can reach **Bedrock AgentCore**: the statement pins `iam:PassedToService` to an AgentCore principal, or sets no such condition while the policy allows an AgentCore action.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPolicyPassroleToBedrockAgentcoreRestricted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPolicyPassroleToBedrockAgentcoreRestricted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamSupportRoleCreated - At least one IAM role has the AWSSupportAccess managed policy attached
type IamSupportRoleCreated struct {
    metadata models.CheckMetadata
}

func NewIamSupportRoleCreated() *IamSupportRoleCreated {
    return &IamSupportRoleCreated{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_support_role_created",
            CheckTitle: "At least one IAM role has the AWSSupportAccess managed policy attached",
            ServiceName: "iam",
            Severity: "low",
            Description: "Presence of an **IAM role** that has the AWS managed `AWSSupportAccess` policy attached, designating a support role for interacting with **AWS Support Center** and related tooling.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamSupportRoleCreated) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamSupportRoleCreated) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserAccesskeyUnused - IAM user does not have unused access keys older than 45 days
type IamUserAccesskeyUnused struct {
    metadata models.CheckMetadata
}

func NewIamUserAccesskeyUnused() *IamUserAccesskeyUnused {
    return &IamUserAccesskeyUnused{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_accesskey_unused",
            CheckTitle: "IAM user does not have unused access keys older than 45 days",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM users** are evaluated for **active access keys** whose `last-used` timestamp exceeds `max_unused_access_keys_days` (default `45`). Users without access keys, or whose keys were used within this window, are reported separately.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserAccesskeyUnused) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserAccesskeyUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamAdministratorAccessWithMfa - IAM group members granted AdministratorAccess have MFA enabled
type IamAdministratorAccessWithMfa struct {
    metadata models.CheckMetadata
}

func NewIamAdministratorAccessWithMfa() *IamAdministratorAccessWithMfa {
    return &IamAdministratorAccessWithMfa{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_administrator_access_with_mfa",
            CheckTitle: "IAM group members granted AdministratorAccess have MFA enabled",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM groups** with the `AdministratorAccess` managed policy are assessed to ensure all member users have **active MFA**.  The finding highlights any administrator group that includes a user without MFA enrollment or activation.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamAdministratorAccessWithMfa) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamAdministratorAccessWithMfa) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserAccessNotStaleToBedrock - Regular Bedrock access ensures IAM users retain only actively used permissions
type IamUserAccessNotStaleToBedrock struct {
    metadata models.CheckMetadata
}

func NewIamUserAccessNotStaleToBedrock() *IamUserAccessNotStaleToBedrock {
    return &IamUserAccessNotStaleToBedrock{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_access_not_stale_to_bedrock",
            CheckTitle: "Regular Bedrock access ensures IAM users retain only actively used permissions",
            ServiceName: "iam",
            Severity: "medium",
            Description: "IAM users granted **Bedrock** permissions are evaluated for recent service usage.  Users whose last Bedrock access exceeds the configured threshold (default **60 days**) or that have **never** accessed Bedrock are flagged, indicating stale permissions that should be reviewed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserAccessNotStaleToBedrock) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserAccessNotStaleToBedrock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamInlinePolicyNoAdministrativePrivileges - Inline IAM policy does not allow '*:*' administrative privileges
type IamInlinePolicyNoAdministrativePrivileges struct {
    metadata models.CheckMetadata
}

func NewIamInlinePolicyNoAdministrativePrivileges() *IamInlinePolicyNoAdministrativePrivileges {
    return &IamInlinePolicyNoAdministrativePrivileges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_inline_policy_no_administrative_privileges",
            CheckTitle: "Inline IAM policy does not allow '*:*' administrative privileges",
            ServiceName: "iam",
            Severity: "critical",
            Description: "**IAM inline policies** on identities are evaluated for statements allowing `Action:'*'` on `Resource:'*'`, which indicates **unrestricted administrative access**.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamInlinePolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamInlinePolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamNoRootAccessKey - Root account has no active access keys
type IamNoRootAccessKey struct {
    metadata models.CheckMetadata
}

func NewIamNoRootAccessKey() *IamNoRootAccessKey {
    return &IamNoRootAccessKey{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_no_root_access_key",
            CheckTitle: "Root account has no active access keys",
            ServiceName: "iam",
            Severity: "critical",
            Description: "**AWS root user** is evaluated for **active access keys**. It identifies whether the root identity has one or two programmatic credentials and notes when organization-level root credential management is present.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamNoRootAccessKey) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamNoRootAccessKey) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserMfaEnabledConsoleAccess - IAM user has MFA enabled for console access or no console password is set
type IamUserMfaEnabledConsoleAccess struct {
    metadata models.CheckMetadata
}

func NewIamUserMfaEnabledConsoleAccess() *IamUserMfaEnabledConsoleAccess {
    return &IamUserMfaEnabledConsoleAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_mfa_enabled_console_access",
            CheckTitle: "IAM user has MFA enabled for console access or no console password is set",
            ServiceName: "iam",
            Severity: "high",
            Description: "**IAM users** that have a console password are expected to have **multi-factor authentication** enabled. The evaluation identifies users who can sign in to the AWS Management Console but do not have an active MFA device associated.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserMfaEnabledConsoleAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserMfaEnabledConsoleAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess - IAM account password policy enforces password expiration within 90 days or less
type IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess struct {
    metadata models.CheckMetadata
}

func NewIamPasswordPolicyExpiresPasswordsWithin90DaysOrLess() *IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess {
    return &IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_password_policy_expires_passwords_within_90_days_or_less",
            CheckTitle: "IAM account password policy enforces password expiration within 90 days or less",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM account password policy** sets a **password expiration period** for IAM user console logins; configuration is aligned when rotation is enabled and set to `<= 90` days.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamSecurityauditRoleCreated - At least one IAM role has the SecurityAudit AWS managed policy attached
type IamSecurityauditRoleCreated struct {
    metadata models.CheckMetadata
}

func NewIamSecurityauditRoleCreated() *IamSecurityauditRoleCreated {
    return &IamSecurityauditRoleCreated{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_securityaudit_role_created",
            CheckTitle: "At least one IAM role has the SecurityAudit AWS managed policy attached",
            ServiceName: "iam",
            Severity: "low",
            Description: "**IAM roles** with the AWS managed `SecurityAudit` policy (`arn:aws:iam::aws:policy/SecurityAudit`) are identified. The focus is on whether a role exists that grants read-only visibility into security-relevant configuration across AWS services.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamSecurityauditRoleCreated) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamSecurityauditRoleCreated) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// IamUserTwoActiveAccessKey - IAM user has at most one active access key
type IamUserTwoActiveAccessKey struct {
    metadata models.CheckMetadata
}

func NewIamUserTwoActiveAccessKey() *IamUserTwoActiveAccessKey {
    return &IamUserTwoActiveAccessKey{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "iam_user_two_active_access_key",
            CheckTitle: "IAM user has at most one active access key",
            ServiceName: "iam",
            Severity: "medium",
            Description: "**IAM users** are evaluated for having **two `Active` access keys** simultaneously.  The check identifies users whose two access key slots are enabled at the same time.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"iam"},
        },
    }
}

func (c *IamUserTwoActiveAccessKey) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *IamUserTwoActiveAccessKey) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "iam",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

