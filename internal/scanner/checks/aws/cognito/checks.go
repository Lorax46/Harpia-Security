package cognito

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CognitoUserPoolBlocksCompromisedCredentialsSignInAttempts - Cognito user pool blocks sign-in attempts with suspected compromised credentials
type CognitoUserPoolBlocksCompromisedCredentialsSignInAttempts struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolBlocksCompromisedCredentialsSignInAttempts() *CognitoUserPoolBlocksCompromisedCredentialsSignInAttempts {
    return &CognitoUserPoolBlocksCompromisedCredentialsSignInAttempts{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_blocks_compromised_credentials_sign_in_attempts",
            CheckTitle: "Cognito user pool blocks sign-in attempts with suspected compromised credentials",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "Amazon Cognito user pool threat protection **blocks sign-ins** when **compromised credentials** are detected. Advanced security is `ENFORCED`, and the compromised-credentials policy applies a `BLOCK` action to sign-in events.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolBlocksCompromisedCredentialsSignInAttempts) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolBlocksCompromisedCredentialsSignInAttempts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolClientPreventUserExistenceErrors - Amazon Cognito user pool client has Prevent User Existence Errors enabled
type CognitoUserPoolClientPreventUserExistenceErrors struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolClientPreventUserExistenceErrors() *CognitoUserPoolClientPreventUserExistenceErrors {
    return &CognitoUserPoolClientPreventUserExistenceErrors{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_client_prevent_user_existence_errors",
            CheckTitle: "Amazon Cognito user pool client has Prevent User Existence Errors enabled",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "Amazon Cognito app clients use `PreventUserExistenceErrors` to suppress **user-existence disclosures**, keeping authentication, confirmation, and recovery responses generic rather than indicating whether a username exists.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolClientPreventUserExistenceErrors) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolClientPreventUserExistenceErrors) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolPasswordPolicyMinimumLength14 - Cognito user pool has a password policy with a minimum length of 14 characters or more
type CognitoUserPoolPasswordPolicyMinimumLength14 struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyMinimumLength14() *CognitoUserPoolPasswordPolicyMinimumLength14 {
    return &CognitoUserPoolPasswordPolicyMinimumLength14{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_password_policy_minimum_length_14",
            CheckTitle: "Cognito user pool has a password policy with a minimum length of 14 characters or more",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** should have a **password policy** requiring a **minimum length** of `14`.  This evaluation detects pools without a policy or with `minimum_length` below `14`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolPasswordPolicyMinimumLength14) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolPasswordPolicyMinimumLength14) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolDeletionProtectionEnabled - Cognito user pool has deletion protection enabled
type CognitoUserPoolDeletionProtectionEnabled struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolDeletionProtectionEnabled() *CognitoUserPoolDeletionProtectionEnabled {
    return &CognitoUserPoolDeletionProtectionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_deletion_protection_enabled",
            CheckTitle: "Cognito user pool has deletion protection enabled",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** have **deletion protection** set to `ACTIVE`. The evaluation inspects each user pool's deletion protection status.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolDeletionProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolDeletionProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolAdvancedSecurityEnabled - Cognito user pool has advanced security enforced with full-function mode
type CognitoUserPoolAdvancedSecurityEnabled struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolAdvancedSecurityEnabled() *CognitoUserPoolAdvancedSecurityEnabled {
    return &CognitoUserPoolAdvancedSecurityEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_advanced_security_enabled",
            CheckTitle: "Cognito user pool has advanced security enforced with full-function mode",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** are evaluated for **Threat protection (advanced security)** mode: `ENFORCED` (full-function) vs `AUDIT` or disabled. This indicates whether adaptive risk responses and compromised-credential checks are applied during authentication.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolAdvancedSecurityEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolAdvancedSecurityEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolPasswordPolicyUppercase - Cognito user pool password policy requires at least one uppercase letter
type CognitoUserPoolPasswordPolicyUppercase struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyUppercase() *CognitoUserPoolPasswordPolicyUppercase {
    return &CognitoUserPoolPasswordPolicyUppercase{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_password_policy_uppercase",
            CheckTitle: "Cognito user pool password policy requires at least one uppercase letter",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "Amazon Cognito user pool password policy is evaluated for an uppercase character requirement (`require_uppercase`). The check also identifies user pools that have no password policy configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolPasswordPolicyUppercase) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolPasswordPolicyUppercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolPasswordPolicyLowercase - Cognito user pool password policy requires at least one lowercase letter
type CognitoUserPoolPasswordPolicyLowercase struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyLowercase() *CognitoUserPoolPasswordPolicyLowercase {
    return &CognitoUserPoolPasswordPolicyLowercase{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_password_policy_lowercase",
            CheckTitle: "Cognito user pool password policy requires at least one lowercase letter",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** are assessed for a password policy that includes a **lowercase character requirement**. Pools with `require_lowercase` set are distinguished from those without a policy, which inherently lack this requirement.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolPasswordPolicyLowercase) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolPasswordPolicyLowercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolClientTokenRevocationEnabled - Amazon Cognito user pool client has token revocation enabled
type CognitoUserPoolClientTokenRevocationEnabled struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolClientTokenRevocationEnabled() *CognitoUserPoolClientTokenRevocationEnabled {
    return &CognitoUserPoolClientTokenRevocationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_client_token_revocation_enabled",
            CheckTitle: "Amazon Cognito user pool client has token revocation enabled",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pool app clients** are evaluated for **token revocation** being enabled via `EnableTokenRevocation`.  This identifies whether each client can invalidate refresh tokens and the access/ID tokens derived from them to end user sessions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolClientTokenRevocationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolClientTokenRevocationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolBlocksPotentialMaliciousSignInAttempts - Amazon Cognito user pool blocks all potential malicious sign-in attempts
type CognitoUserPoolBlocksPotentialMaliciousSignInAttempts struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolBlocksPotentialMaliciousSignInAttempts() *CognitoUserPoolBlocksPotentialMaliciousSignInAttempts {
    return &CognitoUserPoolBlocksPotentialMaliciousSignInAttempts{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_blocks_potential_malicious_sign_in_attempts",
            CheckTitle: "Amazon Cognito user pool blocks all potential malicious sign-in attempts",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pool** with **threat protection** in `ENFORCED` mode and **adaptive authentication** actions set to `BLOCK` for `low`, `medium`, and `high` account-takeover risk levels.  Evaluates the user pool's risk configuration to confirm risky sign-in attempts are blocked across all severities.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolBlocksPotentialMaliciousSignInAttempts) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolBlocksPotentialMaliciousSignInAttempts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolTemporaryPasswordExpiration - Cognito user pool has temporary password expiration set to 7 days or less
type CognitoUserPoolTemporaryPasswordExpiration struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolTemporaryPasswordExpiration() *CognitoUserPoolTemporaryPasswordExpiration {
    return &CognitoUserPoolTemporaryPasswordExpiration{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_temporary_password_expiration",
            CheckTitle: "Cognito user pool has temporary password expiration set to 7 days or less",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** use **administrator-issued temporary passwords**. This evaluates whether a user pool defines a **password policy** and sets the temporary password validity to `7 days` or fewer.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolTemporaryPasswordExpiration) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolTemporaryPasswordExpiration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolPasswordPolicySymbol - Cognito user pool password policy requires at least one symbol
type CognitoUserPoolPasswordPolicySymbol struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicySymbol() *CognitoUserPoolPasswordPolicySymbol {
    return &CognitoUserPoolPasswordPolicySymbol{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_password_policy_symbol",
            CheckTitle: "Cognito user pool password policy requires at least one symbol",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pool** password policy includes a **symbol requirement** for user passwords.  Assesses the presence of a policy and whether `require_symbols` is configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolPasswordPolicySymbol) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolPasswordPolicySymbol) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolWafAclAttached - Amazon Cognito user pool is associated with a WAF Web ACL
type CognitoUserPoolWafAclAttached struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolWafAclAttached() *CognitoUserPoolWafAclAttached {
    return &CognitoUserPoolWafAclAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_waf_acl_attached",
            CheckTitle: "Amazon Cognito user pool is associated with a WAF Web ACL",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "Amazon Cognito user pools are evaluated for an association with an **AWS WAFv2 web ACL** that filters and controls requests to the hosted UI and public user pool API endpoints.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolWafAclAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolWafAclAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoIdentityPoolGuestAccessDisabled - Cognito identity pool has guest access disabled
type CognitoIdentityPoolGuestAccessDisabled struct {
    metadata models.CheckMetadata
}

func NewCognitoIdentityPoolGuestAccessDisabled() *CognitoIdentityPoolGuestAccessDisabled {
    return &CognitoIdentityPoolGuestAccessDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_identity_pool_guest_access_disabled",
            CheckTitle: "Cognito identity pool has guest access disabled",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito identity pools** are evaluated for **guest access** to unauthenticated identities. The assessment considers the `allow_unauthenticated_identities` setting and whether an unauthenticated role can be assumed by guests.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoIdentityPoolGuestAccessDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoIdentityPoolGuestAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolPasswordPolicyNumber - Cognito user pool password policy requires at least one number
type CognitoUserPoolPasswordPolicyNumber struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyNumber() *CognitoUserPoolPasswordPolicyNumber {
    return &CognitoUserPoolPasswordPolicyNumber{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_password_policy_number",
            CheckTitle: "Cognito user pool password policy requires at least one number",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "Amazon Cognito user pools are evaluated for a password policy that **requires at least one number**. The assessment checks whether the policy enforces a numeric character via `RequireNumbers` and also identifies pools with no password policy configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolPasswordPolicyNumber) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolPasswordPolicyNumber) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolMfaEnabled - Amazon Cognito user pool requires Multi-Factor Authentication (MFA)
type CognitoUserPoolMfaEnabled struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolMfaEnabled() *CognitoUserPoolMfaEnabled {
    return &CognitoUserPoolMfaEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_mfa_enabled",
            CheckTitle: "Amazon Cognito user pool requires Multi-Factor Authentication (MFA)",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** with **MFA** set to `ON`, indicating an additional factor is enforced during authentication",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolMfaEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// CognitoUserPoolSelfRegistrationDisabled - Amazon Cognito user pool has self registration disabled
type CognitoUserPoolSelfRegistrationDisabled struct {
    metadata models.CheckMetadata
}

func NewCognitoUserPoolSelfRegistrationDisabled() *CognitoUserPoolSelfRegistrationDisabled {
    return &CognitoUserPoolSelfRegistrationDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "cognito_user_pool_self_registration_disabled",
            CheckTitle: "Amazon Cognito user pool has self registration disabled",
            ServiceName: "cognito",
            Severity: "medium",
            Description: "**Amazon Cognito user pools** are evaluated for **self-service sign-up**. The expected configuration is `AllowAdminCreateUserOnly=true` so only administrators create accounts.  *When self sign-up is allowed*, the check also highlights any linked identity pools and the authenticated role(s) that new users could assume.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"cognito"},
        },
    }
}

func (c *CognitoUserPoolSelfRegistrationDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CognitoUserPoolSelfRegistrationDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "cognito",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

