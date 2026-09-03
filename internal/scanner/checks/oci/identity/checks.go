package identity

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// IdentityUserApiKeysRotated90Days - medium
type IdentityUserApiKeysRotated90Days struct {
	metadata models.CheckMetadata
}

// NewIdentityUserApiKeysRotated90Days cria nova instância
func NewIdentityUserApiKeysRotated90Days() *IdentityUserApiKeysRotated90Days {
	return &IdentityUserApiKeysRotated90Days{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_user_api_keys_rotated_90_days",
			CheckTitle:     "User active API key is rotated within 90 days or less",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI IAM users** with **active API signing keys** older than `90` days are identified. Key age is derived from each key's creation time; only active ",
			RemediationText: "Enforce **API key rotation** every `90` days. - Issue a new key, confirm workloads use it, then revo",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityUserApiKeysRotated90Days) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityUserApiKeysRotated90Days) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityPasswordPolicyMinimumLength14 - high
type IdentityPasswordPolicyMinimumLength14 struct {
	metadata models.CheckMetadata
}

// NewIdentityPasswordPolicyMinimumLength14 cria nova instância
func NewIdentityPasswordPolicyMinimumLength14() *IdentityPasswordPolicyMinimumLength14 {
	return &IdentityPasswordPolicyMinimumLength14{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_password_policy_minimum_length_14",
			CheckTitle:     "IAM password policy requires passwords to be at least 14 characters long",
			ServiceName:    "identity",
			Severity:       "high",
			Description:    "**OCI IAM password policies** are evaluated to confirm a **minimum password length** of `>= 14` characters is enforced. The assessment considers polic",
			RemediationText: "Enforce a **minimum password length** of `>= 14`, preferably using passphrases. Combine with **MFA**",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityPasswordPolicyMinimumLength14) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityPasswordPolicyMinimumLength14) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityUserDbPasswordsRotated90Days - medium
type IdentityUserDbPasswordsRotated90Days struct {
	metadata models.CheckMetadata
}

// NewIdentityUserDbPasswordsRotated90Days cria nova instância
func NewIdentityUserDbPasswordsRotated90Days() *IdentityUserDbPasswordsRotated90Days {
	return &IdentityUserDbPasswordsRotated90Days{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_user_db_passwords_rotated_90_days",
			CheckTitle:     "User IAM database password was created within the last 90 days",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI IAM user database passwords** are evaluated for **age**. Passwords are compared to a rotation window of `90 days`, flagging credentials that hav",
			RemediationText: "Enforce rotation of **IAM database passwords** at or below `90 days` and expire old credentials. Aut",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityUserDbPasswordsRotated90Days) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityUserDbPasswordsRotated90Days) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityPasswordPolicyExpiresWithin365Days - medium
type IdentityPasswordPolicyExpiresWithin365Days struct {
	metadata models.CheckMetadata
}

// NewIdentityPasswordPolicyExpiresWithin365Days cria nova instância
func NewIdentityPasswordPolicyExpiresWithin365Days() *IdentityPasswordPolicyExpiresWithin365Days {
	return &IdentityPasswordPolicyExpiresWithin365Days{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_password_policy_expires_within_365_days",
			CheckTitle:     "Identity Domain password policy expires passwords within 365 days",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI Identity Domain password policies** are evaluated to confirm **password expiration** is configured and set to `<= 365` days (`password_expires_a",
			RemediationText: "Enforce **password rotation** at `<= 365` days in Identity Domains. Combine with **MFA**, strong com",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityPasswordPolicyExpiresWithin365Days) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityPasswordPolicyExpiresWithin365Days) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityTenancyAdminUsersNoApiKeys - high
type IdentityTenancyAdminUsersNoApiKeys struct {
	metadata models.CheckMetadata
}

// NewIdentityTenancyAdminUsersNoApiKeys cria nova instância
func NewIdentityTenancyAdminUsersNoApiKeys() *IdentityTenancyAdminUsersNoApiKeys {
	return &IdentityTenancyAdminUsersNoApiKeys{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_tenancy_admin_users_no_api_keys",
			CheckTitle:     "Tenancy administrator user has no API keys",
			ServiceName:    "identity",
			Severity:       "high",
			Description:    "**OCI tenancy administrator accounts** (members of the `Administrators` group) are inspected for configured user **API keys** tied to those identities",
			RemediationText: "Do not issue **API keys** to tenancy administrators. Apply **least privilege** and **separation of d",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityTenancyAdminUsersNoApiKeys) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityTenancyAdminUsersNoApiKeys) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityTenancyAdminPermissionsLimited - critical
type IdentityTenancyAdminPermissionsLimited struct {
	metadata models.CheckMetadata
}

// NewIdentityTenancyAdminPermissionsLimited cria nova instância
func NewIdentityTenancyAdminPermissionsLimited() *IdentityTenancyAdminPermissionsLimited {
	return &IdentityTenancyAdminPermissionsLimited{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_tenancy_admin_permissions_limited",
			CheckTitle:     "OCI IAM policy does not grant 'manage all-resources in tenancy' unless it is the Tenant Admin Policy",
			ServiceName:    "identity",
			Severity:       "critical",
			Description:    "**OCI IAM policies** are analyzed for statements granting `manage all-resources in tenancy` to groups. Only the `Tenant Admin Policy` for the Administ",
			RemediationText: "Restrict `manage all-resources in tenancy` to the **Administrators** group only. Apply **least privi",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityTenancyAdminPermissionsLimited) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityTenancyAdminPermissionsLimited) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityNonRootCompartmentExists - high
type IdentityNonRootCompartmentExists struct {
	metadata models.CheckMetadata
}

// NewIdentityNonRootCompartmentExists cria nova instância
func NewIdentityNonRootCompartmentExists() *IdentityNonRootCompartmentExists {
	return &IdentityNonRootCompartmentExists{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_non_root_compartment_exists",
			CheckTitle:     "Tenancy has at least one active non-root compartment",
			ServiceName:    "identity",
			Severity:       "high",
			Description:    "**OCI tenancy** includes at least one **active non-root compartment**. Only compartments below the `root` level are considered, indicating that resour",
			RemediationText: "Create dedicated **non-root compartments** per workload, environment, or team; avoid placing resourc",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityNonRootCompartmentExists) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityNonRootCompartmentExists) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityServiceLevelAdminsExist - high
type IdentityServiceLevelAdminsExist struct {
	metadata models.CheckMetadata
}

// NewIdentityServiceLevelAdminsExist cria nova instância
func NewIdentityServiceLevelAdminsExist() *IdentityServiceLevelAdminsExist {
	return &IdentityServiceLevelAdminsExist{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_service_level_admins_exist",
			CheckTitle:     "Identity policy does not grant broad 'manage all-resources' permissions",
			ServiceName:    "identity",
			Severity:       "high",
			Description:    "**OCI IAM policies** are reviewed for **overly broad entitlements**, specifically statements granting `manage all-resources` without scoping to partic",
			RemediationText: "Apply **least privilege** and **separation of duties**: - Replace `manage all-resources` with servic",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityServiceLevelAdminsExist) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityServiceLevelAdminsExist) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityUserMfaEnabledConsoleAccess - high
type IdentityUserMfaEnabledConsoleAccess struct {
	metadata models.CheckMetadata
}

// NewIdentityUserMfaEnabledConsoleAccess cria nova instância
func NewIdentityUserMfaEnabledConsoleAccess() *IdentityUserMfaEnabledConsoleAccess {
	return &IdentityUserMfaEnabledConsoleAccess{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_user_mfa_enabled_console_access",
			CheckTitle:     "User with console password has MFA enabled for console access",
			ServiceName:    "identity",
			Severity:       "high",
			Description:    "**OCI IAM users** with **console password access** are expected to have **multifactor authentication** enabled. The evaluation inspects each local use",
			RemediationText: "Require **MFA** for all users with Console passwords; prefer **phishing-resistant authenticators** (",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityUserMfaEnabledConsoleAccess) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityUserMfaEnabledConsoleAccess) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityPasswordPolicyPreventsReuse - medium
type IdentityPasswordPolicyPreventsReuse struct {
	metadata models.CheckMetadata
}

// NewIdentityPasswordPolicyPreventsReuse cria nova instância
func NewIdentityPasswordPolicyPreventsReuse() *IdentityPasswordPolicyPreventsReuse {
	return &IdentityPasswordPolicyPreventsReuse{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_password_policy_prevents_reuse",
			CheckTitle:     "Identity Domain password policy prevents password reuse by remembering at least 24 previous passwords",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI Identity Domains** password policies are evaluated for **password reuse prevention** via **password history** (`num_passwords_in_history >= 24`)",
			RemediationText: "Enforce **password history** in Identity Domains with `num_passwords_in_history >= 24`. Pair with `m",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityPasswordPolicyPreventsReuse) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityPasswordPolicyPreventsReuse) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityStorageServiceLevelAdminsScoped - medium
type IdentityStorageServiceLevelAdminsScoped struct {
	metadata models.CheckMetadata
}

// NewIdentityStorageServiceLevelAdminsScoped cria nova instância
func NewIdentityStorageServiceLevelAdminsScoped() *IdentityStorageServiceLevelAdminsScoped {
	return &IdentityStorageServiceLevelAdminsScoped{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_storage_service_level_admins_scoped",
			CheckTitle:     "OCI IAM storage service-level admin policies exclude delete permissions",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI IAM policies** are reviewed to ensure storage service-level administrator statements that grant `manage` permissions exclude the relevant storag",
			RemediationText: "Exclude delete permissions from storage service-level administrator policies. Use `request.permissio",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityStorageServiceLevelAdminsScoped) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityStorageServiceLevelAdminsScoped) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityNoResourcesInRootCompartment - high
type IdentityNoResourcesInRootCompartment struct {
	metadata models.CheckMetadata
}

// NewIdentityNoResourcesInRootCompartment cria nova instância
func NewIdentityNoResourcesInRootCompartment() *IdentityNoResourcesInRootCompartment {
	return &IdentityNoResourcesInRootCompartment{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_no_resources_in_root_compartment",
			CheckTitle:     "No resources exist in the root compartment",
			ServiceName:    "identity",
			Severity:       "high",
			Description:    "**OCI root compartment** is evaluated for the presence of **user resources**. The finding highlights any assets created at the tenancy root and provid",
			RemediationText: "Reserve the **root compartment** for governance only. - Create workload-specific child compartments ",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityNoResourcesInRootCompartment) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityNoResourcesInRootCompartment) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityUserAuthTokensRotated90Days - medium
type IdentityUserAuthTokensRotated90Days struct {
	metadata models.CheckMetadata
}

// NewIdentityUserAuthTokensRotated90Days cria nova instância
func NewIdentityUserAuthTokensRotated90Days() *IdentityUserAuthTokensRotated90Days {
	return &IdentityUserAuthTokensRotated90Days{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_user_auth_tokens_rotated_90_days",
			CheckTitle:     "User auth token age is 90 days or less",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI IAM user auth tokens** are evaluated for **rotation age** against a `90-day` threshold using each token's creation time. Tokens older than this ",
			RemediationText: "Enforce routine **token rotation** at `<= 90 days` and prefer **short-lived, scoped credentials**. A",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityUserAuthTokensRotated90Days) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityUserAuthTokensRotated90Days) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityUserCustomerSecretKeysRotated90Days - medium
type IdentityUserCustomerSecretKeysRotated90Days struct {
	metadata models.CheckMetadata
}

// NewIdentityUserCustomerSecretKeysRotated90Days cria nova instância
func NewIdentityUserCustomerSecretKeysRotated90Days() *IdentityUserCustomerSecretKeysRotated90Days {
	return &IdentityUserCustomerSecretKeysRotated90Days{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_user_customer_secret_keys_rotated_90_days",
			CheckTitle:     "User customer secret key is rotated within 90 days or less",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI IAM customer secret keys** are assessed by creation timestamp to determine whether their age exceeds `90` days.",
			RemediationText: "Rotate **customer secret keys** every `<= 90` days. Apply **least privilege**, remove unused keys, a",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityUserCustomerSecretKeysRotated90Days) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityUserCustomerSecretKeysRotated90Days) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityUserValidEmailAddress - low
type IdentityUserValidEmailAddress struct {
	metadata models.CheckMetadata
}

// NewIdentityUserValidEmailAddress cria nova instância
func NewIdentityUserValidEmailAddress() *IdentityUserValidEmailAddress {
	return &IdentityUserValidEmailAddress{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_user_valid_email_address",
			CheckTitle:     "IAM user has a valid email address",
			ServiceName:    "identity",
			Severity:       "low",
			Description:    "**OCI IAM user accounts** are evaluated for a populated `email` attribute that resembles an address (contains `@`). Accounts missing this attribute or",
			RemediationText: "Ensure every user has a unique, verified, and monitored `email`. Enforce this at creation and throug",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityUserValidEmailAddress) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityUserValidEmailAddress) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityInstancePrincipalUsed - medium
type IdentityInstancePrincipalUsed struct {
	metadata models.CheckMetadata
}

// NewIdentityInstancePrincipalUsed cria nova instância
func NewIdentityInstancePrincipalUsed() *IdentityInstancePrincipalUsed {
	return &IdentityInstancePrincipalUsed{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_instance_principal_used",
			CheckTitle:     "Instance principal authentication is configured for OCI instances, OCI Cloud Databases, and OCI Functions",
			ServiceName:    "identity",
			Severity:       "medium",
			Description:    "**OCI dynamic groups** configured for **instance principal** access to workloads like **Compute instances**, **Functions**, and **Autonomous Databases",
			RemediationText: "Adopt **workload identities** with **instance principals** and granular dynamic groups. Apply **leas",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityInstancePrincipalUsed) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityInstancePrincipalUsed) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// IdentityIamAdminsCannotUpdateTenancyAdmins - critical
type IdentityIamAdminsCannotUpdateTenancyAdmins struct {
	metadata models.CheckMetadata
}

// NewIdentityIamAdminsCannotUpdateTenancyAdmins cria nova instância
func NewIdentityIamAdminsCannotUpdateTenancyAdmins() *IdentityIamAdminsCannotUpdateTenancyAdmins {
	return &IdentityIamAdminsCannotUpdateTenancyAdmins{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "identity_iam_admins_cannot_update_tenancy_admins",
			CheckTitle:     "All IAM policies granting manage/use on groups or users in the tenancy restrict access to the Administrators group",
			ServiceName:    "identity",
			Severity:       "critical",
			Description:    "**OCI IAM policies** granting **manage/use** on **groups or users** in the tenancy are evaluated for a condition that excludes the **Administrators** ",
			RemediationText: "Apply **least privilege**: avoid tenancy-wide manage/use on groups or users. When delegation is requ",
			Categories:     []string{"identity"},
		},
	}
}

// Metadata retorna os metadados
func (c *IdentityIamAdminsCannotUpdateTenancyAdmins) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IdentityIamAdminsCannotUpdateTenancyAdmins) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

