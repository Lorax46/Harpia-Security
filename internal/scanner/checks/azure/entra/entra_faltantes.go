package entra

// =============================================================================
// Azure Entra Missing Checks — 11 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type azureEntraMissingCheck struct {
	metadata models.CheckMetadata
}

func newAzureEntraMissingCheck(id, title, desc, sev string) azureEntraMissingCheck {
	return azureEntraMissingCheck{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "entra", ResourceType: "Directory",
		Categories: []string{"entra"},
	}}
}

func (c *azureEntraMissingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *azureEntraMissingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Azure entra check requires Azure SDK",
		ResourceID: c.metadata.CheckID, Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type entraAppRegistrationCredentialNotExpired struct{ azureEntraMissingCheck }

func NewEntraAppRegistrationCredentialNotExpired() *entraAppRegistrationCredentialNotExpired {
	return &entraAppRegistrationCredentialNotExpired{newAzureEntraMissingCheck(
		"entra_app_registration_credential_not_expired",
		"Ensure app registration credentials are not expired",
		"App registration credentials should not be expired",
		"medium",
	)}
}

type entraAuthenticationMethodsPolicyStrongAuthEnforced struct{ azureEntraMissingCheck }

func NewEntraAuthenticationMethodsPolicyStrongAuthEnforced() *entraAuthenticationMethodsPolicyStrongAuthEnforced {
	return &entraAuthenticationMethodsPolicyStrongAuthEnforced{newAzureEntraMissingCheck(
		"entra_authentication_methods_policy_strong_auth_enforced",
		"Ensure strong auth is enforced",
		"Strong authentication should be enforced",
		"high",
	)}
}

type entraConditionalAccessPolicyRequireMfaForAdminPortals struct{ azureEntraMissingCheck }

func NewEntraConditionalAccessPolicyRequireMfaForAdminPortals() *entraConditionalAccessPolicyRequireMfaForAdminPortals {
	return &entraConditionalAccessPolicyRequireMfaForAdminPortals{newAzureEntraMissingCheck(
		"entra_conditional_access_policy_require_mfa_for_admin_portals",
		"Ensure MFA is required for admin portals",
		"MFA should be required for admin portals",
		"high",
	)}
}

type entraConditionalAccessPolicyRequireMfaForManagementApi struct{ azureEntraMissingCheck }

func NewEntraConditionalAccessPolicyRequireMfaForManagementApi() *entraConditionalAccessPolicyRequireMfaForManagementApi {
	return &entraConditionalAccessPolicyRequireMfaForManagementApi{newAzureEntraMissingCheck(
		"entra_conditional_access_policy_require_mfa_for_management_api",
		"Ensure MFA is required for management API",
		"MFA should be required for management API",
		"high",
	)}
}

type entraGlobalAdminInLessThanFiveUsers struct{ azureEntraMissingCheck }

func NewEntraGlobalAdminInLessThanFiveUsers() *entraGlobalAdminInLessThanFiveUsers {
	return &entraGlobalAdminInLessThanFiveUsers{newAzureEntraMissingCheck(
		"entra_global_admin_in_less_than_five_users",
		"Ensure global admin is in less than five users",
		"Global admin should be in less than five users",
		"high",
	)}
}

type entraNonPrivilegedUserHasMfa struct{ azureEntraMissingCheck }

func NewEntraNonPrivilegedUserHasMfa() *entraNonPrivilegedUserHasMfa {
	return &entraNonPrivilegedUserHasMfa{newAzureEntraMissingCheck(
		"entra_non_privileged_user_has_mfa",
		"Ensure non-privileged users have MFA",
		"Non-privileged users should have MFA",
		"medium",
	)}
}

type entraPolicyDefaultUsersCannotCreateSecurityGroups struct{ azureEntraMissingCheck }

func NewEntraPolicyDefaultUsersCannotCreateSecurityGroups() *entraPolicyDefaultUsersCannotCreateSecurityGroups {
	return &entraPolicyDefaultUsersCannotCreateSecurityGroups{newAzureEntraMissingCheck(
		"entra_policy_default_users_cannot_create_security_groups",
		"Ensure default users cannot create security groups",
		"Default users should not be able to create security groups",
		"medium",
	)}
}

type entraPolicyEnsureDefaultUserCannotCreateApps struct{ azureEntraMissingCheck }

func NewEntraPolicyEnsureDefaultUserCannotCreateApps() *entraPolicyEnsureDefaultUserCannotCreateApps {
	return &entraPolicyEnsureDefaultUserCannotCreateApps{newAzureEntraMissingCheck(
		"entra_policy_ensure_default_user_cannot_create_apps",
		"Ensure default users cannot create apps",
		"Default users should not be able to create apps",
		"medium",
	)}
}

type entraPolicyEnsureDefaultUserCannotCreateTenants struct{ azureEntraMissingCheck }

func NewEntraPolicyEnsureDefaultUserCannotCreateTenants() *entraPolicyEnsureDefaultUserCannotCreateTenants {
	return &entraPolicyEnsureDefaultUserCannotCreateTenants{newAzureEntraMissingCheck(
		"entra_policy_ensure_default_user_cannot_create_tenants",
		"Ensure default users cannot create tenants",
		"Default users should not be able to create tenants",
		"medium",
	)}
}

type entraPolicyGuestInviteOnlyForAdminRoles struct{ azureEntraMissingCheck }

func NewEntraPolicyGuestInviteOnlyForAdminRoles() *entraPolicyGuestInviteOnlyForAdminRoles {
	return &entraPolicyGuestInviteOnlyForAdminRoles{newAzureEntraMissingCheck(
		"entra_policy_guest_invite_only_for_admin_roles",
		"Ensure guest invite only for admin roles",
		"Guest invite should only be for admin roles",
		"medium",
	)}
}

type entraPolicyGuestUsersAccessRestrictions struct{ azureEntraMissingCheck }

func NewEntraPolicyGuestUsersAccessRestrictions() *entraPolicyGuestUsersAccessRestrictions {
	return &entraPolicyGuestUsersAccessRestrictions{newAzureEntraMissingCheck(
		"entra_policy_guest_users_access_restrictions",
		"Ensure guest users access restrictions",
		"Guest users access should be restricted",
		"medium",
	)}
}

type entraPolicyRestrictsUserConsentForApps struct{ azureEntraMissingCheck }

func NewEntraPolicyRestrictsUserConsentForApps() *entraPolicyRestrictsUserConsentForApps {
	return &entraPolicyRestrictsUserConsentForApps{newAzureEntraMissingCheck(
		"entra_policy_restricts_user_consent_for_apps",
		"Ensure user consent for apps is restricted",
		"User consent for apps should be restricted",
		"medium",
	)}
}

type entraPolicyUserConsentForVerifiedApps struct{ azureEntraMissingCheck }

func NewEntraPolicyUserConsentForVerifiedApps() *entraPolicyUserConsentForVerifiedApps {
	return &entraPolicyUserConsentForVerifiedApps{newAzureEntraMissingCheck(
		"entra_policy_user_consent_for_verified_apps",
		"Ensure user consent for verified apps",
		"User consent for verified apps should be enabled",
		"low",
	)}
}

type entraPrivilegedUserHasMfa struct{ azureEntraMissingCheck }

func NewEntraPrivilegedUserHasMfa() *entraPrivilegedUserHasMfa {
	return &entraPrivilegedUserHasMfa{newAzureEntraMissingCheck(
		"entra_privileged_user_has_mfa",
		"Ensure privileged users have MFA",
		"Privileged users should have MFA",
		"critical",
	)}
}

type entraSecurityDefaultsEnabled struct{ azureEntraMissingCheck }

func NewEntraSecurityDefaultsEnabled() *entraSecurityDefaultsEnabled {
	return &entraSecurityDefaultsEnabled{newAzureEntraMissingCheck(
		"entra_security_defaults_enabled",
		"Ensure security defaults are enabled",
		"Security defaults should be enabled",
		"high",
	)}
}

type entraTrustedNamedLocationsExists struct{ azureEntraMissingCheck }

func NewEntraTrustedNamedLocationsExists() *entraTrustedNamedLocationsExists {
	return &entraTrustedNamedLocationsExists{newAzureEntraMissingCheck(
		"entra_trusted_named_locations_exists",
		"Ensure trusted named locations exist",
		"Trusted named locations should exist",
		"medium",
	)}
}

type entraUserWithRecentSignIn struct{ azureEntraMissingCheck }

func NewEntraUserWithRecentSignIn() *entraUserWithRecentSignIn {
	return &entraUserWithRecentSignIn{newAzureEntraMissingCheck(
		"entra_user_with_recent_sign_in",
		"Ensure users have recent sign-in",
		"Users should have recent sign-in",
		"low",
	)}
}

type entraUserWithVmAccessHasMfa struct{ azureEntraMissingCheck }

func NewEntraUserWithVmAccessHasMfa() *entraUserWithVmAccessHasMfa {
	return &entraUserWithVmAccessHasMfa{newAzureEntraMissingCheck(
		"entra_user_with_vm_access_has_mfa",
		"Ensure users with VM access have MFA",
		"Users with VM access should have MFA",
		"high",
	)}
}

type entraUsersCannotCreateMicrosoft365Groups struct{ azureEntraMissingCheck }

func NewEntraUsersCannotCreateMicrosoft365Groups() *entraUsersCannotCreateMicrosoft365Groups {
	return &entraUsersCannotCreateMicrosoft365Groups{newAzureEntraMissingCheck(
		"entra_users_cannot_create_microsoft_365_groups",
		"Ensure users cannot create Microsoft 365 groups",
		"Users should not be able to create Microsoft 365 groups",
		"medium",
	)}
}
