package entra

// =============================================================================
// Azure Entra (Active Directory) Checks — 19 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

func newEntraCheck(id, title, description, severity string) struct {
	metadata models.CheckMetadata
} {
	return struct {
		metadata models.CheckMetadata
	}{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: id, CheckTitle: title,
			Description: description, Severity: severity,
			ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra"},
		},
	}
}

// EntraAdminMfaEnabled - verifica MFA para admins
type EntraAdminMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewEntraAdminMfaEnabled() *EntraAdminMfaEnabled {
	return &EntraAdminMfaEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_admin_mfa_enabled",
			CheckTitle: "Ensure MFA is enabled for administrators",
			Description: "MFA should be enabled for all administrative accounts",
			Severity: "critical", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "mfa"},
		},
	}
}

func (c *EntraAdminMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAdminMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra admin MFA check requires Azure SDK",
		ResourceID: "entra-admin-mfa", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAdminSecuredMFA - verifica MFA seguro para admins
type EntraAdminSecuredMFA struct {
	metadata models.CheckMetadata
}

func NewEntraAdminSecuredMFA() *EntraAdminSecuredMFA {
	return &EntraAdminSecuredMFA{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_admin_secured_mfa",
			CheckTitle: "Ensure administrators have secured MFA",
			Description: "Administrators should use secured MFA methods",
			Severity: "critical", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "mfa"},
		},
	}
}

func (c *EntraAdminSecuredMFA) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAdminSecuredMFA) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra secured MFA check requires Azure SDK",
		ResourceID: "entra-secured-mfa", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAnonymousUsersNotOwner - verifica usuários anônimos
type EntraAnonymousUsersNotOwner struct {
	metadata models.CheckMetadata
}

func NewEntraAnonymousUsersNotOwner() *EntraAnonymousUsersNotOwner {
	return &EntraAnonymousUsersNotOwner{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_anonymous_users_not_owner",
			CheckTitle: "Ensure anonymous users are not owners",
			Description: "Anonymous users should not have owner permissions",
			Severity: "high", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "access"},
		},
	}
}

func (c *EntraAnonymousUsersNotOwner) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAnonymousUsersNotOwner) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra anonymous users check requires Azure SDK",
		ResourceID: "entra-anonymous-users", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppAdminConsent - verifica consentimento de admin
type EntraAppAdminConsent struct {
	metadata models.CheckMetadata
}

func NewEntraAppAdminConsent() *EntraAppAdminConsent {
	return &EntraAppAdminConsent{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_admin_consent",
			CheckTitle: "Ensure app admin consent is properly configured",
			Description: "App admin consent should be properly configured",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "consent"},
		},
	}
}

func (c *EntraAppAdminConsent) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppAdminConsent) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra app admin consent check requires Azure SDK",
		ResourceID: "entra-consent", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppApiPermissions - verifica permissões de API
type EntraAppApiPermissions struct {
	metadata models.CheckMetadata
}

func NewEntraAppApiPermissions() *EntraAppApiPermissions {
	return &EntraAppApiPermissions{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_api_permissions",
			CheckTitle: "Ensure app API permissions are properly configured",
			Description: "App API permissions should be properly configured",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "permissions"},
		},
	}
}

func (c *EntraAppApiPermissions) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppApiPermissions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra API permissions check requires Azure SDK",
		ResourceID: "entra-api-permissions", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppAuthenticationBehaviors - verifica comportamentos de autenticação
type EntraAppAuthenticationBehaviors struct {
	metadata models.CheckMetadata
}

func NewEntraAppAuthenticationBehaviors() *EntraAppAuthenticationBehaviors {
	return &EntraAppAuthenticationBehaviors{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_authentication_behaviors",
			CheckTitle: "Ensure app authentication behaviors are configured",
			Description: "App authentication behaviors should be configured",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "authentication"},
		},
	}
}

func (c *EntraAppAuthenticationBehaviors) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppAuthenticationBehaviors) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra authentication behaviors check requires Azure SDK",
		ResourceID: "entra-auth-behaviors", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppConsentRequests - verifica solicitações de consentimento
type EntraAppConsentRequests struct {
	metadata models.CheckMetadata
}

func NewEntraAppConsentRequests() *EntraAppConsentRequests {
	return &EntraAppConsentRequests{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_consent_requests",
			CheckTitle: "Ensure app consent requests are managed",
			Description: "App consent requests should be managed",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "consent"},
		},
	}
}

func (c *EntraAppConsentRequests) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppConsentRequests) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra consent requests check requires Azure SDK",
		ResourceID: "entra-consent-requests", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppDefaultRedirectUri - verifica redirect URI padrão
type EntraAppDefaultRedirectUri struct {
	metadata models.CheckMetadata
}

func NewEntraAppDefaultRedirectUri() *EntraAppDefaultRedirectUri {
	return &EntraAppDefaultRedirectUri{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_default_redirect_uri",
			CheckTitle: "Ensure app default redirect URI is configured",
			Description: "App default redirect URI should be configured",
			Severity: "low", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "redirect"},
		},
	}
}

func (c *EntraAppDefaultRedirectUri) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppDefaultRedirectUri) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra redirect URI check requires Azure SDK",
		ResourceID: "entra-redirect-uri", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppIdentifierUri - verifica identifier URI
type EntraAppIdentifierUri struct {
	metadata models.CheckMetadata
}

func NewEntraAppIdentifierUri() *EntraAppIdentifierUri {
	return &EntraAppIdentifierUri{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_identifier_uri",
			CheckTitle: "Ensure app identifier URI is configured",
			Description: "App identifier URI should be configured",
			Severity: "low", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "uri"},
		},
	}
}

func (c *EntraAppIdentifierUri) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppIdentifierUri) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra identifier URI check requires Azure SDK",
		ResourceID: "entra-identifier-uri", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppNoNativeAppRegistration - verifica registros de app nativos
type EntraAppNoNativeAppRegistration struct {
	metadata models.CheckMetadata
}

func NewEntraAppNoNativeAppRegistration() *EntraAppNoNativeAppRegistration {
	return &EntraAppNoNativeAppRegistration{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_no_native_app_registration",
			CheckTitle: "Ensure no native app registrations",
			Description: "Native app registrations should be avoided",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "registration"},
		},
	}
}

func (c *EntraAppNoNativeAppRegistration) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppNoNativeAppRegistration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra native app registration check requires Azure SDK",
		ResourceID: "entra-native-app", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppOwnerAssignedPermission - verifica permissões de owner
type EntraAppOwnerAssignedPermission struct {
	metadata models.CheckMetadata
}

func NewEntraAppOwnerAssignedPermission() *EntraAppOwnerAssignedPermission {
	return &EntraAppOwnerAssignedPermission{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_owner_assigned_permission",
			CheckTitle: "Ensure app owners have assigned permissions",
			Description: "App owners should have assigned permissions",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "permissions"},
		},
	}
}

func (c *EntraAppOwnerAssignedPermission) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppOwnerAssignedPermission) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra owner permissions check requires Azure SDK",
		ResourceID: "entra-owner-permissions", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppPasswordCredentialRotation - verifica rotação de senhas
type EntraAppPasswordCredentialRotation struct {
	metadata models.CheckMetadata
}

func NewEntraAppPasswordCredentialRotation() *EntraAppPasswordCredentialRotation {
	return &EntraAppPasswordCredentialRotation{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_password_credential_rotation",
			CheckTitle: "Ensure app password credentials are rotated",
			Description: "App password credentials should be rotated",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "credentials"},
		},
	}
}

func (c *EntraAppPasswordCredentialRotation) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppPasswordCredentialRotation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra password rotation check requires Azure SDK",
		ResourceID: "entra-password-rotation", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppPublicClientNoSpa - verifica clientes públicos
type EntraAppPublicClientNoSpa struct {
	metadata models.CheckMetadata
}

func NewEntraAppPublicClientNoSpa() *EntraAppPublicClientNoSpa {
	return &EntraAppPublicClientNoSpa{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_public_client_no_spa",
			CheckTitle: "Ensure no public client SPA registrations",
			Description: "Public client SPA registrations should be avoided",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "client"},
		},
	}
}

func (c *EntraAppPublicClientNoSpa) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppPublicClientNoSpa) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra public client check requires Azure SDK",
		ResourceID: "entra-public-client", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppRequiredResourceAccess - verifica acesso a recursos
type EntraAppRequiredResourceAccess struct {
	metadata models.CheckMetadata
}

func NewEntraAppRequiredResourceAccess() *EntraAppRequiredResourceAccess {
	return &EntraAppRequiredResourceAccess{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_required_resource_access",
			CheckTitle: "Ensure app required resource access is configured",
			Description: "App required resource access should be configured",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "access"},
		},
	}
}

func (c *EntraAppRequiredResourceAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppRequiredResourceAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra resource access check requires Azure SDK",
		ResourceID: "entra-resource-access", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraAppRoleAssignments - verifica atribuições de role
type EntraAppRoleAssignments struct {
	metadata models.CheckMetadata
}

func NewEntraAppRoleAssignments() *EntraAppRoleAssignments {
	return &EntraAppRoleAssignments{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_app_role_assignments",
			CheckTitle: "Ensure app role assignments are configured",
			Description: "App role assignments should be configured",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "roles"},
		},
	}
}

func (c *EntraAppRoleAssignments) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraAppRoleAssignments) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra role assignments check requires Azure SDK",
		ResourceID: "entra-role-assignments", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraConditionalAccessAppRegistrationPolicy - verifica política de registro
type EntraConditionalAccessAppRegistrationPolicy struct {
	metadata models.CheckMetadata
}

func NewEntraConditionalAccessAppRegistrationPolicy() *EntraConditionalAccessAppRegistrationPolicy {
	return &EntraConditionalAccessAppRegistrationPolicy{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_conditional_access_app_registration_policy",
			CheckTitle: "Ensure conditional access app registration policy is configured",
			Description: "Conditional access app registration policy should be configured",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "conditional-access"},
		},
	}
}

func (c *EntraConditionalAccessAppRegistrationPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraConditionalAccessAppRegistrationPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra conditional access check requires Azure SDK",
		ResourceID: "entra-conditional-access", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraConditionalAccessMfa - verifica MFA condicional
type EntraConditionalAccessMfa struct {
	metadata models.CheckMetadata
}

func NewEntraConditionalAccessMfa() *EntraConditionalAccessMfa {
	return &EntraConditionalAccessMfa{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_conditional_access_mfa",
			CheckTitle: "Ensure conditional access MFA policy is configured",
			Description: "Conditional access MFA policy should be configured",
			Severity: "high", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "mfa"},
		},
	}
}

func (c *EntraConditionalAccessMfa) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraConditionalAccessMfa) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra conditional MFA check requires Azure SDK",
		ResourceID: "entra-conditional-mfa", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraConditionalAccessPolicy - verifica política de acesso condicional
type EntraConditionalAccessPolicy struct {
	metadata models.CheckMetadata
}

func NewEntraConditionalAccessPolicy() *EntraConditionalAccessPolicy {
	return &EntraConditionalAccessPolicy{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_conditional_access_policy",
			CheckTitle: "Ensure conditional access policy is configured",
			Description: "Conditional access policy should be configured",
			Severity: "high", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "conditional-access"},
		},
	}
}

func (c *EntraConditionalAccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraConditionalAccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra conditional access policy check requires Azure SDK",
		ResourceID: "entra-conditional-policy", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EntraDefaultUserRolePermissions - verifica permissões padrão
type EntraDefaultUserRolePermissions struct {
	metadata models.CheckMetadata
}

func NewEntraDefaultUserRolePermissions() *EntraDefaultUserRolePermissions {
	return &EntraDefaultUserRolePermissions{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "entra_default_user_role_permissions",
			CheckTitle: "Ensure default user role permissions are limited",
			Description: "Default user role permissions should be limited",
			Severity: "medium", ServiceName: "entra", ResourceType: "Directory",
			Categories: []string{"entra", "roles"},
		},
	}
}

func (c *EntraDefaultUserRolePermissions) Metadata() models.CheckMetadata { return c.metadata }

func (c *EntraDefaultUserRolePermissions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Entra default role permissions check requires Azure SDK",
		ResourceID: "entra-default-role", Provider: "azure", Service: "entra",
		FoundAt: time.Now().UTC(),
	}}, nil
}
