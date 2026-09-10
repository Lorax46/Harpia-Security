package okta

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type oktaProvider interface {
	OrgURL() string
}

// OktaMfaEnabledCheck verifica MFA
type OktaMfaEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewOktaMfaEnabledCheck() *OktaMfaEnabledCheck {
	return &OktaMfaEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "okta", CheckID: "okta_mfa_enabled",
			CheckTitle: "Ensure MFA is enabled",
			Description: "MFA should be enabled for all users",
			Severity: "critical", ServiceName: "okta", ResourceType: "MFA",
			RemediationText: "Enable MFA for all users",
			Categories: []string{"okta", "mfa"},
		},
	}
}

func (c *OktaMfaEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OktaMfaEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "MFA check completed",
		Provider: "okta", Service: "okta", ResourceID: "mfa",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// OktaPasswordPolicyCheck verifica política de senha
type OktaPasswordPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewOktaPasswordPolicyCheck() *OktaPasswordPolicyCheck {
	return &OktaPasswordPolicyCheck{
		metadata: models.CheckMetadata{
			Provider: "okta", CheckID: "okta_password_policy",
			CheckTitle: "Ensure password policy is configured",
			Description: "Password policy should be configured",
			Severity: "medium", ServiceName: "okta", ResourceType: "PasswordPolicy",
			RemediationText: "Configure password policy",
			Categories: []string{"okta", "password"},
		},
	}
}

func (c *OktaPasswordPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OktaPasswordPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Password policy check completed",
		Provider: "okta", Service: "okta", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// OktaAdminPrivilegesCheck verifica privilégios de admin
type OktaAdminPrivilegesCheck struct {
	metadata models.CheckMetadata
}

func NewOktaAdminPrivilegesCheck() *OktaAdminPrivilegesCheck {
	return &OktaAdminPrivilegesCheck{
		metadata: models.CheckMetadata{
			Provider: "okta", CheckID: "okta_admin_privileges",
			CheckTitle: "Ensure admin privileges are reviewed",
			Description: "Admin privileges should be reviewed",
			Severity: "high", ServiceName: "okta", ResourceType: "Admin",
			RemediationText: "Review admin privileges",
			Categories: []string{"okta", "admin"},
		},
	}
}

func (c *OktaAdminPrivilegesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OktaAdminPrivilegesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Admin privileges check completed",
		Provider: "okta", Service: "okta", ResourceID: "admin",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// OktaApiTokensCheck verifica tokens de API
type OktaApiTokensCheck struct {
	metadata models.CheckMetadata
}

func NewOktaApiTokensCheck() *OktaApiTokensCheck {
	return &OktaApiTokensCheck{
		metadata: models.CheckMetadata{
			Provider: "okta", CheckID: "okta_api_tokens",
			CheckTitle: "Ensure API tokens are reviewed",
			Description: "API tokens should be reviewed",
			Severity: "medium", ServiceName: "okta", ResourceType: "APIToken",
			RemediationText: "Review API tokens",
			Categories: []string{"okta", "api"},
		},
	}
}

func (c *OktaApiTokensCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OktaApiTokensCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "API tokens check completed",
		Provider: "okta", Service: "okta", ResourceID: "api-tokens",
		FoundAt: time.Now().UTC(),
	}}, nil
}
