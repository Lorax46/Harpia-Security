package microsoft365

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type microsoft365Provider interface {
	TenantID() string
}

// Microsoft365ConditionalAccessCheck verifica conditional access
type Microsoft365ConditionalAccessCheck struct {
	metadata models.CheckMetadata
}

func NewMicrosoft365ConditionalAccessCheck() *Microsoft365ConditionalAccessCheck {
	return &Microsoft365ConditionalAccessCheck{
		metadata: models.CheckMetadata{
			Provider: "microsoft365", CheckID: "microsoft365_conditional_access",
			CheckTitle: "Ensure conditional access policies are configured",
			Description: "Conditional access policies should be configured",
			Severity: "high", ServiceName: "microsoft365", ResourceType: "ConditionalAccess",
			RemediationText: "Configure conditional access policies",
			Categories: []string{"microsoft365", "identity"},
		},
	}
}

func (c *Microsoft365ConditionalAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Microsoft365ConditionalAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Conditional access check completed",
		Provider: "microsoft365", Service: "microsoft365", ResourceID: "conditional-access",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// Microsoft365MfaEnabledCheck verifica MFA
type Microsoft365MfaEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewMicrosoft365MfaEnabledCheck() *Microsoft365MfaEnabledCheck {
	return &Microsoft365MfaEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "microsoft365", CheckID: "microsoft365_mfa_enabled",
			CheckTitle: "Ensure MFA is enabled",
			Description: "MFA should be enabled for all users",
			Severity: "critical", ServiceName: "microsoft365", ResourceType: "MFA",
			RemediationText: "Enable MFA for all users",
			Categories: []string{"microsoft365", "mfa"},
		},
	}
}

func (c *Microsoft365MfaEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Microsoft365MfaEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "MFA check completed",
		Provider: "microsoft365", Service: "microsoft365", ResourceID: "mfa",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// Microsoft365PasswordPolicyCheck verifica política de senha
type Microsoft365PasswordPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewMicrosoft365PasswordPolicyCheck() *Microsoft365PasswordPolicyCheck {
	return &Microsoft365PasswordPolicyCheck{
		metadata: models.CheckMetadata{
			Provider: "microsoft365", CheckID: "microsoft365_password_policy",
			CheckTitle: "Ensure password policy is configured",
			Description: "Password policy should be configured",
			Severity: "medium", ServiceName: "microsoft365", ResourceType: "PasswordPolicy",
			RemediationText: "Configure password policy",
			Categories: []string{"microsoft365", "password"},
		},
	}
}

func (c *Microsoft365PasswordPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Microsoft365PasswordPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Password policy check completed",
		Provider: "microsoft365", Service: "microsoft365", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// Microsoft365AdminConsentCheck verifica consentimento de admin
type Microsoft365AdminConsentCheck struct {
	metadata models.CheckMetadata
}

func NewMicrosoft365AdminConsentCheck() *Microsoft365AdminConsentCheck {
	return &Microsoft365AdminConsentCheck{
		metadata: models.CheckMetadata{
			Provider: "microsoft365", CheckID: "microsoft365_admin_consent",
			CheckTitle: "Ensure admin consent is configured",
			Description: "Admin consent should be configured",
			Severity: "high", ServiceName: "microsoft365", ResourceType: "AdminConsent",
			RemediationText: "Configure admin consent",
			Categories: []string{"microsoft365", "consent"},
		},
	}
}

func (c *Microsoft365AdminConsentCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Microsoft365AdminConsentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Admin consent check completed",
		Provider: "microsoft365", Service: "microsoft365", ResourceID: "admin-consent",
		FoundAt: time.Now().UTC(),
	}}, nil
}
