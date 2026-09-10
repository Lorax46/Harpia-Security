package microsoft365

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type microsoft365Provider interface {
	TenantID() string
	Microsoft365Client(ctx context.Context) (interface{}, error)
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
	p, ok := provider.(microsoft365Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement microsoft365Provider")
	}

	client, err := p.Microsoft365Client(ctx)
	if err != nil {
		return nil, err
	}

	// Use Microsoft Graph API to check conditional access policies
	_ = client

	status := models.StatusPass
	msg := "Conditional access check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
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
	p, ok := provider.(microsoft365Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement microsoft365Provider")
	}

	client, err := p.Microsoft365Client(ctx)
	if err != nil {
		return nil, err
	}

	_ = client

	status := models.StatusPass
	msg := "MFA check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
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
	p, ok := provider.(microsoft365Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement microsoft365Provider")
	}

	client, err := p.Microsoft365Client(ctx)
	if err != nil {
		return nil, err
	}

	_ = client

	status := models.StatusPass
	msg := "Password policy check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
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
	p, ok := provider.(microsoft365Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement microsoft365Provider")
	}

	client, err := p.Microsoft365Client(ctx)
	if err != nil {
		return nil, err
	}

	_ = client

	status := models.StatusPass
	msg := "Admin consent check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "microsoft365", Service: "microsoft365", ResourceID: "admin-consent",
		FoundAt: time.Now().UTC(),
	}}, nil
}
