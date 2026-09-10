package seguranca

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type segurancaProvider interface {
	Seguranca(ctx context.Context) (interface{}, error)
}

// SecEncryptionAtRestCheck - Encryption at rest is enforced
type SecEncryptionAtRestCheck struct {
	metadata models.CheckMetadata
}

func NewSecEncryptionAtRestCheck() *SecEncryptionAtRestCheck {
	return &SecEncryptionAtRestCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_encryption_at_rest",
			CheckTitle:      "Encryption at rest is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "Encryption",
			Description:     "Encryption at rest is enforced",
			RemediationText: "Review and remediate encryption at rest is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecEncryptionAtRestCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecEncryptionAtRestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_encryption_at_rest
	_ = findings
	return findings, nil
}

// SecEncryptionInTransitCheck - Encryption in transit is enforced
type SecEncryptionInTransitCheck struct {
	metadata models.CheckMetadata
}

func NewSecEncryptionInTransitCheck() *SecEncryptionInTransitCheck {
	return &SecEncryptionInTransitCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_encryption_in_transit",
			CheckTitle:      "Encryption in transit is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "Encryption",
			Description:     "Encryption in transit is enforced",
			RemediationText: "Review and remediate encryption in transit is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecEncryptionInTransitCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecEncryptionInTransitCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_encryption_in_transit
	_ = findings
	return findings, nil
}

// SecKeyManagementCheck - Key management is configured
type SecKeyManagementCheck struct {
	metadata models.CheckMetadata
}

func NewSecKeyManagementCheck() *SecKeyManagementCheck {
	return &SecKeyManagementCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_key_management",
			CheckTitle:      "Key management is configured",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "KeyMgmt",
			Description:     "Key management is configured",
			RemediationText: "Review and remediate key management is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecKeyManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecKeyManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_key_management
	_ = findings
	return findings, nil
}

// SecKeyRotationCheck - Key rotation is configured
type SecKeyRotationCheck struct {
	metadata models.CheckMetadata
}

func NewSecKeyRotationCheck() *SecKeyRotationCheck {
	return &SecKeyRotationCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_key_rotation",
			CheckTitle:      "Key rotation is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "KeyMgmt",
			Description:     "Key rotation is configured",
			RemediationText: "Review and remediate key rotation is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecKeyRotationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecKeyRotationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_key_rotation
	_ = findings
	return findings, nil
}

// SecKeyRevocationCheck - Key revocation is configured
type SecKeyRevocationCheck struct {
	metadata models.CheckMetadata
}

func NewSecKeyRevocationCheck() *SecKeyRevocationCheck {
	return &SecKeyRevocationCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_key_revocation",
			CheckTitle:      "Key revocation is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "KeyMgmt",
			Description:     "Key revocation is configured",
			RemediationText: "Review and remediate key revocation is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecKeyRevocationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecKeyRevocationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_key_revocation
	_ = findings
	return findings, nil
}

// SecKeyBackupCheck - Key backup is configured
type SecKeyBackupCheck struct {
	metadata models.CheckMetadata
}

func NewSecKeyBackupCheck() *SecKeyBackupCheck {
	return &SecKeyBackupCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_key_backup",
			CheckTitle:      "Key backup is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "KeyMgmt",
			Description:     "Key backup is configured",
			RemediationText: "Review and remediate key backup is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecKeyBackupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecKeyBackupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_key_backup
	_ = findings
	return findings, nil
}

// SecKeyRecoveryCheck - Key recovery is configured
type SecKeyRecoveryCheck struct {
	metadata models.CheckMetadata
}

func NewSecKeyRecoveryCheck() *SecKeyRecoveryCheck {
	return &SecKeyRecoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_key_recovery",
			CheckTitle:      "Key recovery is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "KeyMgmt",
			Description:     "Key recovery is configured",
			RemediationText: "Review and remediate key recovery is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecKeyRecoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecKeyRecoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_key_recovery
	_ = findings
	return findings, nil
}

// SecHardwareSecurityModuleCheck - HSM is configured
type SecHardwareSecurityModuleCheck struct {
	metadata models.CheckMetadata
}

func NewSecHardwareSecurityModuleCheck() *SecHardwareSecurityModuleCheck {
	return &SecHardwareSecurityModuleCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_hardware_security_module",
			CheckTitle:      "HSM is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "HSM",
			Description:     "HSM is configured",
			RemediationText: "Review and remediate hsm is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecHardwareSecurityModuleCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecHardwareSecurityModuleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_hardware_security_module
	_ = findings
	return findings, nil
}

// SecCertificateManagementCheck - Certificate management is configured
type SecCertificateManagementCheck struct {
	metadata models.CheckMetadata
}

func NewSecCertificateManagementCheck() *SecCertificateManagementCheck {
	return &SecCertificateManagementCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_certificate_management",
			CheckTitle:      "Certificate management is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Certificate management is configured",
			RemediationText: "Review and remediate certificate management is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCertificateManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCertificateManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_certificate_management
	_ = findings
	return findings, nil
}

// SecCertificateRotationCheck - Certificate rotation is configured
type SecCertificateRotationCheck struct {
	metadata models.CheckMetadata
}

func NewSecCertificateRotationCheck() *SecCertificateRotationCheck {
	return &SecCertificateRotationCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_certificate_rotation",
			CheckTitle:      "Certificate rotation is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Certificate rotation is configured",
			RemediationText: "Review and remediate certificate rotation is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCertificateRotationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCertificateRotationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_certificate_rotation
	_ = findings
	return findings, nil
}

// SecCertificateMonitoringCheck - Certificate monitoring is enabled
type SecCertificateMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewSecCertificateMonitoringCheck() *SecCertificateMonitoringCheck {
	return &SecCertificateMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_certificate_monitoring",
			CheckTitle:      "Certificate monitoring is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Certificate monitoring is enabled",
			RemediationText: "Review and remediate certificate monitoring is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCertificateMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCertificateMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_certificate_monitoring
	_ = findings
	return findings, nil
}

// SecCertificatePinningCheck - Certificate pinning is enabled
type SecCertificatePinningCheck struct {
	metadata models.CheckMetadata
}

func NewSecCertificatePinningCheck() *SecCertificatePinningCheck {
	return &SecCertificatePinningCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_certificate_pinning",
			CheckTitle:      "Certificate pinning is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Certificate pinning is enabled",
			RemediationText: "Review and remediate certificate pinning is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCertificatePinningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCertificatePinningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_certificate_pinning
	_ = findings
	return findings, nil
}

// SecOauthSecurityCheck - OAuth security is enforced
type SecOauthSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecOauthSecurityCheck() *SecOauthSecurityCheck {
	return &SecOauthSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_oauth_security",
			CheckTitle:      "OAuth security is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "OAuth",
			Description:     "OAuth security is enforced",
			RemediationText: "Review and remediate oauth security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecOauthSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecOauthSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_oauth_security
	_ = findings
	return findings, nil
}

// SecOidcSecurityCheck - OIDC security is enforced
type SecOidcSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecOidcSecurityCheck() *SecOidcSecurityCheck {
	return &SecOidcSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_oidc_security",
			CheckTitle:      "OIDC security is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "OIDC",
			Description:     "OIDC security is enforced",
			RemediationText: "Review and remediate oidc security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecOidcSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecOidcSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_oidc_security
	_ = findings
	return findings, nil
}

// SecSamlSecurityCheck - SAML security is enforced
type SecSamlSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecSamlSecurityCheck() *SecSamlSecurityCheck {
	return &SecSamlSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_saml_security",
			CheckTitle:      "SAML security is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "SAML",
			Description:     "SAML security is enforced",
			RemediationText: "Review and remediate saml security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecSamlSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecSamlSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_saml_security
	_ = findings
	return findings, nil
}

// SecJwtSecurityCheck - JWT security is enforced
type SecJwtSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecJwtSecurityCheck() *SecJwtSecurityCheck {
	return &SecJwtSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_jwt_security",
			CheckTitle:      "JWT security is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "JWT",
			Description:     "JWT security is enforced",
			RemediationText: "Review and remediate jwt security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecJwtSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecJwtSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_jwt_security
	_ = findings
	return findings, nil
}

// SecApiKeySecurityCheck - API key security is enforced
type SecApiKeySecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecApiKeySecurityCheck() *SecApiKeySecurityCheck {
	return &SecApiKeySecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_api_key_security",
			CheckTitle:      "API key security is enforced",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "APIKey",
			Description:     "API key security is enforced",
			RemediationText: "Review and remediate api key security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecApiKeySecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecApiKeySecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_api_key_security
	_ = findings
	return findings, nil
}

// SecTokenSecurityCheck - Token security is enforced
type SecTokenSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecTokenSecurityCheck() *SecTokenSecurityCheck {
	return &SecTokenSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_token_security",
			CheckTitle:      "Token security is enforced",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Token",
			Description:     "Token security is enforced",
			RemediationText: "Review and remediate token security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecTokenSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecTokenSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_token_security
	_ = findings
	return findings, nil
}

// SecSessionSecurityCheck - Session security is enforced
type SecSessionSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecSessionSecurityCheck() *SecSessionSecurityCheck {
	return &SecSessionSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_session_security",
			CheckTitle:      "Session security is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "Session",
			Description:     "Session security is enforced",
			RemediationText: "Review and remediate session security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecSessionSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecSessionSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_session_security
	_ = findings
	return findings, nil
}

// SecCookieSecurityCheck - Cookie security is enforced
type SecCookieSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewSecCookieSecurityCheck() *SecCookieSecurityCheck {
	return &SecCookieSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_cookie_security",
			CheckTitle:      "Cookie security is enforced",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Cookie",
			Description:     "Cookie security is enforced",
			RemediationText: "Review and remediate cookie security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCookieSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCookieSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_cookie_security
	_ = findings
	return findings, nil
}

// SecCsrfProtectionCheck - CSRF protection is enabled
type SecCsrfProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecCsrfProtectionCheck() *SecCsrfProtectionCheck {
	return &SecCsrfProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_csrf_protection",
			CheckTitle:      "CSRF protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "CSRF",
			Description:     "CSRF protection is enabled",
			RemediationText: "Review and remediate csrf protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCsrfProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCsrfProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_csrf_protection
	_ = findings
	return findings, nil
}

// SecXssProtectionCheck - XSS protection is enabled
type SecXssProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecXssProtectionCheck() *SecXssProtectionCheck {
	return &SecXssProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_xss_protection",
			CheckTitle:      "XSS protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "XSS",
			Description:     "XSS protection is enabled",
			RemediationText: "Review and remediate xss protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecXssProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecXssProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_xss_protection
	_ = findings
	return findings, nil
}

// SecCspPolicyCheck - CSP policy is configured
type SecCspPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewSecCspPolicyCheck() *SecCspPolicyCheck {
	return &SecCspPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_csp_policy",
			CheckTitle:      "CSP policy is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "CSP",
			Description:     "CSP policy is configured",
			RemediationText: "Review and remediate csp policy is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCspPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCspPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_csp_policy
	_ = findings
	return findings, nil
}

// SecHstsPolicyCheck - HSTS policy is configured
type SecHstsPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewSecHstsPolicyCheck() *SecHstsPolicyCheck {
	return &SecHstsPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_hsts_policy",
			CheckTitle:      "HSTS policy is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "HSTS",
			Description:     "HSTS policy is configured",
			RemediationText: "Review and remediate hsts policy is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecHstsPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecHstsPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_hsts_policy
	_ = findings
	return findings, nil
}

// SecXframeOptionsCheck - X-Frame-Options is configured
type SecXframeOptionsCheck struct {
	metadata models.CheckMetadata
}

func NewSecXframeOptionsCheck() *SecXframeOptionsCheck {
	return &SecXframeOptionsCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_xframe_options",
			CheckTitle:      "X-Frame-Options is configured",
			ServiceName:     "seguranca",
			Severity:        "medium",
			ResourceType:    "Header",
			Description:     "X-Frame-Options is configured",
			RemediationText: "Review and remediate x-frame-options is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecXframeOptionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecXframeOptionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_xframe_options
	_ = findings
	return findings, nil
}

// SecXcontentTypeCheck - X-Content-Type-Options is configured
type SecXcontentTypeCheck struct {
	metadata models.CheckMetadata
}

func NewSecXcontentTypeCheck() *SecXcontentTypeCheck {
	return &SecXcontentTypeCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_xcontent_type",
			CheckTitle:      "X-Content-Type-Options is configured",
			ServiceName:     "seguranca",
			Severity:        "medium",
			ResourceType:    "Header",
			Description:     "X-Content-Type-Options is configured",
			RemediationText: "Review and remediate x-content-type-options is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecXcontentTypeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecXcontentTypeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_xcontent_type
	_ = findings
	return findings, nil
}

// SecReferrerPolicyCheck - Referrer-Policy is configured
type SecReferrerPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewSecReferrerPolicyCheck() *SecReferrerPolicyCheck {
	return &SecReferrerPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_referrer_policy",
			CheckTitle:      "Referrer-Policy is configured",
			ServiceName:     "seguranca",
			Severity:        "low",
			ResourceType:    "Header",
			Description:     "Referrer-Policy is configured",
			RemediationText: "Review and remediate referrer-policy is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecReferrerPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecReferrerPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_referrer_policy
	_ = findings
	return findings, nil
}

// SecPermissionPolicyCheck - Permission-Policy is configured
type SecPermissionPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewSecPermissionPolicyCheck() *SecPermissionPolicyCheck {
	return &SecPermissionPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_permission_policy",
			CheckTitle:      "Permission-Policy is configured",
			ServiceName:     "seguranca",
			Severity:        "low",
			ResourceType:    "Header",
			Description:     "Permission-Policy is configured",
			RemediationText: "Review and remediate permission-policy is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecPermissionPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecPermissionPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_permission_policy
	_ = findings
	return findings, nil
}

// SecCorsPolicyCheck - CORS policy is configured
type SecCorsPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewSecCorsPolicyCheck() *SecCorsPolicyCheck {
	return &SecCorsPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_cors_policy",
			CheckTitle:      "CORS policy is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "CORS",
			Description:     "CORS policy is configured",
			RemediationText: "Review and remediate cors policy is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecCorsPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecCorsPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_cors_policy
	_ = findings
	return findings, nil
}

// SecInputValidationCheck - Input validation is enforced
type SecInputValidationCheck struct {
	metadata models.CheckMetadata
}

func NewSecInputValidationCheck() *SecInputValidationCheck {
	return &SecInputValidationCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_input_validation",
			CheckTitle:      "Input validation is enforced",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "Validation",
			Description:     "Input validation is enforced",
			RemediationText: "Review and remediate input validation is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecInputValidationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecInputValidationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_input_validation
	_ = findings
	return findings, nil
}

// SecOutputEncodingCheck - Output encoding is enforced
type SecOutputEncodingCheck struct {
	metadata models.CheckMetadata
}

func NewSecOutputEncodingCheck() *SecOutputEncodingCheck {
	return &SecOutputEncodingCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_output_encoding",
			CheckTitle:      "Output encoding is enforced",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Encoding",
			Description:     "Output encoding is enforced",
			RemediationText: "Review and remediate output encoding is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecOutputEncodingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecOutputEncodingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_output_encoding
	_ = findings
	return findings, nil
}

// SecSqlInjectionCheck - SQL injection protection is enabled
type SecSqlInjectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecSqlInjectionCheck() *SecSqlInjectionCheck {
	return &SecSqlInjectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_sql_injection",
			CheckTitle:      "SQL injection protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "SQLi",
			Description:     "SQL injection protection is enabled",
			RemediationText: "Review and remediate sql injection protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecSqlInjectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecSqlInjectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_sql_injection
	_ = findings
	return findings, nil
}

// SecNosqlInjectionCheck - NoSQL injection protection is enabled
type SecNosqlInjectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecNosqlInjectionCheck() *SecNosqlInjectionCheck {
	return &SecNosqlInjectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_nosql_injection",
			CheckTitle:      "NoSQL injection protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "NoSQLi",
			Description:     "NoSQL injection protection is enabled",
			RemediationText: "Review and remediate nosql injection protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecNosqlInjectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecNosqlInjectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_nosql_injection
	_ = findings
	return findings, nil
}

// SecLdapInjectionCheck - LDAP injection protection is enabled
type SecLdapInjectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecLdapInjectionCheck() *SecLdapInjectionCheck {
	return &SecLdapInjectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_ldap_injection",
			CheckTitle:      "LDAP injection protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "LDAP",
			Description:     "LDAP injection protection is enabled",
			RemediationText: "Review and remediate ldap injection protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecLdapInjectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecLdapInjectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_ldap_injection
	_ = findings
	return findings, nil
}

// SecXmlInjectionCheck - XML injection protection is enabled
type SecXmlInjectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecXmlInjectionCheck() *SecXmlInjectionCheck {
	return &SecXmlInjectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_xml_injection",
			CheckTitle:      "XML injection protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "XML",
			Description:     "XML injection protection is enabled",
			RemediationText: "Review and remediate xml injection protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecXmlInjectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecXmlInjectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_xml_injection
	_ = findings
	return findings, nil
}

// SecPathTraversalCheck - Path traversal protection is enabled
type SecPathTraversalCheck struct {
	metadata models.CheckMetadata
}

func NewSecPathTraversalCheck() *SecPathTraversalCheck {
	return &SecPathTraversalCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_path_traversal",
			CheckTitle:      "Path traversal protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "Path",
			Description:     "Path traversal protection is enabled",
			RemediationText: "Review and remediate path traversal protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecPathTraversalCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecPathTraversalCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_path_traversal
	_ = findings
	return findings, nil
}

// SecFileUploadCheck - File upload security is enforced
type SecFileUploadCheck struct {
	metadata models.CheckMetadata
}

func NewSecFileUploadCheck() *SecFileUploadCheck {
	return &SecFileUploadCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_file_upload",
			CheckTitle:      "File upload security is enforced",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "File",
			Description:     "File upload security is enforced",
			RemediationText: "Review and remediate file upload security is enforced",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecFileUploadCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecFileUploadCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_file_upload
	_ = findings
	return findings, nil
}

// SecRateLimitingCheck - Rate limiting is configured
type SecRateLimitingCheck struct {
	metadata models.CheckMetadata
}

func NewSecRateLimitingCheck() *SecRateLimitingCheck {
	return &SecRateLimitingCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_rate_limiting",
			CheckTitle:      "Rate limiting is configured",
			ServiceName:     "seguranca",
			Severity:        "high",
			ResourceType:    "RateLimit",
			Description:     "Rate limiting is configured",
			RemediationText: "Review and remediate rate limiting is configured",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecRateLimitingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecRateLimitingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_rate_limiting
	_ = findings
	return findings, nil
}

// SecDdosProtectionCheck - DDoS protection is enabled
type SecDdosProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecDdosProtectionCheck() *SecDdosProtectionCheck {
	return &SecDdosProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_ddos_protection",
			CheckTitle:      "DDoS protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "DDoS",
			Description:     "DDoS protection is enabled",
			RemediationText: "Review and remediate ddos protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecDdosProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecDdosProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_ddos_protection
	_ = findings
	return findings, nil
}

// SecWafProtectionCheck - WAF protection is enabled
type SecWafProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewSecWafProtectionCheck() *SecWafProtectionCheck {
	return &SecWafProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "seguranca",
			CheckID:         "sec_waf_protection",
			CheckTitle:      "WAF protection is enabled",
			ServiceName:     "seguranca",
			Severity:        "critical",
			ResourceType:    "WAF",
			Description:     "WAF protection is enabled",
			RemediationText: "Review and remediate waf protection is enabled",
			Categories:      []string{"seguranca", "security"},
		},
	}
}

func (c *SecWafProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecWafProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(segurancaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement segurancaProvider")
	}
	client, err := p.Seguranca(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement sec_waf_protection
	_ = findings
	return findings, nil
}
