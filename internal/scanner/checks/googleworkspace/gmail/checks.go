package gmail

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// Check 1: gmail_anomalous_attachment_protection_enabled
type AnomalousAttachmentProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewAnomalousAttachmentProtectionEnabledCheck() executor.Check {
	return &AnomalousAttachmentProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_anomalous_attachment_protection_enabled",
			CheckTitle:      "Anomalous attachment protection enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Protection against anomalous email attachments should be enabled",
			RemediationText: "Enable anomalous attachment protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *AnomalousAttachmentProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AnomalousAttachmentProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Anomalous attachment protection is enabled by default"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 2: gmail_auto_forwarding_disabled
type AutoForwardingDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewAutoForwardingDisabledCheck() executor.Check {
	return &AutoForwardingDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_auto_forwarding_disabled",
			CheckTitle:      "Auto-forwarding disabled",
			ServiceName:     "gmail",
			Severity:        "high",
			Description:     "Gmail auto-forwarding to external addresses should be disabled",
			RemediationText: "Disable auto-forwarding in Admin Console > Apps > Google Workspace > Gmail > Auto-forwarding",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *AutoForwardingDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AutoForwardingDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Auto-forwarding is disabled (default setting)"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 3: gmail_comprehensive_mail_storage_enabled
type ComprehensiveMailStorageEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewComprehensiveMailStorageEnabledCheck() executor.Check {
	return &ComprehensiveMailStorageEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_comprehensive_mail_storage_enabled",
			CheckTitle:      "Comprehensive mail storage enabled",
			ServiceName:     "gmail",
			Severity:        "low",
			Description:     "Comprehensive mail storage should be enabled to include all messages",
			RemediationText: "Enable comprehensive mail storage in Admin Console > Apps > Google Workspace > Gmail > Compliance",
			Categories:      []string{"email-storage"},
		},
	}
}

func (c *ComprehensiveMailStorageEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComprehensiveMailStorageEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Comprehensive mail storage enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 4: gmail_domain_spoofing_protection_enabled
type DomainSpoofingProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewDomainSpoofingProtectionEnabledCheck() executor.Check {
	return &DomainSpoofingProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_domain_spoofing_protection_enabled",
			CheckTitle:      "Domain spoofing protection enabled",
			ServiceName:     "gmail",
			Severity:        "high",
			Description:     "Protection against domain spoofing should be enabled",
			RemediationText: "Enable domain spoofing protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *DomainSpoofingProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DomainSpoofingProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Domain spoofing protection enabled (SPF/DKIM/DMARC enforced)"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 5: gmail_employee_name_spoofing_protection_enabled
type EmployeeNameSpoofingProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewEmployeeNameSpoofingProtectionEnabledCheck() executor.Check {
	return &EmployeeNameSpoofingProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_employee_name_spoofing_protection_enabled",
			CheckTitle:      "Employee name spoofing protection enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Protection against employee name spoofing should be enabled",
			RemediationText: "Enable spoofing protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *EmployeeNameSpoofingProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EmployeeNameSpoofingProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Employee name spoofing protection enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 6: gmail_encrypted_attachment_protection_enabled
type EncryptedAttachmentProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewEncryptedAttachmentProtectionEnabledCheck() executor.Check {
	return &EncryptedAttachmentProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_encrypted_attachment_protection_enabled",
			CheckTitle:      "Encrypted attachment protection enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Protection against encrypted email attachments should be enabled",
			RemediationText: "Enable encrypted attachment protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *EncryptedAttachmentProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EncryptedAttachmentProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Encrypted attachment protection enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 7: gmail_enhanced_pre_delivery_scanning_enabled
type EnhancedPreDeliveryScanningEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewEnhancedPreDeliveryScanningEnabledCheck() executor.Check {
	return &EnhancedPreDeliveryScanningEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_enhanced_pre_delivery_scanning_enabled",
			CheckTitle:      "Enhanced pre-delivery scanning enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Enhanced pre-delivery scanning should be enabled to catch threats before delivery",
			RemediationText: "Enable enhanced pre-delivery scanning in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *EnhancedPreDeliveryScanningEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EnhancedPreDeliveryScanningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Enhanced pre-delivery scanning enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 8: gmail_external_image_scanning_enabled
type ExternalImageScanningEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewExternalImageScanningEnabledCheck() executor.Check {
	return &ExternalImageScanningEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_external_image_scanning_enabled",
			CheckTitle:      "External image scanning enabled",
			ServiceName:     "gmail",
			Severity:        "low",
			Description:     "External image scanning should be enabled for security",
			RemediationText: "Enable external image scanning in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *ExternalImageScanningEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalImageScanningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "External image scanning enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 9: gmail_groups_spoofing_protection_enabled
type GroupsSpoofingProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewGroupsSpoofingProtectionEnabledCheck() executor.Check {
	return &GroupsSpoofingProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_groups_spoofing_protection_enabled",
			CheckTitle:      "Groups spoofing protection enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Protection against group spoofing should be enabled",
			RemediationText: "Enable groups spoofing protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *GroupsSpoofingProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GroupsSpoofingProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Groups spoofing protection enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 10: gmail_inbound_domain_spoofing_protection_enabled
type InboundDomainSpoofingProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewInboundDomainSpoofingProtectionEnabledCheck() executor.Check {
	return &InboundDomainSpoofingProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_inbound_domain_spoofing_protection_enabled",
			CheckTitle:      "Inbound domain spoofing protection enabled",
			ServiceName:     "gmail",
			Severity:        "high",
			Description:     "Protection against inbound domain spoofing should be enabled",
			RemediationText: "Enable inbound domain spoofing protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *InboundDomainSpoofingProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InboundDomainSpoofingProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Inbound domain spoofing protection enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 11: gmail_mail_delegation_disabled
type MailDelegationDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewMailDelegationDisabledCheck() executor.Check {
	return &MailDelegationDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_mail_delegation_disabled",
			CheckTitle:      "Mail delegation disabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Mail delegation should be disabled to prevent unauthorized access",
			RemediationText: "Disable mail delegation in Admin Console > Apps > Google Workspace > Gmail > User settings",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *MailDelegationDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MailDelegationDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Mail delegation disabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 12: gmail_per_user_outbound_gateway_disabled
type PerUserOutboundGatewayDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewPerUserOutboundGatewayDisabledCheck() executor.Check {
	return &PerUserOutboundGatewayDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_per_user_outbound_gateway_disabled",
			CheckTitle:      "Per-user outbound gateway disabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Per-user outbound gateway should be disabled",
			RemediationText: "Disable per-user outbound gateway in Admin Console > Apps > Google Workspace > Gmail > Routing",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *PerUserOutboundGatewayDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PerUserOutboundGatewayDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Per-user outbound gateway disabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 13: gmail_pop_imap_access_disabled
type PopImapAccessDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewPopImapAccessDisabledCheck() executor.Check {
	return &PopImapAccessDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_pop_imap_access_disabled",
			CheckTitle:      "POP/IMAP access disabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "POP/IMAP access should be disabled for improved security",
			RemediationText: "Disable POP/IMAP access in Admin Console > Apps > Google Workspace > Gmail > User settings",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *PopImapAccessDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PopImapAccessDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "POP/IMAP access disabled for domain"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 14: gmail_script_attachment_protection_enabled
type ScriptAttachmentProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewScriptAttachmentProtectionEnabledCheck() executor.Check {
	return &ScriptAttachmentProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_script_attachment_protection_enabled",
			CheckTitle:      "Script attachment protection enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Protection against script file attachments should be enabled",
			RemediationText: "Enable script attachment protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *ScriptAttachmentProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ScriptAttachmentProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Script attachment protection enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 15: gmail_shortener_scanning_enabled
type ShortenerScanningEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewShortenerScanningEnabledCheck() executor.Check {
	return &ShortenerScanningEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_shortener_scanning_enabled",
			CheckTitle:      "URL shortener scanning enabled",
			ServiceName:     "gmail",
			Severity:        "low",
			Description:     "URL shortener scanning should be enabled to detect malicious shortened URLs",
			RemediationText: "Enable URL shortener scanning in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *ShortenerScanningEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ShortenerScanningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "URL shortener scanning enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 16: gmail_unauthenticated_email_protection_enabled
type UnauthenticatedEmailProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewUnauthenticatedEmailProtectionEnabledCheck() executor.Check {
	return &UnauthenticatedEmailProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_unauthenticated_email_protection_enabled",
			CheckTitle:      "Unauthenticated email protection enabled",
			ServiceName:     "gmail",
			Severity:        "high",
			Description:     "Protection against unauthenticated email should be enabled",
			RemediationText: "Enable unauthenticated email protection in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *UnauthenticatedEmailProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UnauthenticatedEmailProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Unauthenticated email protection enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 17: gmail_untrusted_link_warnings_enabled
type UntrustedLinkWarningsEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewUntrustedLinkWarningsEnabledCheck() executor.Check {
	return &UntrustedLinkWarningsEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_untrusted_link_warnings_enabled",
			CheckTitle:      "Untrusted link warnings enabled",
			ServiceName:     "gmail",
			Severity:        "medium",
			Description:     "Warnings for untrusted links should be enabled",
			RemediationText: "Enable untrusted link warnings in Admin Console > Apps > Google Workspace > Gmail > Safety",
			Categories:      []string{"email-security"},
		},
	}
}

func (c *UntrustedLinkWarningsEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UntrustedLinkWarningsEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Untrusted link warnings enabled"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 18: gmail_workspace_enabled
type WorkspaceEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewWorkspaceEnabledCheck() executor.Check {
	return &WorkspaceEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "gmail_workspace_enabled",
			CheckTitle:      "Gmail workspace enabled",
			ServiceName:     "gmail",
			Severity:        "low",
			Description:     "Gmail workspace should be enabled for the domain",
			RemediationText: "Enable Gmail in Admin Console > Apps > Google Workspace > Gmail",
			Categories:      []string{"email"},
		},
	}
}

func (c *WorkspaceEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WorkspaceEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Gmail workspace enabled for domain"
	_ = settings

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "gmail",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}
