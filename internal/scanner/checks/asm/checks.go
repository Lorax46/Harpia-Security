package asm

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type asmProvider interface {
	Asm(ctx context.Context) (interface{}, error)
}

// AsmProvider interface

// ExternalIpDiscoveryCheck - External IP addresses are discovered
type ExternalIpDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalIpDiscoveryCheck() *ExternalIpDiscoveryCheck {
	return &ExternalIpDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_ip_discovery",
			CheckTitle:      "External IP addresses are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Network",
			Description:     "External IP addresses are discovered",
			RemediationText: "Review and remediate external ip addresses are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalIpDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalIpDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_ip_discovery
	_ = findings
	return findings, nil
}

// ExternalDomainDiscoveryCheck - External domains are discovered
type ExternalDomainDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalDomainDiscoveryCheck() *ExternalDomainDiscoveryCheck {
	return &ExternalDomainDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_domain_discovery",
			CheckTitle:      "External domains are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "DNS",
			Description:     "External domains are discovered",
			RemediationText: "Review and remediate external domains are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalDomainDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalDomainDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_domain_discovery
	_ = findings
	return findings, nil
}

// ExternalSubdomainDiscoveryCheck - External subdomains are discovered
type ExternalSubdomainDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSubdomainDiscoveryCheck() *ExternalSubdomainDiscoveryCheck {
	return &ExternalSubdomainDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_subdomain_discovery",
			CheckTitle:      "External subdomains are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "DNS",
			Description:     "External subdomains are discovered",
			RemediationText: "Review and remediate external subdomains are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalSubdomainDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSubdomainDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_subdomain_discovery
	_ = findings
	return findings, nil
}

// ExternalSslDiscoveryCheck - External SSL certificates are discovered
type ExternalSslDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSslDiscoveryCheck() *ExternalSslDiscoveryCheck {
	return &ExternalSslDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_ssl_discovery",
			CheckTitle:      "External SSL certificates are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "External SSL certificates are discovered",
			RemediationText: "Review and remediate external ssl certificates are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalSslDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSslDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_ssl_discovery
	_ = findings
	return findings, nil
}

// ExternalServiceDiscoveryCheck - External services are discovered
type ExternalServiceDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalServiceDiscoveryCheck() *ExternalServiceDiscoveryCheck {
	return &ExternalServiceDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_service_discovery",
			CheckTitle:      "External services are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Service",
			Description:     "External services are discovered",
			RemediationText: "Review and remediate external services are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalServiceDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalServiceDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_service_discovery
	_ = findings
	return findings, nil
}

// ExternalPortDiscoveryCheck - External ports are discovered
type ExternalPortDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPortDiscoveryCheck() *ExternalPortDiscoveryCheck {
	return &ExternalPortDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_port_discovery",
			CheckTitle:      "External ports are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Port",
			Description:     "External ports are discovered",
			RemediationText: "Review and remediate external ports are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPortDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPortDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_port_discovery
	_ = findings
	return findings, nil
}

// ExternalTechnologyDiscoveryCheck - External technologies are discovered
type ExternalTechnologyDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalTechnologyDiscoveryCheck() *ExternalTechnologyDiscoveryCheck {
	return &ExternalTechnologyDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_technology_discovery",
			CheckTitle:      "External technologies are discovered",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Technology",
			Description:     "External technologies are discovered",
			RemediationText: "Review and remediate external technologies are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalTechnologyDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalTechnologyDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_technology_discovery
	_ = findings
	return findings, nil
}

// ExternalFrameworkDiscoveryCheck - External frameworks are discovered
type ExternalFrameworkDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalFrameworkDiscoveryCheck() *ExternalFrameworkDiscoveryCheck {
	return &ExternalFrameworkDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_framework_discovery",
			CheckTitle:      "External frameworks are discovered",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Framework",
			Description:     "External frameworks are discovered",
			RemediationText: "Review and remediate external frameworks are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalFrameworkDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalFrameworkDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_framework_discovery
	_ = findings
	return findings, nil
}

// ExternalCmsDiscoveryCheck - External CMS are discovered
type ExternalCmsDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalCmsDiscoveryCheck() *ExternalCmsDiscoveryCheck {
	return &ExternalCmsDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_cms_discovery",
			CheckTitle:      "External CMS are discovered",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "CMS",
			Description:     "External CMS are discovered",
			RemediationText: "Review and remediate external cms are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalCmsDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalCmsDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_cms_discovery
	_ = findings
	return findings, nil
}

// ExternalJsDiscoveryCheck - External JavaScript libraries are discovered
type ExternalJsDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalJsDiscoveryCheck() *ExternalJsDiscoveryCheck {
	return &ExternalJsDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_js_discovery",
			CheckTitle:      "External JavaScript libraries are discovered",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "JavaScript",
			Description:     "External JavaScript libraries are discovered",
			RemediationText: "Review and remediate external javascript libraries are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalJsDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalJsDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_js_discovery
	_ = findings
	return findings, nil
}

// ExternalCssDiscoveryCheck - External CSS frameworks are discovered
type ExternalCssDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalCssDiscoveryCheck() *ExternalCssDiscoveryCheck {
	return &ExternalCssDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_css_discovery",
			CheckTitle:      "External CSS frameworks are discovered",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "CSS",
			Description:     "External CSS frameworks are discovered",
			RemediationText: "Review and remediate external css frameworks are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalCssDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalCssDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_css_discovery
	_ = findings
	return findings, nil
}

// ExternalFontDiscoveryCheck - External fonts are discovered
type ExternalFontDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalFontDiscoveryCheck() *ExternalFontDiscoveryCheck {
	return &ExternalFontDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_font_discovery",
			CheckTitle:      "External fonts are discovered",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Font",
			Description:     "External fonts are discovered",
			RemediationText: "Review and remediate external fonts are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalFontDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalFontDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_font_discovery
	_ = findings
	return findings, nil
}

// ExternalImageDiscoveryCheck - External images are discovered
type ExternalImageDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalImageDiscoveryCheck() *ExternalImageDiscoveryCheck {
	return &ExternalImageDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_image_discovery",
			CheckTitle:      "External images are discovered",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Image",
			Description:     "External images are discovered",
			RemediationText: "Review and remediate external images are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalImageDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalImageDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_image_discovery
	_ = findings
	return findings, nil
}

// ExternalVideoDiscoveryCheck - External videos are discovered
type ExternalVideoDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalVideoDiscoveryCheck() *ExternalVideoDiscoveryCheck {
	return &ExternalVideoDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_video_discovery",
			CheckTitle:      "External videos are discovered",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Video",
			Description:     "External videos are discovered",
			RemediationText: "Review and remediate external videos are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalVideoDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalVideoDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_video_discovery
	_ = findings
	return findings, nil
}

// ExternalDocumentDiscoveryCheck - External documents are discovered
type ExternalDocumentDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalDocumentDiscoveryCheck() *ExternalDocumentDiscoveryCheck {
	return &ExternalDocumentDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_document_discovery",
			CheckTitle:      "External documents are discovered",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Document",
			Description:     "External documents are discovered",
			RemediationText: "Review and remediate external documents are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalDocumentDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalDocumentDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_document_discovery
	_ = findings
	return findings, nil
}

// ExternalEmailDiscoveryCheck - External emails are discovered
type ExternalEmailDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalEmailDiscoveryCheck() *ExternalEmailDiscoveryCheck {
	return &ExternalEmailDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_email_discovery",
			CheckTitle:      "External emails are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Email",
			Description:     "External emails are discovered",
			RemediationText: "Review and remediate external emails are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalEmailDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalEmailDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_email_discovery
	_ = findings
	return findings, nil
}

// ExternalPhoneDiscoveryCheck - External phone numbers are discovered
type ExternalPhoneDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPhoneDiscoveryCheck() *ExternalPhoneDiscoveryCheck {
	return &ExternalPhoneDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_phone_discovery",
			CheckTitle:      "External phone numbers are discovered",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Phone",
			Description:     "External phone numbers are discovered",
			RemediationText: "Review and remediate external phone numbers are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPhoneDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPhoneDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_phone_discovery
	_ = findings
	return findings, nil
}

// ExternalSocialDiscoveryCheck - External social media are discovered
type ExternalSocialDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSocialDiscoveryCheck() *ExternalSocialDiscoveryCheck {
	return &ExternalSocialDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_social_discovery",
			CheckTitle:      "External social media are discovered",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Social",
			Description:     "External social media are discovered",
			RemediationText: "Review and remediate external social media are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalSocialDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSocialDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_social_discovery
	_ = findings
	return findings, nil
}

// ExternalCodeDiscoveryCheck - External code repositories are discovered
type ExternalCodeDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalCodeDiscoveryCheck() *ExternalCodeDiscoveryCheck {
	return &ExternalCodeDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_code_discovery",
			CheckTitle:      "External code repositories are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "External code repositories are discovered",
			RemediationText: "Review and remediate external code repositories are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalCodeDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalCodeDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_code_discovery
	_ = findings
	return findings, nil
}

// ExternalCloudDiscoveryCheck - External cloud resources are discovered
type ExternalCloudDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewExternalCloudDiscoveryCheck() *ExternalCloudDiscoveryCheck {
	return &ExternalCloudDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_cloud_discovery",
			CheckTitle:      "External cloud resources are discovered",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Cloud",
			Description:     "External cloud resources are discovered",
			RemediationText: "Review and remediate external cloud resources are discovered",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalCloudDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalCloudDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_cloud_discovery
	_ = findings
	return findings, nil
}

// ExternalThreatIntelCheck - Threat intelligence is integrated
type ExternalThreatIntelCheck struct {
	metadata models.CheckMetadata
}

func NewExternalThreatIntelCheck() *ExternalThreatIntelCheck {
	return &ExternalThreatIntelCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_threat_intel",
			CheckTitle:      "Threat intelligence is integrated",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "ThreatIntel",
			Description:     "Threat intelligence is integrated",
			RemediationText: "Review and remediate threat intelligence is integrated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalThreatIntelCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalThreatIntelCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_threat_intel
	_ = findings
	return findings, nil
}

// ExternalDarkWebCheck - Dark web monitoring is enabled
type ExternalDarkWebCheck struct {
	metadata models.CheckMetadata
}

func NewExternalDarkWebCheck() *ExternalDarkWebCheck {
	return &ExternalDarkWebCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_dark_web",
			CheckTitle:      "Dark web monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "DarkWeb",
			Description:     "Dark web monitoring is enabled",
			RemediationText: "Review and remediate dark web monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalDarkWebCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalDarkWebCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_dark_web
	_ = findings
	return findings, nil
}

// ExternalPasteSitesCheck - Paste site monitoring is enabled
type ExternalPasteSitesCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPasteSitesCheck() *ExternalPasteSitesCheck {
	return &ExternalPasteSitesCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_paste_sites",
			CheckTitle:      "Paste site monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Paste",
			Description:     "Paste site monitoring is enabled",
			RemediationText: "Review and remediate paste site monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPasteSitesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPasteSitesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_paste_sites
	_ = findings
	return findings, nil
}

// ExternalBreachDbCheck - Breach database monitoring is enabled
type ExternalBreachDbCheck struct {
	metadata models.CheckMetadata
}

func NewExternalBreachDbCheck() *ExternalBreachDbCheck {
	return &ExternalBreachDbCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_breach_db",
			CheckTitle:      "Breach database monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Breach",
			Description:     "Breach database monitoring is enabled",
			RemediationText: "Review and remediate breach database monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalBreachDbCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalBreachDbCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_breach_db
	_ = findings
	return findings, nil
}

// ExternalCveMonitoringCheck - CVE monitoring is enabled
type ExternalCveMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalCveMonitoringCheck() *ExternalCveMonitoringCheck {
	return &ExternalCveMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_cve_monitoring",
			CheckTitle:      "CVE monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "CVE",
			Description:     "CVE monitoring is enabled",
			RemediationText: "Review and remediate cve monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalCveMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalCveMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_cve_monitoring
	_ = findings
	return findings, nil
}

// ExternalExploitMonitoringCheck - Exploit monitoring is enabled
type ExternalExploitMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalExploitMonitoringCheck() *ExternalExploitMonitoringCheck {
	return &ExternalExploitMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_exploit_monitoring",
			CheckTitle:      "Exploit monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Exploit",
			Description:     "Exploit monitoring is enabled",
			RemediationText: "Review and remediate exploit monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalExploitMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalExploitMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_exploit_monitoring
	_ = findings
	return findings, nil
}

// ExternalMalwareMonitoringCheck - Malware monitoring is enabled
type ExternalMalwareMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalMalwareMonitoringCheck() *ExternalMalwareMonitoringCheck {
	return &ExternalMalwareMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_malware_monitoring",
			CheckTitle:      "Malware monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Malware",
			Description:     "Malware monitoring is enabled",
			RemediationText: "Review and remediate malware monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalMalwareMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalMalwareMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_malware_monitoring
	_ = findings
	return findings, nil
}

// ExternalPhishingMonitoringCheck - Phishing monitoring is enabled
type ExternalPhishingMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPhishingMonitoringCheck() *ExternalPhishingMonitoringCheck {
	return &ExternalPhishingMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_phishing_monitoring",
			CheckTitle:      "Phishing monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Phishing",
			Description:     "Phishing monitoring is enabled",
			RemediationText: "Review and remediate phishing monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPhishingMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPhishingMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_phishing_monitoring
	_ = findings
	return findings, nil
}

// ExternalBrandMonitoringCheck - Brand monitoring is enabled
type ExternalBrandMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalBrandMonitoringCheck() *ExternalBrandMonitoringCheck {
	return &ExternalBrandMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_brand_monitoring",
			CheckTitle:      "Brand monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Brand",
			Description:     "Brand monitoring is enabled",
			RemediationText: "Review and remediate brand monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalBrandMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalBrandMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_brand_monitoring
	_ = findings
	return findings, nil
}

// ExternalTyposquatMonitoringCheck - Typosquat monitoring is enabled
type ExternalTyposquatMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalTyposquatMonitoringCheck() *ExternalTyposquatMonitoringCheck {
	return &ExternalTyposquatMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_typosquat_monitoring",
			CheckTitle:      "Typosquat monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Typosquat",
			Description:     "Typosquat monitoring is enabled",
			RemediationText: "Review and remediate typosquat monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalTyposquatMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalTyposquatMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_typosquat_monitoring
	_ = findings
	return findings, nil
}

// ExternalImpersonationMonitoringCheck - Impersonation monitoring is enabled
type ExternalImpersonationMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewExternalImpersonationMonitoringCheck() *ExternalImpersonationMonitoringCheck {
	return &ExternalImpersonationMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_impersonation_monitoring",
			CheckTitle:      "Impersonation monitoring is enabled",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "Impersonation",
			Description:     "Impersonation monitoring is enabled",
			RemediationText: "Review and remediate impersonation monitoring is enabled",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalImpersonationMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalImpersonationMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_impersonation_monitoring
	_ = findings
	return findings, nil
}

// ExternalTakedownCheck - Takedown service is configured
type ExternalTakedownCheck struct {
	metadata models.CheckMetadata
}

func NewExternalTakedownCheck() *ExternalTakedownCheck {
	return &ExternalTakedownCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_takedown",
			CheckTitle:      "Takedown service is configured",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Takedown",
			Description:     "Takedown service is configured",
			RemediationText: "Review and remediate takedown service is configured",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalTakedownCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalTakedownCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_takedown
	_ = findings
	return findings, nil
}

// ExternalVulnerabilityIntelCheck - Vulnerability intelligence is integrated
type ExternalVulnerabilityIntelCheck struct {
	metadata models.CheckMetadata
}

func NewExternalVulnerabilityIntelCheck() *ExternalVulnerabilityIntelCheck {
	return &ExternalVulnerabilityIntelCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_vulnerability_intel",
			CheckTitle:      "Vulnerability intelligence is integrated",
			ServiceName:     "asm",
			Severity:        "high",
			ResourceType:    "VulnIntel",
			Description:     "Vulnerability intelligence is integrated",
			RemediationText: "Review and remediate vulnerability intelligence is integrated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalVulnerabilityIntelCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalVulnerabilityIntelCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_vulnerability_intel
	_ = findings
	return findings, nil
}

// ExternalAttackSurfaceReportCheck - Attack surface report is generated
type ExternalAttackSurfaceReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalAttackSurfaceReportCheck() *ExternalAttackSurfaceReportCheck {
	return &ExternalAttackSurfaceReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_attack_surface_report",
			CheckTitle:      "Attack surface report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Report",
			Description:     "Attack surface report is generated",
			RemediationText: "Review and remediate attack surface report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalAttackSurfaceReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalAttackSurfaceReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_attack_surface_report
	_ = findings
	return findings, nil
}

// ExternalRiskScoreCheck - Risk score is calculated
type ExternalRiskScoreCheck struct {
	metadata models.CheckMetadata
}

func NewExternalRiskScoreCheck() *ExternalRiskScoreCheck {
	return &ExternalRiskScoreCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_risk_score",
			CheckTitle:      "Risk score is calculated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Risk",
			Description:     "Risk score is calculated",
			RemediationText: "Review and remediate risk score is calculated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalRiskScoreCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalRiskScoreCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_risk_score
	_ = findings
	return findings, nil
}

// ExternalExposureScoreCheck - Exposure score is calculated
type ExternalExposureScoreCheck struct {
	metadata models.CheckMetadata
}

func NewExternalExposureScoreCheck() *ExternalExposureScoreCheck {
	return &ExternalExposureScoreCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_exposure_score",
			CheckTitle:      "Exposure score is calculated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Exposure",
			Description:     "Exposure score is calculated",
			RemediationText: "Review and remediate exposure score is calculated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalExposureScoreCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalExposureScoreCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_exposure_score
	_ = findings
	return findings, nil
}

// ExternalSecurityRatingCheck - Security rating is calculated
type ExternalSecurityRatingCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSecurityRatingCheck() *ExternalSecurityRatingCheck {
	return &ExternalSecurityRatingCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_security_rating",
			CheckTitle:      "Security rating is calculated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Rating",
			Description:     "Security rating is calculated",
			RemediationText: "Review and remediate security rating is calculated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalSecurityRatingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSecurityRatingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_security_rating
	_ = findings
	return findings, nil
}

// ExternalComplianceScoreCheck - Compliance score is calculated
type ExternalComplianceScoreCheck struct {
	metadata models.CheckMetadata
}

func NewExternalComplianceScoreCheck() *ExternalComplianceScoreCheck {
	return &ExternalComplianceScoreCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_compliance_score",
			CheckTitle:      "Compliance score is calculated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Compliance",
			Description:     "Compliance score is calculated",
			RemediationText: "Review and remediate compliance score is calculated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalComplianceScoreCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalComplianceScoreCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_compliance_score
	_ = findings
	return findings, nil
}

// ExternalTrendAnalysisCheck - Trend analysis is performed
type ExternalTrendAnalysisCheck struct {
	metadata models.CheckMetadata
}

func NewExternalTrendAnalysisCheck() *ExternalTrendAnalysisCheck {
	return &ExternalTrendAnalysisCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_trend_analysis",
			CheckTitle:      "Trend analysis is performed",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Trend",
			Description:     "Trend analysis is performed",
			RemediationText: "Review and remediate trend analysis is performed",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalTrendAnalysisCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalTrendAnalysisCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_trend_analysis
	_ = findings
	return findings, nil
}

// ExternalPeerBenchmarkCheck - Peer benchmark is performed
type ExternalPeerBenchmarkCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPeerBenchmarkCheck() *ExternalPeerBenchmarkCheck {
	return &ExternalPeerBenchmarkCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_peer_benchmark",
			CheckTitle:      "Peer benchmark is performed",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Benchmark",
			Description:     "Peer benchmark is performed",
			RemediationText: "Review and remediate peer benchmark is performed",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPeerBenchmarkCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPeerBenchmarkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_peer_benchmark
	_ = findings
	return findings, nil
}

// ExternalExecutiveReportCheck - Executive report is generated
type ExternalExecutiveReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalExecutiveReportCheck() *ExternalExecutiveReportCheck {
	return &ExternalExecutiveReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_executive_report",
			CheckTitle:      "Executive report is generated",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Executive",
			Description:     "Executive report is generated",
			RemediationText: "Review and remediate executive report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalExecutiveReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalExecutiveReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_executive_report
	_ = findings
	return findings, nil
}

// ExternalTechnicalReportCheck - Technical report is generated
type ExternalTechnicalReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalTechnicalReportCheck() *ExternalTechnicalReportCheck {
	return &ExternalTechnicalReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_technical_report",
			CheckTitle:      "Technical report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Technical",
			Description:     "Technical report is generated",
			RemediationText: "Review and remediate technical report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalTechnicalReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalTechnicalReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_technical_report
	_ = findings
	return findings, nil
}

// ExternalComplianceReportCheck - Compliance report is generated
type ExternalComplianceReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalComplianceReportCheck() *ExternalComplianceReportCheck {
	return &ExternalComplianceReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_compliance_report",
			CheckTitle:      "Compliance report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "ComplianceReport",
			Description:     "Compliance report is generated",
			RemediationText: "Review and remediate compliance report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalComplianceReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalComplianceReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_compliance_report
	_ = findings
	return findings, nil
}

// ExternalAuditReportCheck - Audit report is generated
type ExternalAuditReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalAuditReportCheck() *ExternalAuditReportCheck {
	return &ExternalAuditReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_audit_report",
			CheckTitle:      "Audit report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "AuditReport",
			Description:     "Audit report is generated",
			RemediationText: "Review and remediate audit report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalAuditReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalAuditReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_audit_report
	_ = findings
	return findings, nil
}

// ExternalPentestReportCheck - Pentest report is generated
type ExternalPentestReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPentestReportCheck() *ExternalPentestReportCheck {
	return &ExternalPentestReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_pentest_report",
			CheckTitle:      "Pentest report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "PentestReport",
			Description:     "Pentest report is generated",
			RemediationText: "Review and remediate pentest report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPentestReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPentestReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_pentest_report
	_ = findings
	return findings, nil
}

// ExternalRedTeamReportCheck - Red team report is generated
type ExternalRedTeamReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalRedTeamReportCheck() *ExternalRedTeamReportCheck {
	return &ExternalRedTeamReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_red_team_report",
			CheckTitle:      "Red team report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "RedTeam",
			Description:     "Red team report is generated",
			RemediationText: "Review and remediate red team report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalRedTeamReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalRedTeamReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_red_team_report
	_ = findings
	return findings, nil
}

// ExternalBlueTeamReportCheck - Blue team report is generated
type ExternalBlueTeamReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalBlueTeamReportCheck() *ExternalBlueTeamReportCheck {
	return &ExternalBlueTeamReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_blue_team_report",
			CheckTitle:      "Blue team report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "BlueTeam",
			Description:     "Blue team report is generated",
			RemediationText: "Review and remediate blue team report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalBlueTeamReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalBlueTeamReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_blue_team_report
	_ = findings
	return findings, nil
}

// ExternalPurpleTeamReportCheck - Purple team report is generated
type ExternalPurpleTeamReportCheck struct {
	metadata models.CheckMetadata
}

func NewExternalPurpleTeamReportCheck() *ExternalPurpleTeamReportCheck {
	return &ExternalPurpleTeamReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_purple_team_report",
			CheckTitle:      "Purple team report is generated",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "PurpleTeam",
			Description:     "Purple team report is generated",
			RemediationText: "Review and remediate purple team report is generated",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalPurpleTeamReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalPurpleTeamReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_purple_team_report
	_ = findings
	return findings, nil
}

// ExternalTabletopExerciseCheck - Tabletop exercise is performed
type ExternalTabletopExerciseCheck struct {
	metadata models.CheckMetadata
}

func NewExternalTabletopExerciseCheck() *ExternalTabletopExerciseCheck {
	return &ExternalTabletopExerciseCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_tabletop_exercise",
			CheckTitle:      "Tabletop exercise is performed",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "Tabletop",
			Description:     "Tabletop exercise is performed",
			RemediationText: "Review and remediate tabletop exercise is performed",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalTabletopExerciseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalTabletopExerciseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_tabletop_exercise
	_ = findings
	return findings, nil
}

// ExternalWarGameCheck - War game is performed
type ExternalWarGameCheck struct {
	metadata models.CheckMetadata
}

func NewExternalWarGameCheck() *ExternalWarGameCheck {
	return &ExternalWarGameCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_war_game",
			CheckTitle:      "War game is performed",
			ServiceName:     "asm",
			Severity:        "low",
			ResourceType:    "WarGame",
			Description:     "War game is performed",
			RemediationText: "Review and remediate war game is performed",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalWarGameCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalWarGameCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_war_game
	_ = findings
	return findings, nil
}

// ExternalIncidentSimulationCheck - Incident simulation is performed
type ExternalIncidentSimulationCheck struct {
	metadata models.CheckMetadata
}

func NewExternalIncidentSimulationCheck() *ExternalIncidentSimulationCheck {
	return &ExternalIncidentSimulationCheck{
		metadata: models.CheckMetadata{
			Provider:        "asm",
			CheckID:         "asm_external_incident_simulation",
			CheckTitle:      "Incident simulation is performed",
			ServiceName:     "asm",
			Severity:        "medium",
			ResourceType:    "Incident",
			Description:     "Incident simulation is performed",
			RemediationText: "Review and remediate incident simulation is performed",
			Categories:      []string{"asm", "security"},
		},
	}
}

func (c *ExternalIncidentSimulationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalIncidentSimulationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(asmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement asmProvider")
	}
	client, err := p.Asm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement asm_external_incident_simulation
	_ = findings
	return findings, nil
}
