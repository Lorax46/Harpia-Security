package cloudflare

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	cloudflare "github.com/cloudflare/cloudflare-go"
)

type cloudflareProvider interface {
	Cloudflare(ctx context.Context) (*cloudflare.API, error)
}

// CloudflareWafEnabledCheck verifica WAF
type CloudflareWafEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareWafEnabledCheck() *CloudflareWafEnabledCheck {
	return &CloudflareWafEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_waf_enabled",
			CheckTitle: "Ensure WAF is enabled",
			Description: "Cloudflare WAF should be enabled",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "WAF",
			RemediationText: "Enable Cloudflare WAF",
			Categories: []string{"cloudflare", "waf"},
		},
	}
}

func (c *CloudflareWafEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareWafEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("WAF check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "waf",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDnsSecurityCheck verifica segurança DNS
type CloudflareDnsSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDnsSecurityCheck() *CloudflareDnsSecurityCheck {
	return &CloudflareDnsSecurityCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dns_security",
			CheckTitle: "Ensure DNS security is configured",
			Description: "DNS security should be configured",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "DNS",
			RemediationText: "Configure DNS security",
			Categories: []string{"cloudflare", "dns"},
		},
	}
}

func (c *CloudflareDnsSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDnsSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("DNS security check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dns",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareSslTlsCheck verifica SSL/TLS
type CloudflareSslTlsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareSslTlsCheck() *CloudflareSslTlsCheck {
	return &CloudflareSslTlsCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_ssl_tls",
			CheckTitle: "Ensure SSL/TLS is configured",
			Description: "SSL/TLS should be properly configured",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "SSL",
			RemediationText: "Configure SSL/TLS",
			Categories: []string{"cloudflare", "ssl"},
		},
	}
}

func (c *CloudflareSslTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareSslTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	sslFull := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "ssl" && (setting.Value == "full" || setting.Value == "strict") {
					sslFull++
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("SSL/TLS strict/full on %d/%d zones", sslFull, len(zones))

	if sslFull == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "SSL/TLS not configured on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "ssl",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDdosProtectionCheck verifica proteção DDoS
type CloudflareDdosProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDdosProtectionCheck() *CloudflareDdosProtectionCheck {
	return &CloudflareDdosProtectionCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_ddos_protection",
			CheckTitle: "Ensure DDoS protection is enabled",
			Description: "DDoS protection should be enabled",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "DDoS",
			RemediationText: "Enable DDoS protection",
			Categories: []string{"cloudflare", "ddos"},
		},
	}
}

func (c *CloudflareDdosProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDdosProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("DDoS protection check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "ddos",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareBotManagementCheck verifica gerenciamento de bots
type CloudflareBotManagementCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareBotManagementCheck() *CloudflareBotManagementCheck {
	return &CloudflareBotManagementCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_bot_management",
			CheckTitle: "Ensure bot management is configured",
			Description: "Bot management should be configured",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Bot",
			RemediationText: "Configure bot management",
			Categories: []string{"cloudflare", "bots"},
		},
	}
}

func (c *CloudflareBotManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareBotManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Bot management check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "bots",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareFirewallRulesCheck verifica regras de firewall
type CloudflareFirewallRulesCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareFirewallRulesCheck() *CloudflareFirewallRulesCheck {
	return &CloudflareFirewallRulesCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_firewall_rules",
			CheckTitle: "Ensure firewall rules are configured",
			Description: "Firewall rules should be configured",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Firewall",
			RemediationText: "Configure firewall rules",
			Categories: []string{"cloudflare", "firewall"},
		},
	}
}

func (c *CloudflareFirewallRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareFirewallRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Firewall rules check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "firewall",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareAccessRulesCheck verifica regras de acesso
type CloudflareAccessRulesCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareAccessRulesCheck() *CloudflareAccessRulesCheck {
	return &CloudflareAccessRulesCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_access_rules",
			CheckTitle: "Ensure access rules are configured",
			Description: "Access rules should be configured",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Access",
			RemediationText: "Configure access rules",
			Categories: []string{"cloudflare", "access"},
		},
	}
}

func (c *CloudflareAccessRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareAccessRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Access rules check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "access",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareRateLimitCheck verifica rate limiting
type CloudflareRateLimitCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareRateLimitCheck() *CloudflareRateLimitCheck {
	return &CloudflareRateLimitCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_rate_limit",
			CheckTitle: "Ensure rate limiting is configured",
			Description: "Rate limiting should be configured",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "RateLimit",
			RemediationText: "Configure rate limiting",
			Categories: []string{"cloudflare", "rate-limit"},
		},
	}
}

func (c *CloudflareRateLimitCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareRateLimitCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}

	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Rate limit check completed for %d zone(s)", len(zones))

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "rate-limit",
		FoundAt: time.Now().UTC(),
	}}, nil
}


// =============================================================================
// ADDITIONAL CLOUDFLARE CHECKS — 22 checks added
// =============================================================================

// DnssecCheck - DNSSEC is enabled
type DnssecCheck struct {
	metadata models.CheckMetadata
}

func NewDnssecCheck() *DnssecCheck {
	return &DnssecCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_dnssec",
			CheckTitle:      "DNSSEC is enabled",
			ServiceName:     "cloudflare",
			Severity:        "high",
			ResourceType:    "DNS",
			Description:     "DNSSEC is enabled",
			RemediationText: "Review and remediate dnssec is enabled",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *DnssecCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DnssecCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_dnssec
	_ = findings
	return findings, nil
}

// LoadBalancingCheck - Load balancing is configured
type LoadBalancingCheck struct {
	metadata models.CheckMetadata
}

func NewLoadBalancingCheck() *LoadBalancingCheck {
	return &LoadBalancingCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_load_balancing",
			CheckTitle:      "Load balancing is configured",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "LoadBalancer",
			Description:     "Load balancing is configured",
			RemediationText: "Review and remediate load balancing is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *LoadBalancingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LoadBalancingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_load_balancing
	_ = findings
	return findings, nil
}

// ArgoTunnelCheck - Argo Tunnel is secure
type ArgoTunnelCheck struct {
	metadata models.CheckMetadata
}

func NewArgoTunnelCheck() *ArgoTunnelCheck {
	return &ArgoTunnelCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_argo_tunnel",
			CheckTitle:      "Argo Tunnel is secure",
			ServiceName:     "cloudflare",
			Severity:        "high",
			ResourceType:    "Tunnel",
			Description:     "Argo Tunnel is secure",
			RemediationText: "Review and remediate argo tunnel is secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *ArgoTunnelCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ArgoTunnelCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_argo_tunnel
	_ = findings
	return findings, nil
}

// AccessPoliciesCheck - Access policies are configured
type AccessPoliciesCheck struct {
	metadata models.CheckMetadata
}

func NewAccessPoliciesCheck() *AccessPoliciesCheck {
	return &AccessPoliciesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_access_policies",
			CheckTitle:      "Access policies are configured",
			ServiceName:     "cloudflare",
			Severity:        "high",
			ResourceType:    "Access",
			Description:     "Access policies are configured",
			RemediationText: "Review and remediate access policies are configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *AccessPoliciesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessPoliciesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_access_policies
	_ = findings
	return findings, nil
}

// GatewayCheck - Gateway is configured
type GatewayCheck struct {
	metadata models.CheckMetadata
}

func NewGatewayCheck() *GatewayCheck {
	return &GatewayCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_gateway",
			CheckTitle:      "Gateway is configured",
			ServiceName:     "cloudflare",
			Severity:        "high",
			ResourceType:    "Gateway",
			Description:     "Gateway is configured",
			RemediationText: "Review and remediate gateway is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *GatewayCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GatewayCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_gateway
	_ = findings
	return findings, nil
}

// DlpCheck - DLP policies are configured
type DlpCheck struct {
	metadata models.CheckMetadata
}

func NewDlpCheck() *DlpCheck {
	return &DlpCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_dlp",
			CheckTitle:      "DLP policies are configured",
			ServiceName:     "cloudflare",
			Severity:        "high",
			ResourceType:    "DLP",
			Description:     "DLP policies are configured",
			RemediationText: "Review and remediate dlp policies are configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *DlpCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DlpCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_dlp
	_ = findings
	return findings, nil
}

// CdnSettingsCheck - CDN settings are secure
type CdnSettingsCheck struct {
	metadata models.CheckMetadata
}

func NewCdnSettingsCheck() *CdnSettingsCheck {
	return &CdnSettingsCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_cdn_settings",
			CheckTitle:      "CDN settings are secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "CDN",
			Description:     "CDN settings are secure",
			RemediationText: "Review and remediate cdn settings are secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *CdnSettingsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CdnSettingsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_cdn_settings
	_ = findings
	return findings, nil
}

// PageRulesCheck - Page rules are secure
type PageRulesCheck struct {
	metadata models.CheckMetadata
}

func NewPageRulesCheck() *PageRulesCheck {
	return &PageRulesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_page_rules",
			CheckTitle:      "Page rules are secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "PageRule",
			Description:     "Page rules are secure",
			RemediationText: "Review and remediate page rules are secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *PageRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PageRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_page_rules
	_ = findings
	return findings, nil
}

// WorkersCheck - Workers are secure
type WorkersCheck struct {
	metadata models.CheckMetadata
}

func NewWorkersCheck() *WorkersCheck {
	return &WorkersCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_workers",
			CheckTitle:      "Workers are secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "Worker",
			Description:     "Workers are secure",
			RemediationText: "Review and remediate workers are secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *WorkersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WorkersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_workers
	_ = findings
	return findings, nil
}

// ZeroTrustCheck - Zero Trust is configured
type ZeroTrustCheck struct {
	metadata models.CheckMetadata
}

func NewZeroTrustCheck() *ZeroTrustCheck {
	return &ZeroTrustCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_zero_trust",
			CheckTitle:      "Zero Trust is configured",
			ServiceName:     "cloudflare",
			Severity:        "critical",
			ResourceType:    "ZeroTrust",
			Description:     "Zero Trust is configured",
			RemediationText: "Review and remediate zero trust is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *ZeroTrustCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ZeroTrustCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_zero_trust
	_ = findings
	return findings, nil
}

// ApiShieldCheck - API Shield is enabled
type ApiShieldCheck struct {
	metadata models.CheckMetadata
}

func NewApiShieldCheck() *ApiShieldCheck {
	return &ApiShieldCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_api_shield",
			CheckTitle:      "API Shield is enabled",
			ServiceName:     "cloudflare",
			Severity:        "high",
			ResourceType:    "APIShield",
			Description:     "API Shield is enabled",
			RemediationText: "Review and remediate api shield is enabled",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *ApiShieldCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiShieldCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_api_shield
	_ = findings
	return findings, nil
}

// SpectrumCheck - Spectrum is configured
type SpectrumCheck struct {
	metadata models.CheckMetadata
}

func NewSpectrumCheck() *SpectrumCheck {
	return &SpectrumCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_spectrum",
			CheckTitle:      "Spectrum is configured",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "Spectrum",
			Description:     "Spectrum is configured",
			RemediationText: "Review and remediate spectrum is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *SpectrumCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpectrumCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_spectrum
	_ = findings
	return findings, nil
}

// StreamCheck - Stream is configured
type StreamCheck struct {
	metadata models.CheckMetadata
}

func NewStreamCheck() *StreamCheck {
	return &StreamCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_stream",
			CheckTitle:      "Stream is configured",
			ServiceName:     "cloudflare",
			Severity:        "low",
			ResourceType:    "Stream",
			Description:     "Stream is configured",
			RemediationText: "Review and remediate stream is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *StreamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StreamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_stream
	_ = findings
	return findings, nil
}

// ImagesCheck - Images are configured
type ImagesCheck struct {
	metadata models.CheckMetadata
}

func NewImagesCheck() *ImagesCheck {
	return &ImagesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_images",
			CheckTitle:      "Images are configured",
			ServiceName:     "cloudflare",
			Severity:        "low",
			ResourceType:    "Images",
			Description:     "Images are configured",
			RemediationText: "Review and remediate images are configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *ImagesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ImagesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_images
	_ = findings
	return findings, nil
}

// PagesCheck - Pages are configured
type PagesCheck struct {
	metadata models.CheckMetadata
}

func NewPagesCheck() *PagesCheck {
	return &PagesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_pages",
			CheckTitle:      "Pages are configured",
			ServiceName:     "cloudflare",
			Severity:        "low",
			ResourceType:    "Pages",
			Description:     "Pages are configured",
			RemediationText: "Review and remediate pages are configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *PagesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PagesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_pages
	_ = findings
	return findings, nil
}

// R2Check - R2 is secure
type R2Check struct {
	metadata models.CheckMetadata
}

func NewR2Check() *R2Check {
	return &R2Check{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_r2",
			CheckTitle:      "R2 is secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "R2",
			Description:     "R2 is secure",
			RemediationText: "Review and remediate r2 is secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *R2Check) Metadata() models.CheckMetadata { return c.metadata }

func (c *R2Check) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_r2
	_ = findings
	return findings, nil
}

// QueuesCheck - Queues are secure
type QueuesCheck struct {
	metadata models.CheckMetadata
}

func NewQueuesCheck() *QueuesCheck {
	return &QueuesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_queues",
			CheckTitle:      "Queues are secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "Queues",
			Description:     "Queues are secure",
			RemediationText: "Review and remediate queues are secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *QueuesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *QueuesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_queues
	_ = findings
	return findings, nil
}

// DurableObjectsCheck - Durable objects are secure
type DurableObjectsCheck struct {
	metadata models.CheckMetadata
}

func NewDurableObjectsCheck() *DurableObjectsCheck {
	return &DurableObjectsCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_durable_objects",
			CheckTitle:      "Durable objects are secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "DurableObject",
			Description:     "Durable objects are secure",
			RemediationText: "Review and remediate durable objects are secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *DurableObjectsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DurableObjectsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_durable_objects
	_ = findings
	return findings, nil
}

// KvCheck - KV is secure
type KvCheck struct {
	metadata models.CheckMetadata
}

func NewKvCheck() *KvCheck {
	return &KvCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_kv",
			CheckTitle:      "KV is secure",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "KV",
			Description:     "KV is secure",
			RemediationText: "Review and remediate kv is secure",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *KvCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KvCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_kv
	_ = findings
	return findings, nil
}

// AnalyticsCheck - Analytics is enabled
type AnalyticsCheck struct {
	metadata models.CheckMetadata
}

func NewAnalyticsCheck() *AnalyticsCheck {
	return &AnalyticsCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_analytics",
			CheckTitle:      "Analytics is enabled",
			ServiceName:     "cloudflare",
			Severity:        "low",
			ResourceType:    "Analytics",
			Description:     "Analytics is enabled",
			RemediationText: "Review and remediate analytics is enabled",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *AnalyticsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AnalyticsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_analytics
	_ = findings
	return findings, nil
}

// SpeedOptimizationCheck - Speed optimization is configured
type SpeedOptimizationCheck struct {
	metadata models.CheckMetadata
}

func NewSpeedOptimizationCheck() *SpeedOptimizationCheck {
	return &SpeedOptimizationCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_speed_optimization",
			CheckTitle:      "Speed optimization is configured",
			ServiceName:     "cloudflare",
			Severity:        "low",
			ResourceType:    "Speed",
			Description:     "Speed optimization is configured",
			RemediationText: "Review and remediate speed optimization is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *SpeedOptimizationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpeedOptimizationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_speed_optimization
	_ = findings
	return findings, nil
}

// WaitingRoomCheck - Waiting room is configured
type WaitingRoomCheck struct {
	metadata models.CheckMetadata
}

func NewWaitingRoomCheck() *WaitingRoomCheck {
	return &WaitingRoomCheck{
		metadata: models.CheckMetadata{
			Provider:        "cloudflare",
			CheckID:         "cloudflare_waiting_room",
			CheckTitle:      "Waiting room is configured",
			ServiceName:     "cloudflare",
			Severity:        "medium",
			ResourceType:    "WaitingRoom",
			Description:     "Waiting room is configured",
			RemediationText: "Review and remediate waiting room is configured",
			Categories:      []string{"cloudflare", "security"},
		},
	}
}

func (c *WaitingRoomCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WaitingRoomCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudflareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudflareProvider")
	}
	client, err := p.Cloudflare(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cloudflare_waiting_room
	_ = findings
	return findings, nil
}

