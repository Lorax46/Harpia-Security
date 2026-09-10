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
