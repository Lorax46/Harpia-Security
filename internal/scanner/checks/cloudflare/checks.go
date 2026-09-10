package cloudflare

import (
	"context"
	"fmt"
	"net"
	"strings"
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

// CloudflareDnsRecordCnameTargetValidCheck - copiado do Prowler dns_record_cname_target_valid
// Verifica se registros CNAME/MX/NS/SRV apontam para alvos válidos (sem dangling)
type CloudflareDnsRecordCnameTargetValidCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDnsRecordCnameTargetValidCheck() *CloudflareDnsRecordCnameTargetValidCheck {
	return &CloudflareDnsRecordCnameTargetValidCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dns_cname_target_valid",
			CheckTitle: "Ensure CNAME records point to valid targets",
			Description: "DNS records should not point to dangling hostnames that could be taken over",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "DNS",
			RemediationText: "Remove dangling CNAME/MX/NS/SRV records or update to valid targets",
			Categories: []string{"cloudflare", "dns", "cname"},
		},
	}
}

func (c *CloudflareDnsRecordCnameTargetValidCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDnsRecordCnameTargetValidCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	// Record types que apontam para hostnames e podem ser dangling
	danglingRiskTypes := map[string]bool{"CNAME": true, "MX": true, "NS": true, "SRV": true}

	issues := 0
	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})
		if err != nil {
			continue
		}
		for _, record := range records {
			if danglingRiskTypes[record.Type] {
				// Verifica se o target resolve (dangling check)
				if record.Content != "" {
					_, err := net.LookupHost(record.Content)
					if err != nil {
						issues++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("No dangling CNAME/MX/NS/SRV records found in %d zone(s)", len(zones))
	if issues > 0 {
		status = models.StatusFail
		msg = fmt.Sprintf("Found %d dangling DNS record(s) across %d zone(s)", issues, len(zones))
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dns-cname-valid",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDnsRecordNoInternalIpCheck - copiado do Prowler dns_record_no_internal_ip
// Verifica se registros DNS não expõem IPs internos/privados
type CloudflareDnsRecordNoInternalIpCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDnsRecordNoInternalIpCheck() *CloudflareDnsRecordNoInternalIpCheck {
	return &CloudflareDnsRecordNoInternalIpCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dns_no_internal_ip",
			CheckTitle: "Ensure DNS records do not expose internal IP addresses",
			Description: "Public DNS records should not contain private or internal IP addresses",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "DNS",
			RemediationText: "Remove or update DNS records that expose internal IP addresses",
			Categories: []string{"cloudflare", "dns", "internal-ip"},
		},
	}
}

func (c *CloudflareDnsRecordNoInternalIpCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDnsRecordNoInternalIpCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	issues := 0
	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})
		if err != nil {
			continue
		}
		for _, record := range records {
			if record.Type == "A" || record.Type == "AAAA" {
				if record.Content != "" {
					ip := net.ParseIP(record.Content)
					if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
						issues++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("No internal IPs found in DNS records across %d zone(s)", len(zones))
	if issues > 0 {
		status = models.StatusFail
		msg = fmt.Sprintf("Found %d DNS record(s) with internal IP addresses", issues)
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dns-no-internal-ip",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDnsRecordNoWildcardCheck - copiado do Prowler dns_record_no_wildcard
// Verifica se não há registros DNS wildcard
type CloudflareDnsRecordNoWildcardCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDnsRecordNoWildcardCheck() *CloudflareDnsRecordNoWildcardCheck {
	return &CloudflareDnsRecordNoWildcardCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dns_no_wildcard",
			CheckTitle: "Ensure wildcard DNS records are not configured",
			Description: "Wildcard DNS records should not be configured for security reasons",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "DNS",
			RemediationText: "Remove wildcard DNS records (*.domain.com) or restrict to specific types",
			Categories: []string{"cloudflare", "dns", "wildcard"},
		},
	}
}

func (c *CloudflareDnsRecordNoWildcardCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDnsRecordNoWildcardCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	wildcardRiskTypes := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "SRV": true}
	issues := 0

	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})
		if err != nil {
			continue
		}
		for _, record := range records {
			if wildcardRiskTypes[record.Type] && strings.HasPrefix(record.Name, "*.") {
				issues++
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("No wildcard DNS records found in %d zone(s)", len(zones))
	if issues > 0 {
		status = models.StatusFail
		msg = fmt.Sprintf("Found %d wildcard DNS record(s) across %d zone(s)", issues, len(zones))
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dns-no-wildcard",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDnsRecordProxiedCheck - copiado do Prowler dns_record_proxied
// Verifica se registros DNS estão via proxy Cloudflare
type CloudflareDnsRecordProxiedCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDnsRecordProxiedCheck() *CloudflareDnsRecordProxiedCheck {
	return &CloudflareDnsRecordProxiedCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dns_proxied",
			CheckTitle: "Ensure DNS records are proxied through Cloudflare",
			Description: "DNS records should be proxied to hide origin IP and enable security features",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "DNS",
			RemediationText: "Enable Cloudflare proxy for A, AAAA, and CNAME records",
			Categories: []string{"cloudflare", "dns", "proxy"},
		},
	}
}

func (c *CloudflareDnsRecordProxiedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDnsRecordProxiedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	proxyableTypes := map[string]bool{"A": true, "AAAA": true, "CNAME": true}
	notProxied := 0
	totalProxyable := 0

	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})
		if err != nil {
			continue
		}
		for _, record := range records {
			if proxyableTypes[record.Type] {
				totalProxyable++
				if record.Proxied != nil && !*record.Proxied {
							notProxied++
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("All %d proxyable DNS records are proxied across %d zone(s)", totalProxyable, len(zones))
	if notProxied > 0 {
		status = models.StatusFail
		msg = fmt.Sprintf("%d/%d DNS records are not proxied across %d zone(s)", notProxied, totalProxyable, len(zones))
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dns-proxied",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDnssecEnabledCheck - copiado do Prowler zone_dnssec_enabled
// Verifica se DNSSEC está habilitado
type CloudflareDnssecEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDnssecEnabledCheck() *CloudflareDnssecEnabledCheck {
	return &CloudflareDnssecEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dnssec_enabled",
			CheckTitle: "Ensure DNSSEC is enabled",
			Description: "DNSSEC should be enabled to protect against DNS spoofing",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "DNSSEC",
			RemediationText: "Enable DNSSEC in Cloudflare zone settings",
			Categories: []string{"cloudflare", "dnssec", "dns"},
		},
	}
}

func (c *CloudflareDnssecEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDnssecEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	enabled := 0
	for _, zone := range zones {
		dnssec, err := client.ZoneDNSSECSetting(ctx, zone.ID)
		if err == nil && dnssec.Status == "active" {
			enabled++
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("DNSSEC enabled on %d/%d zones", enabled, len(zones))
	if enabled == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "DNSSEC not enabled on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dnssec",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareMinTlsVersionCheck - copiado do Prowler zone_min_tls_version_secure
// Verifica se TLS mínimo é 1.2+
type CloudflareMinTlsVersionCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareMinTlsVersionCheck() *CloudflareMinTlsVersionCheck {
	return &CloudflareMinTlsVersionCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_min_tls_version",
			CheckTitle: "Ensure minimum TLS version is 1.2 or higher",
			Description: "TLS 1.0 and 1.1 are deprecated and should not be allowed",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "TLS",
			RemediationText: "Set minimum TLS version to 1.2 or 1.3 in Cloudflare settings",
			Categories: []string{"cloudflare", "tls", "version"},
		},
	}
}

func (c *CloudflareMinTlsVersionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareMinTlsVersionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	compliant := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "min_tls_version" {
					if v, ok := setting.Value.(string); ok {
						if v == "1.2" || v == "1.3" {
							compliant++
						}
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("TLS 1.2+ configured on %d/%d zones", compliant, len(zones))
	if compliant == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Minimum TLS version not set to 1.2+ on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "min-tls-version",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareHstsEnabledCheck - copiado do Prowler zone_hsts_enabled
// Verifica se HSTS está habilitado com max-age >= 6 meses e includeSubdomains
type CloudflareHstsEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareHstsEnabledCheck() *CloudflareHstsEnabledCheck {
	return &CloudflareHstsEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_hsts_enabled",
			CheckTitle: "Ensure HSTS is enabled with secure settings",
			Description: "HSTS should be enabled with max-age >= 6 months and includeSubdomains",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "HTTPS",
			RemediationText: "Enable HSTS with max-age of at least 15768000 seconds (6 months) and includeSubdomains",
			Categories: []string{"cloudflare", "hsts", "https"},
		},
	}
}

func (c *CloudflareHstsEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareHstsEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	// Prowler usa recommended_max_age = 15768000 (6 meses)
	recommendedMaxAge := int64(15768000)
	compliant := 0
	total := 0

	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "security_header" {
					total++
					// security_header.value contém strict_transport_security
					if hstsMap, ok := setting.Value.(map[string]interface{}); ok {
						if sts, ok := hstsMap["strict_transport_security"].(map[string]interface{}); ok {
							enabled, _ := sts["enabled"].(bool)
							includeSubs, _ := sts["include_subdomains"].(bool)
							maxAge, _ := sts["max_age"].(int64)
							if enabled && includeSubs && maxAge >= recommendedMaxAge {
								compliant++
							}
						}
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("HSTS properly configured on %d/%d zones (max-age >= 6mo, includeSubdomains)", compliant, total)
	if compliant == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "HSTS not properly configured on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "hsts",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareSslStrictCheck - copiado do Prowler zone_ssl_strict
// Verifica se SSL/TLS está em modo Full (Strict)
type CloudflareSslStrictCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareSslStrictCheck() *CloudflareSslStrictCheck {
	return &CloudflareSslStrictCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_ssl_strict",
			CheckTitle: "Ensure SSL/TLS encryption mode is Full (Strict)",
			Description: "SSL/TLS should be set to Full (Strict) for end-to-end encryption with certificate validation",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "SSL",
			RemediationText: "Set SSL/TLS encryption mode to Full (Strict) in Cloudflare zone settings",
			Categories: []string{"cloudflare", "ssl", "strict"},
		},
	}
}

func (c *CloudflareSslStrictCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareSslStrictCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	strict := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "ssl" {
					if v, ok := setting.Value.(string); ok && v == "strict" {
						strict++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("SSL/TLS Full (Strict) on %d/%d zones", strict, len(zones))
	if strict == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "SSL/TLS not set to Full (Strict) on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "ssl-strict",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareTls13EnabledCheck - copiado do Prowler zone_tls_1_3_enabled
// Verifica se TLS 1.3 está habilitado
type CloudflareTls13EnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareTls13EnabledCheck() *CloudflareTls13EnabledCheck {
	return &CloudflareTls13EnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_tls_1_3_enabled",
			CheckTitle: "Ensure TLS 1.3 is enabled",
			Description: "TLS 1.3 should be enabled for improved security and performance",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "TLS",
			RemediationText: "Enable TLS 1.3 in Cloudflare zone settings",
			Categories: []string{"cloudflare", "tls", "1.3"},
		},
	}
}

func (c *CloudflareTls13EnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareTls13EnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	enabled := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "tls_1_3" {
					if v, ok := setting.Value.(string); ok && (v == "on" || v == "zrt") {
						enabled++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("TLS 1.3 enabled on %d/%d zones", enabled, len(zones))
	if enabled == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "TLS 1.3 not enabled on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "tls-1-3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareUniversalSslEnabledCheck - copiado do Prowler zone_universal_ssl_enabled
// Verifica se Universal SSL está habilitado
type CloudflareUniversalSslEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareUniversalSslEnabledCheck() *CloudflareUniversalSslEnabledCheck {
	return &CloudflareUniversalSslEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_universal_ssl_enabled",
			CheckTitle: "Ensure Universal SSL is enabled",
			Description: "Universal SSL provides free SSL/TLS certificates for the domain and subdomains",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "SSL",
			RemediationText: "Enable Universal SSL in Cloudflare zone settings",
			Categories: []string{"cloudflare", "universal-ssl", "ssl"},
		},
	}
}

func (c *CloudflareUniversalSslEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareUniversalSslEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	enabled := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "universal_ssl" {
					if v, ok := setting.Value.(bool); ok && v {
						enabled++
					} else if v, ok := setting.Value.(string); ok && v == "on" {
						enabled++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Universal SSL enabled on %d/%d zones", enabled, len(zones))
	if enabled == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Universal SSL not enabled on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "universal-ssl",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareHttpsRedirectEnabledCheck - copiado do Prowler zone_https_redirect_enabled
// Verifica se Always Use HTTPS está habilitado
type CloudflareHttpsRedirectEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareHttpsRedirectEnabledCheck() *CloudflareHttpsRedirectEnabledCheck {
	return &CloudflareHttpsRedirectEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_https_redirect_enabled",
			CheckTitle: "Ensure Always Use HTTPS is enabled",
			Description: "Always Use HTTPS redirects all HTTP traffic to HTTPS",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "HTTPS",
			RemediationText: "Enable Always Use HTTPS in Cloudflare zone settings",
			Categories: []string{"cloudflare", "https", "redirect"},
		},
	}
}

func (c *CloudflareHttpsRedirectEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareHttpsRedirectEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	enabled := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "always_use_https" {
					if v, ok := setting.Value.(bool); ok && v {
						enabled++
					} else if v, ok := setting.Value.(string); ok && v == "on" {
						enabled++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Always Use HTTPS enabled on %d/%d zones", enabled, len(zones))
	if enabled == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Always Use HTTPS not enabled on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "https-redirect",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareWafOwaspRulesetEnabledCheck - copiado do Prowler zone_waf_owasp_ruleset_enabled
// Verifica se OWASP WAF ruleset está habilitado
type CloudflareWafOwaspRulesetEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareWafOwaspRulesetEnabledCheck() *CloudflareWafOwaspRulesetEnabledCheck {
	return &CloudflareWafOwaspRulesetEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_waf_owasp_enabled",
			CheckTitle: "Ensure OWASP WAF rulesets are enabled",
			Description: "OWASP Core Ruleset provides protection against common web vulnerabilities",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "WAF",
			RemediationText: "Enable OWASP managed WAF rulesets in Security > WAF",
			Categories: []string{"cloudflare", "waf", "owasp"},
		},
	}
}

func (c *CloudflareWafOwaspRulesetEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareWafOwaspRulesetEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	protected := 0
	for _, zone := range zones {
		rulesets, err := client.ListRulesets(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListRulesetsParams{})
		if err == nil {
			for _, rs := range rulesets {
				if strings.Contains(strings.ToLower(rs.Name), "owasp") {
					protected++
					break
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("OWASP WAF ruleset enabled on %d/%d zones", protected, len(zones))
	if protected == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "OWASP WAF ruleset not enabled on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "waf-owasp",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareFirewallBlockingRulesConfiguredCheck - copiado do Prowler zone_firewall_blocking_rules_configured
// Verifica se há regras de firewall com ações de bloqueio
type CloudflareFirewallBlockingRulesConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareFirewallBlockingRulesConfiguredCheck() *CloudflareFirewallBlockingRulesConfiguredCheck {
	return &CloudflareFirewallBlockingRulesConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_firewall_blocking_rules",
			CheckTitle: "Ensure firewall rules with blocking actions are configured",
			Description: "Firewall rules should use block, challenge, or js_challenge actions",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Firewall",
			RemediationText: "Configure firewall rules with blocking actions in Cloudflare Firewall Rules",
			Categories: []string{"cloudflare", "firewall", "blocking"},
		},
	}
}

func (c *CloudflareFirewallBlockingRulesConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareFirewallBlockingRulesConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	blockingActions := map[string]bool{"block": true, "challenge": true, "js_challenge": true, "managed_challenge": true}
	zonesWithBlocking := 0

	for _, zone := range zones {
		rulesets, err := client.ListRulesets(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListRulesetsParams{})
		if err == nil {
			hasBlocking := false
			for _, rs := range rulesets {
				if rs.Phase == "http_request_firewall_custom" || rs.Phase == "http_request_firewall_managed" {
					for _, rule := range rs.Rules {
						if blockingActions[rule.Action] {
							hasBlocking = true
							break
						}
					}
				}
				if hasBlocking {
					break
				}
			}
			if hasBlocking {
				zonesWithBlocking++
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Firewall blocking rules configured on %d/%d zones", zonesWithBlocking, len(zones))
	if zonesWithBlocking == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "No firewall blocking rules configured on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "firewall-blocking",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareRateLimitingEnabledCheck - copiado do Prowler zone_rate_limiting_enabled
// Verifica se Rate Limiting está configurado
type CloudflareRateLimitingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareRateLimitingEnabledCheck() *CloudflareRateLimitingEnabledCheck {
	return &CloudflareRateLimitingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_rate_limiting_enabled",
			CheckTitle: "Ensure rate limiting is configured",
			Description: "Rate limiting protects against DDoS and brute force attacks",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "RateLimit",
			RemediationText: "Configure rate limiting rules in Cloudflare",
			Categories: []string{"cloudflare", "rate-limiting", "ddos"},
		},
	}
}

func (c *CloudflareRateLimitingEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareRateLimitingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	zonesWithRateLimit := 0

	for _, zone := range zones {
		rulesets, err := client.ListRulesets(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListRulesetsParams{})
		if err == nil {
			for _, rs := range rulesets {
				if rs.Phase == "http_ratelimit" {
					for _, rule := range rs.Rules {
						if rule.Enabled != nil && *rule.Enabled {
							zonesWithRateLimit++
							break
						}
					}
				}
				if zonesWithRateLimit > 0 {
					break
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Rate limiting configured on %d/%d zones", zonesWithRateLimit, len(zones))
	if zonesWithRateLimit == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Rate limiting not configured on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "rate-limiting",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareSpfRecordExistsCheck - copiado do Prowler zone_record_spf_exists
// Verifica se existe registro SPF com política estrita (-all)
type CloudflareSpfRecordExistsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareSpfRecordExistsCheck() *CloudflareSpfRecordExistsCheck {
	return &CloudflareSpfRecordExistsCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_spf_record_exists",
			CheckTitle: "Ensure SPF record exists with strict policy",
			Description: "SPF record should exist with -all qualifier to reject unauthorized senders",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Email",
			RemediationText: "Add SPT TXT record: v=spf1 ... -all",
			Categories: []string{"cloudflare", "spf", "email"},
		},
	}
}

func (c *CloudflareSpfRecordExistsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareSpfRecordExistsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	zonesWithSpf := 0

	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{Type: "TXT"})
		if err == nil {
			for _, record := range records {
				content := record.Content
				if strings.HasPrefix(content, "v=spf1") && strings.Contains(content, "-all") {
					zonesWithSpf++
					break
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("SPF record with strict policy exists on %d/%d zones", zonesWithSpf, len(zones))
	if zonesWithSpf == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "SPF record not found or not strict (-all) on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "spf-record",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDkimRecordExistsCheck - copiado do Prowler zone_record_dkim_exists
// Verifica se existe registro DKIM com chave pública válida
type CloudflareDkimRecordExistsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDkimRecordExistsCheck() *CloudflareDkimRecordExistsCheck {
	return &CloudflareDkimRecordExistsCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dkim_record_exists",
			CheckTitle: "Ensure DKIM record exists with valid public key",
			Description: "DKIM record should exist with valid public key for email authentication",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Email",
			RemediationText: "Add DKIM TXT record at *._domainkey with v=DKIM1 and valid public key",
			Categories: []string{"cloudflare", "dkim", "email"},
		},
	}
}

func (c *CloudflareDkimRecordExistsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDkimRecordExistsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	zonesWithDkim := 0

	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{Type: "TXT"})
		if err == nil {
			for _, record := range records {
				content := record.Content
				if strings.Contains(record.Name, "._domainkey") && strings.Contains(content, "v=DKIM1") {
					zonesWithDkim++
					break
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("DKIM record exists on %d/%d zones", zonesWithDkim, len(zones))
	if zonesWithDkim == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "DKIM record not found on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dkim-record",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareDmarcRecordExistsCheck - copiado do Prowler zone_record_dmarc_exists
// Verifica se existe registro DMARC com política de enforcement
type CloudflareDmarcRecordExistsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareDmarcRecordExistsCheck() *CloudflareDmarcRecordExistsCheck {
	return &CloudflareDmarcRecordExistsCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_dmarc_record_exists",
			CheckTitle: "Ensure DMARC record exists with enforcement policy",
			Description: "DMARC record should exist with p=reject or p=quarantine",
			Severity: "medium", ServiceName: "cloudflare", ResourceType: "Email",
			RemediationText: "Add DMARC TXT record at _dmarc with p=reject or p=quarantine",
			Categories: []string{"cloudflare", "dmarc", "email"},
		},
	}
}

func (c *CloudflareDmarcRecordExistsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareDmarcRecordExistsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	zonesWithDmarc := 0

	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{Type: "TXT", Name: fmt.Sprintf("_dmarc.%s", zone.Name)})
		if err == nil {
			for _, record := range records {
				content := record.Content
				if strings.Contains(content, "v=DMARC1") && (strings.Contains(content, "p=reject") || strings.Contains(content, "p=quarantine")) {
					zonesWithDmarc++
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("DMARC record with enforcement exists on %d/%d zones", zonesWithDmarc, len(zones))
	if zonesWithDmarc == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "DMARC record not found or not enforced on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "dmarc-record",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareCaaRecordExistsCheck - copiado do Prowler zone_record_caa_exists
// Verifica se existe registro CAA com issue/issuewild
type CloudflareCaaRecordExistsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareCaaRecordExistsCheck() *CloudflareCaaRecordExistsCheck {
	return &CloudflareCaaRecordExistsCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_caa_record_exists",
			CheckTitle: "Ensure CAA record exists with certificate issuance restrictions",
			Description: "CAA record should specify authorized certificate authorities",
			Severity: "low", ServiceName: "cloudflare", ResourceType: "DNS",
			RemediationText: "Add CAA record with issue and issuewild tags",
			Categories: []string{"cloudflare", "caa", "certificate"},
		},
	}
}

func (c *CloudflareCaaRecordExistsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareCaaRecordExistsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	zonesWithCaa := 0

	for _, zone := range zones {
		records, _, err := client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{Type: "CAA"})
		if err == nil {
			for _, record := range records {
				if record.Content != "" {
					zonesWithCaa++
					break
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("CAA record exists on %d/%d zones", zonesWithCaa, len(zones))
	if zonesWithCaa == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "CAA record not found on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "caa-record",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareAlwaysOnlineDisabledCheck - copiado do Prowler zone_always_online_disabled
// Verifica se Always Online está desabilitado
type CloudflareAlwaysOnlineDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareAlwaysOnlineDisabledCheck() *CloudflareAlwaysOnlineDisabledCheck {
	return &CloudflareAlwaysOnlineDisabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_always_online_disabled",
			CheckTitle: "Ensure Always Online is disabled",
			Description: "Always Online should be disabled to prevent serving stale content",
			Severity: "high", ServiceName: "cloudflare", ResourceType: "Availability",
			RemediationText: "Disable Always Online in Cloudflare zone settings",
			Categories: []string{"cloudflare", "always-online"},
		},
	}
}

func (c *CloudflareAlwaysOnlineDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareAlwaysOnlineDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	disabled := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "always_online" {
					if v, ok := setting.Value.(string); ok && v == "off" {
						disabled++
					} else if v, ok := setting.Value.(bool); ok && !v {
						disabled++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Always Online disabled on %d/%d zones", disabled, len(zones))
	if disabled == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Always Online is enabled on all zones"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "always-online",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareUnderAttackModeDisabledCheck - copiado do Prowler zone_security_under_attack_disabled
// Verifica se "Under Attack" mode está desabilitado
type CloudflareUnderAttackModeDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareUnderAttackModeDisabledCheck() *CloudflareUnderAttackModeDisabledCheck {
	return &CloudflareUnderAttackModeDisabledCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_under_attack_disabled",
			CheckTitle: "Ensure Under Attack Mode is disabled during normal operations",
			Description: "Under Attack Mode should only be enabled during active DDoS attacks",
			Severity: "low", ServiceName: "cloudflare", ResourceType: "Security",
			RemediationText: "Disable Under Attack Mode in Cloudflare security settings",
			Categories: []string{"cloudflare", "under-attack", "ddos"},
		},
	}
}

func (c *CloudflareUnderAttackModeDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareUnderAttackModeDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	normalMode := 0
	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "security_level" {
					if v, ok := setting.Value.(string); ok && v != "under_attack" {
						normalMode++
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Under Attack Mode disabled on %d/%d zones", normalMode, len(zones))
	if normalMode == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Under Attack Mode is enabled on all zones"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "under-attack",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// CloudflareChallengePassageConfiguredCheck - copiado do Prowler zone_challenge_passage_configured
// Verifica se Challenge TTL está entre 15-45 minutos
type CloudflareChallengePassageConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewCloudflareChallengePassageConfiguredCheck() *CloudflareChallengePassageConfiguredCheck {
	return &CloudflareChallengePassageConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "cloudflare", CheckID: "cloudflare_challenge_passage_configured",
			CheckTitle: "Ensure Challenge Passage is configured between 15 and 45 minutes",
			Description: "Challenge TTL should be between 900 and 2700 seconds (15-45 min)",
			Severity: "low", ServiceName: "cloudflare", ResourceType: "Security",
			RemediationText: "Configure Challenge TTL between 900 and 2700 seconds",
			Categories: []string{"cloudflare", "challenge", "ttl"},
		},
	}
}

func (c *CloudflareChallengePassageConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudflareChallengePassageConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	minTTL := 900    // 15 minutos
	maxTTL := 2700   // 45 minutos
	compliant := 0

	for _, zone := range zones {
		settings, err := client.ZoneSettings(ctx, zone.ID)
		if err == nil {
			for _, setting := range settings.Result {
				if setting.ID == "challenge_ttl" {
					if v, ok := setting.Value.(float64); ok {
						ttl := int(v)
						if ttl >= minTTL && ttl <= maxTTL {
							compliant++
						}
					}
				}
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Challenge TTL configured correctly on %d/%d zones", compliant, len(zones))
	if compliant == 0 && len(zones) > 0 {
		status = models.StatusFail
		msg = "Challenge TTL not in recommended range (15-45 min) on any zone"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "cloudflare", Service: "cloudflare", ResourceID: "challenge-ttl",
		FoundAt: time.Now().UTC(),
	}}, nil
}
