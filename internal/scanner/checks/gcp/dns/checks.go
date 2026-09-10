package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/dns/v1"
)

type dnsProvider interface {
	DNS(ctx context.Context) (*dns.Service, error)
	ProjectID() string
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. DNSZonePublicAccessCheck — verifica se a zona DNS é publicamente acessível
// ─────────────────────────────────────────────────────────────────────────────

type DNSZonePublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewDNSZonePublicAccessCheck() *DNSZonePublicAccessCheck {
	return &DNSZonePublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:      "gcp",
			CheckID:       "dns_zone_public_access",
			CheckTitle:    "DNS zone should not be publicly accessible",
			ServiceName:   "dns",
			Severity:      "high",
			ResourceType:  "ManagedZone",
			Description:   "DNS zones should not be publicly accessible",
			Risk:          "Public DNS zones expose records to the internet",
			RemediationText: "Make DNS zone private",
			RemediationURL:  "https://cloud.google.com/dns/docs/zones",
			Categories:    []string{"dns", "networking"},
		},
	}
}

func (c *DNSZonePublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DNSZonePublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dnsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dnsProvider")
	}
	dnsService, err := p.DNS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dnsService.ManagedZones.List(p.ProjectID())
	err = req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			isPublic := zone.Visibility == "public"
			status := models.StatusPass
			ext := "DNS zone is private"
			if isPublic {
				status = models.StatusFail
				ext = "DNS zone is public"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dns",
				ResourceID:     zone.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. DNSZoneDnssecCheck — verifica se DNSSEC está habilitado na zona
// ─────────────────────────────────────────────────────────────────────────────

type DNSZoneDnssecCheck struct {
	metadata models.CheckMetadata
}

func NewDNSZoneDnssecCheck() *DNSZoneDnssecCheck {
	return &DNSZoneDnssecCheck{
		metadata: models.CheckMetadata{
			Provider:      "gcp",
			CheckID:       "dns_zone_dnssec_enabled",
			CheckTitle:    "DNS zone should have DNSSEC enabled",
			ServiceName:   "dns",
			Severity:      "medium",
			ResourceType:  "ManagedZone",
			Description:   "DNSSEC adds cryptographic authentication to DNS records",
			Risk:          "Without DNSSEC, DNS responses can be spoofed or poisoned",
			RemediationText: "Enable DNSSEC on the DNS zone",
			RemediationURL:  "https://cloud.google.com/dns/docs/dnssec",
			Categories:    []string{"dns", "cryptography"},
		},
	}
}

func (c *DNSZoneDnssecCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DNSZoneDnssecCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dnsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dnsProvider")
	}
	dnsService, err := p.DNS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dnsService.ManagedZones.List(p.ProjectID())
	err = req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			// Só faz sentido verificar DNSSEC em zonas públicas
			if zone.Visibility != "public" {
				continue
			}
			dnssecEnabled := zone.DnssecConfig != nil && zone.DnssecConfig.State == "on"
			status := models.StatusFail
			ext := "DNSSEC is not enabled on the DNS zone"
			if dnssecEnabled {
				status = models.StatusPass
				ext = "DNSSEC is enabled on the DNS zone"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dns",
				ResourceID:     zone.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DNSZoneDsRecordCheck — verifica se a zona pública tem DS record configurado
// ─────────────────────────────────────────────────────────────────────────────

type DNSZoneDsRecordCheck struct {
	metadata models.CheckMetadata
}

func NewDNSZoneDsRecordCheck() *DNSZoneDsRecordCheck {
	return &DNSZoneDsRecordCheck{
		metadata: models.CheckMetadata{
			Provider:      "gcp",
			CheckID:       "dns_zone_ds_record",
			CheckTitle:    "DNS zone should have DS record configured",
			ServiceName:   "dns",
			Severity:      "medium",
			ResourceType:  "ManagedZone",
			Description:   "DS records are required for DNSSEC chain of trust",
			Risk:          "Without DS records, DNSSEC validation will fail",
			RemediationText: "Register DS record with the domain registrar",
			RemediationURL:  "https://cloud.google.com/dns/docs/dnssec#ds-record",
			Categories:    []string{"dns", "cryptography"},
		},
	}
}

func (c *DNSZoneDsRecordCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DNSZoneDsRecordCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dnsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dnsProvider")
	}
	dnsService, err := p.DNS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dnsService.ManagedZones.List(p.ProjectID())
	err = req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			// Só verifica zonas públicas com DNSSEC habilitado
			if zone.Visibility != "public" {
				continue
			}
			if zone.DnssecConfig == nil || zone.DnssecConfig.State != "on" {
				continue
			}
			// Verifica se existe DS record nas key specs
			hasDSRecord := false
			if zone.DnssecConfig.DefaultKeySpecs != nil {
				for _, ks := range zone.DnssecConfig.DefaultKeySpecs {
					if ks.KeyType == "keySigning" && ks.Algorithm != "" {
						hasDSRecord = true
						break
					}
				}
			}
			status := models.StatusFail
			ext := "DNS zone does not have DS record configured"
			if hasDSRecord {
				status = models.StatusPass
				ext = "DNS zone has DS record configured"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dns",
				ResourceID:     zone.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. DNSManagedZonePrivateCheck — verifica se zonas privadas estão configuradas corretamente
// ─────────────────────────────────────────────────────────────────────────────

type DNSManagedZonePrivateCheck struct {
	metadata models.CheckMetadata
}

func NewDNSManagedZonePrivateCheck() *DNSManagedZonePrivateCheck {
	return &DNSManagedZonePrivateCheck{
		metadata: models.CheckMetadata{
			Provider:      "gcp",
			CheckID:       "dns_managed_zone_private",
			CheckTitle:    "DNS private zones should have VPC networks configured",
			ServiceName:   "dns",
			Severity:      "low",
			ResourceType:  "ManagedZone",
			Description:   "Private DNS zones should have at least one VPC network attached",
			Risk:          "Private zones without VPC networks are not serving any resources",
			RemediationText: "Add VPC networks to the private DNS zone",
			RemediationURL:  "https://cloud.google.com/dns/docs/zones/private-zones",
			Categories:    []string{"dns", "networking"},
		},
	}
}

func (c *DNSManagedZonePrivateCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DNSManagedZonePrivateCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dnsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dnsProvider")
	}
	dnsService, err := p.DNS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dnsService.ManagedZones.List(p.ProjectID())
	err = req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			// Só verifica zonas privadas
			if zone.Visibility != "private" {
				continue
			}
			hasVPC := len(zone.PrivateVisibilityConfig.Networks) > 0
			status := models.StatusFail
			ext := "Private DNS zone has no VPC networks configured"
			if hasVPC {
				status = models.StatusPass
				ext = fmt.Sprintf("Private DNS zone has %d VPC network(s) configured", len(zone.PrivateVisibilityConfig.Networks))
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dns",
				ResourceID:     zone.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. DNSZoneLoggingCheck — verifica se o logging está habilitado na zona
// ─────────────────────────────────────────────────────────────────────────────

type DNSZoneLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewDNSZoneLoggingCheck() *DNSZoneLoggingCheck {
	return &DNSZoneLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:      "gcp",
			CheckID:       "dns_zone_logging_enabled",
			CheckTitle:    "DNS zone should have logging enabled",
			ServiceName:   "dns",
			Severity:      "low",
			ResourceType:  "ManagedZone",
			Description:   "DNS logging helps with auditing and troubleshooting",
			Risk:          "Without logging, DNS queries cannot be audited",
			RemediationText: "Enable Cloud Logging for the DNS zone",
			RemediationURL:  "https://cloud.google.com/dns/docs/monitoring",
			Categories:    []string{"dns", "logging", "monitoring"},
		},
	}
}

func (c *DNSZoneLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DNSZoneLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dnsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dnsProvider")
	}
	dnsService, err := p.DNS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dnsService.ManagedZones.List(p.ProjectID())
	err = req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			loggingEnabled := zone.CloudLoggingConfig != nil && zone.CloudLoggingConfig.EnableLogging
			status := models.StatusFail
			ext := "DNS zone logging is not enabled"
			if loggingEnabled {
				status = models.StatusPass
				ext = "DNS zone logging is enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dns",
				ResourceID:     zone.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}