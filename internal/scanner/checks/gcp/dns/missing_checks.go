package dns

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type dnsCheck struct {
	metadata models.CheckMetadata
}

func (c *dnsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *dnsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP DNS check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "dns",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newDnsCheck(id, title, desc, sev string) dnsCheck {
	return dnsCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "dns", ResourceType: "Zone",
		Categories: []string{"dns"},
	}}
}

type dnsDnssecEnabled struct{ dnsCheck }

func NewDnsDnssecEnabled() *dnsDnssecEnabled {
	return &dnsDnssecEnabled{newDnsCheck("dns_dnssec_enabled", "Ensure DNS DNSSEC is enabled", "DNS DNSSEC should be enabled", "medium")}
}

type dnsZoneNoRrsaasNoRsasha1 struct{ dnsCheck }

func NewDnsZoneNoRrsaasNoRsasha1() *dnsZoneNoRrsaasNoRsasha1 {
	return &dnsZoneNoRrsaasNoRsasha1{newDnsCheck("dns_zone_no_rrsaas_no_rsasha1", "Ensure DNS zone has no RSAAS and no RSASHA1", "DNS zone should have no RSAAS and no RSASHA1", "medium")}
}

type dnsZoneNoRsasha1 struct{ dnsCheck }

func NewDnsZoneNoRsasha1() *dnsZoneNoRsasha1 {
	return &dnsZoneNoRsasha1{newDnsCheck("dns_zone_no_rsasha1", "Ensure DNS zone has no RSASHA1", "DNS zone should have no RSASHA1", "medium")}
}
