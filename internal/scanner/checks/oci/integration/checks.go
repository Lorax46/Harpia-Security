package integration

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/integration"
)

// IntegrationInstanceAccessRestricted verifica se a instância de integração tem acesso restrito
type IntegrationInstanceAccessRestricted struct {
	metadata models.CheckMetadata
}

func NewIntegrationInstanceAccessRestricted() *IntegrationInstanceAccessRestricted {
	return &IntegrationInstanceAccessRestricted{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "integration_instance_access_restricted",
			CheckTitle:      "Integration Cloud instance uses a private endpoint or a public endpoint with IP or VCN allowlists",
			ServiceName:     "integration",
			Severity:        "high",
			Description:     "Oracle Integration Cloud instances should have network access restricted via private endpoint or IP/VCN allowlists.",
			RemediationText: "Configure private endpoints or use IP/VCN allowlists.",
			Categories:      []string{"integration"},
		},
	}
}

func (c *IntegrationInstanceAccessRestricted) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *IntegrationInstanceAccessRestricted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Integration() (integration.IntegrationInstanceClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Integration()")
	}

	client, err := p.Integration()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := integration.ListIntegrationInstancesRequest{
		CompartmentId: &tenancyId,
	}

	instances, err := client.ListIntegrationInstances(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar integration instances: %w", err)
	}

	for _, instance := range instances.Items {
		isUnrestricted := false
		reason := ""

		if instance.NetworkEndpointDetails == nil {
			isUnrestricted = true
			reason = "no network endpoint details configured (unrestricted access)"
		} else {
			// Verifica se é PublicEndpointDetails
			if pubEndpoint, ok := instance.NetworkEndpointDetails.(integration.PublicEndpointDetails); ok {
				// Verifica se tem 0.0.0.0/0 nos IPs permitidos
				hasOpenAccess := false
				for _, ip := range pubEndpoint.AllowlistedHttpIps {
					if strings.Contains(ip, "0.0.0.0/0") {
						hasOpenAccess = true
						break
					}
				}

				if hasOpenAccess {
					isUnrestricted = true
					reason = "unrestricted access with 0.0.0.0/0 in allowlisted HTTP IPs"
				} else if len(pubEndpoint.AllowlistedHttpIps) == 0 && len(pubEndpoint.AllowlistedHttpVcns) == 0 {
					isUnrestricted = true
					reason = "public access with no IP or VCN allowlists configured"
				}
			}
		}

		if isUnrestricted {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Integration instance %s has %s.", safeString(instance.DisplayName), reason),
				ResourceID:     safeString(instance.Id),
				Provider:       "oci",
				Service:        "integration",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Integration instance %s has restricted network access configured.", safeString(instance.DisplayName)),
				ResourceID:     safeString(instance.Id),
				Provider:       "oci",
				Service:        "integration",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No integration instances found",
			Provider:       "oci",
			Service:        "integration",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
