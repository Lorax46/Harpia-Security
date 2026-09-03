package integration

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// IntegrationInstanceAccessRestricted - high
type IntegrationInstanceAccessRestricted struct {
	metadata models.CheckMetadata
}

// NewIntegrationInstanceAccessRestricted cria nova instância
func NewIntegrationInstanceAccessRestricted() *IntegrationInstanceAccessRestricted {
	return &IntegrationInstanceAccessRestricted{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "integration_instance_access_restricted",
			CheckTitle:     "Integration Cloud instance uses a private endpoint or a public endpoint with IP or VCN allowlists",
			ServiceName:    "integration",
			Severity:       "high",
			Description:    "**Oracle Integration Cloud instances** are evaluated for **network endpoint restrictions**, confirming access is limited to approved IPs or VCNs. Conf",
			RemediationText: "Prefer **PRIVATE** endpoints and restrict access to specific VCNs. *If PUBLIC is required*, enforce ",
			Categories:     []string{"integration"},
		},
	}
}

// Metadata retorna os metadados
func (c *IntegrationInstanceAccessRestricted) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *IntegrationInstanceAccessRestricted) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "integration",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

