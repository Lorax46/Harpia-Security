package analytics

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// AnalyticsInstanceAccessRestricted - high
type AnalyticsInstanceAccessRestricted struct {
	metadata models.CheckMetadata
}

// NewAnalyticsInstanceAccessRestricted cria nova instância
func NewAnalyticsInstanceAccessRestricted() *AnalyticsInstanceAccessRestricted {
	return &AnalyticsInstanceAccessRestricted{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "analytics_instance_access_restricted",
			CheckTitle:     "Oracle Analytics Cloud instance is deployed within a Virtual Cloud Network or restricts public access to allowed sources",
			ServiceName:    "analytics",
			Severity:       "high",
			Description:    "Oracle Analytics Cloud endpoints are evaluated for **network exposure**. Public endpoints must use **restricted allowlists** of specific IPs/CIDRs; pr",
			RemediationText: "Prefer **private deployment in a VCN** and apply **least privilege** network access. *If public is r",
			Categories:     []string{"analytics"},
		},
	}
}

// Metadata retorna os metadados
func (c *AnalyticsInstanceAccessRestricted) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *AnalyticsInstanceAccessRestricted) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "analytics",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

