package cloudguard

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// CloudguardEnabled - high
type CloudguardEnabled struct {
	metadata models.CheckMetadata
}

// NewCloudguardEnabled cria nova instância
func NewCloudguardEnabled() *CloudguardEnabled {
	return &CloudguardEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "cloudguard_enabled",
			CheckTitle:     "Cloud Guard is enabled in the root compartment of the tenancy",
			ServiceName:    "cloudguard",
			Severity:       "high",
			Description:    "**OCI Cloud Guard** status in the tenancy's root compartment is evaluated, expecting `ENABLED` to indicate the service is active for organization-wide",
			RemediationText: "Enable **Cloud Guard** at the tenancy root to centralize monitoring and automated response. Apply **",
			Categories:     []string{"cloudguard"},
		},
	}
}

// Metadata retorna os metadados
func (c *CloudguardEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *CloudguardEnabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "cloudguard",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

