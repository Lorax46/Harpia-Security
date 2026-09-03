package analytics

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// InstanceAccessRestrictedCheck verifica se instâncias analytics têm acesso restrito
type InstanceAccessRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceAccessRestrictedCheck() *InstanceAccessRestrictedCheck {
	return &InstanceAccessRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "analytics_instance_access_restricted",
			CheckTitle:      "Ensure Analytics Cloud instances are not publicly accessible",
			ServiceName:     "analytics",
			Severity:        "high",
			Description:     "Oracle Analytics Cloud instances should not be publicly accessible",
			RemediationText: "Restrict access to Oracle Analytics Cloud instances",
			Categories:      []string{"analytics"},
		},
	}
}

func (c *InstanceAccessRestrictedCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceAccessRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation - OCI SDK API incompatibility",
			Provider:       "oci",
			Service:        "analytics",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}
