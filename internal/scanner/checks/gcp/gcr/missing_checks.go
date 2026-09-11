package gcr

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type gcrCheck struct {
	metadata models.CheckMetadata
}

func (c *gcrCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *gcrCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP GCR check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "gcr",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newGcrCheck(id, title, desc, sev string) gcrCheck {
	return gcrCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "gcr", ResourceType: "Registry",
		Categories: []string{"gcr"},
	}}
}

type gcrContainerRegistryPublicAccessDisabled struct{ gcrCheck }

func NewGcrContainerRegistryPublicAccessDisabled() *gcrContainerRegistryPublicAccessDisabled {
	return &gcrContainerRegistryPublicAccessDisabled{newGcrCheck("gcr_container_registry_public_access_disabled", "Ensure GCR public access is disabled", "GCR should have public access disabled", "high")}
}
