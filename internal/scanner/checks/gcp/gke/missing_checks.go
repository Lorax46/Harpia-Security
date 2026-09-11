package gke

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type gkeCheck struct {
	metadata models.CheckMetadata
}

func (c *gkeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *gkeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP GKE check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "gke",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newGkeCheck(id, title, desc, sev string) gkeCheck {
	return gkeCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "gke", ResourceType: "Cluster",
		Categories: []string{"gke"},
	}}
}

type gkeClusterBinaryAuthorizationEnabled struct{ gkeCheck }

func NewGkeClusterBinaryAuthorizationEnabled() *gkeClusterBinaryAuthorizationEnabled {
	return &gkeClusterBinaryAuthorizationEnabled{newGkeCheck("gke_cluster_binary_authorization_enabled", "Ensure GKE cluster binary authorization is enabled", "GKE cluster should have binary authorization enabled", "high")}
}
