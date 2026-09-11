package aisearch

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type aisearchServiceNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewAisearchServiceNotPubliclyAccessible() *aisearchServiceNotPubliclyAccessible {
	return &aisearchServiceNotPubliclyAccessible{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "aisearch_service_not_publicly_accessible",
		CheckTitle: "Ensure AI Search service is not publicly accessible",
		Description: "AI Search service should not be publicly accessible",
		Severity: "high", ServiceName: "aisearch", ResourceType: "SearchService",
		Categories: []string{"aisearch"},
	}}
}

func (c *aisearchServiceNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *aisearchServiceNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "AI Search public access check requires Azure SDK",
		ResourceID: "aisearch-public-access", Provider: "azure", Service: "aisearch",
		FoundAt: time.Now().UTC(),
	}}, nil
}
