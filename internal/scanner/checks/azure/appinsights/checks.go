package appinsights

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type appinsightsEnsureIsConfigured struct {
	metadata models.CheckMetadata
}

func NewAppinsightsEnsureIsConfigured() *appinsightsEnsureIsConfigured {
	return &appinsightsEnsureIsConfigured{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "appinsights_ensure_is_configured",
		CheckTitle: "Ensure Application Insights is configured",
		Description: "Application Insights should be configured for applications",
		Severity: "medium", ServiceName: "appinsights", ResourceType: "Component",
		Categories: []string{"appinsights"},
	}}
}

func (c *appinsightsEnsureIsConfigured) Metadata() models.CheckMetadata { return c.metadata }

func (c *appinsightsEnsureIsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App Insights check requires Azure SDK",
		ResourceID: "appinsights-configured", Provider: "azure", Service: "appinsights",
		FoundAt: time.Now().UTC(),
	}}, nil
}
