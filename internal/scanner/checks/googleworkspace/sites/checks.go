package sites

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// SitesServiceDisabledCheck checks that Google Sites service is disabled or controlled
type SitesServiceDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewSitesServiceDisabledCheck() executor.Check {
	return &SitesServiceDisabledCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "sites_service_disabled",
			CheckTitle: "Google Sites service controlled",
			ServiceName: "sites",
			Severity: "low",
			Description: "Google Sites service should be controlled to prevent unauthorized content creation",
			RemediationText: "Control Sites service in Admin Console > Apps > Google Workspace > Sites",
			Categories: []string{"data-governance", "sites"},
		},
	}
}

func (c *SitesServiceDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SitesServiceDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	_, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to access provider: %w", err)
	}

	// In a real implementation, this would check if the Sites service is enabled
	// For now, report informational status
	status := models.StatusInfo
	msg := "Google Sites service status should be reviewed in Admin Console"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "sites",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}
