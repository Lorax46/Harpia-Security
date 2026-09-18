package marketplace

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// MarketplaceAppsAccessRestrictedCheck checks that Marketplace apps access is restricted
type MarketplaceAppsAccessRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewMarketplaceAppsAccessRestrictedCheck() executor.Check {
	return &MarketplaceAppsAccessRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "marketplace_apps_access_restricted",
			CheckTitle: "Marketplace apps access restricted",
			ServiceName: "marketplace",
			Severity: "medium",
			Description: "Google Workspace Marketplace app installations should be restricted to approved apps only",
			RemediationText: "Restrict Marketplace apps in Admin Console > Apps > Google Workspace Marketplace apps > Apps access control",
			Categories: []string{"application", "marketplace"},
		},
	}
}

func (c *MarketplaceAppsAccessRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MarketplaceAppsAccessRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	status := models.StatusFail
	msg := "Marketplace apps access is not restricted"
	if settings != nil && settings.AllowUsersToManageApps {
		status = models.StatusPass
		msg = "Marketplace apps access is restricted"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "marketplace",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}
