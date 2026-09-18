package additionalservices

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// AdditionalservicesExternalGroupsDisabledCheck checks that external groups are disabled in additional services
type AdditionalservicesExternalGroupsDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewAdditionalservicesExternalGroupsDisabledCheck() executor.Check {
	return &AdditionalservicesExternalGroupsDisabledCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "additionalservices_external_groups_disabled",
			CheckTitle: "External groups disabled in additional services",
			ServiceName: "additionalservices",
			Severity: "medium",
			Description: "External groups should be disabled in additional Google services",
			RemediationText: "Disable external groups in Admin Console > Apps > Additional Google services",
			Categories: []string{"data-protection", "additionalservices"},
		},
	}
}

func (c *AdditionalservicesExternalGroupsDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdditionalservicesExternalGroupsDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	_, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to access provider: %w", err)
	}

	// In a real implementation, this would check additional services settings
	// For now, report informational status
	status := models.StatusInfo
	msg := "External groups status in additional services should be reviewed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "additionalservices",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}
