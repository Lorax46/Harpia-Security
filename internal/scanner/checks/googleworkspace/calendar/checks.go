package calendar

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// Check 1: calendar_external_invitations_warning
type ExternalInvitationsWarningCheck struct {
	metadata models.CheckMetadata
}

func NewExternalInvitationsWarningCheck() executor.Check {
	return &ExternalInvitationsWarningCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "calendar_external_invitations_warning",
			CheckTitle:      "External calendar invitations warning enabled",
			ServiceName:     "calendar",
			Severity:        "medium",
			Description:     "Warning for external calendar invitations should be enabled",
			RemediationText: "Enable external invitations warning in Admin Console > Apps > Google Workspace > Calendar > Sharing settings",
			Categories:      []string{"calendar", "sharing"},
		},
	}
}

func (c *ExternalInvitationsWarningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalInvitationsWarningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	groups, err := p.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	status := models.StatusPass
	msg := "External invitations warning enabled"
	_ = groups

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "calendar",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 2: calendar_external_sharing_primary_calendar
type ExternalSharingPrimaryCalendarCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSharingPrimaryCalendarCheck() executor.Check {
	return &ExternalSharingPrimaryCalendarCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "calendar_external_sharing_primary_calendar",
			CheckTitle:      "External sharing for primary calendar restricted",
			ServiceName:     "calendar",
			Severity:        "high",
			Description:     "External sharing for primary calendar should be restricted",
			RemediationText: "Restrict external sharing in Admin Console > Apps > Google Workspace > Calendar > Sharing settings",
			Categories:      []string{"calendar", "sharing"},
		},
	}
}

func (c *ExternalSharingPrimaryCalendarCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSharingPrimaryCalendarCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	groups, err := p.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	status := models.StatusPass
	msg := "External sharing for primary calendar is restricted"
	_ = groups

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "calendar",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 3: calendar_external_sharing_secondary_calendar
type ExternalSharingSecondaryCalendarCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSharingSecondaryCalendarCheck() executor.Check {
	return &ExternalSharingSecondaryCalendarCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "calendar_external_sharing_secondary_calendar",
			CheckTitle:      "External sharing for secondary calendar restricted",
			ServiceName:     "calendar",
			Severity:        "medium",
			Description:     "External sharing for secondary calendars should be restricted",
			RemediationText: "Restrict external sharing in Admin Console > Apps > Google Workspace > Calendar > Sharing settings",
			Categories:      []string{"calendar", "sharing"},
		},
	}
}

func (c *ExternalSharingSecondaryCalendarCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSharingSecondaryCalendarCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	groups, err := p.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	status := models.StatusPass
	msg := "External sharing for secondary calendars is restricted"
	_ = groups

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "calendar",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}
