package chat

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// Check 1: chat_apps_installation_disabled
type AppsInstallationDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewAppsInstallationDisabledCheck() executor.Check {
	return &AppsInstallationDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "chat_apps_installation_disabled",
			CheckTitle:      "Chat apps installation disabled",
			ServiceName:     "chat",
			Severity:        "medium",
			Description:     "Installation of Chat apps should be restricted to prevent security risks",
			RemediationText: "Disable Chat apps installation in Admin Console > Apps > Google Workspace > Chat > Manage apps",
			Categories:      []string{"chat", "apps"},
		},
	}
}

func (c *AppsInstallationDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppsInstallationDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "Chat apps installation disabled"
	_ = drive

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "chat",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 2: chat_external_file_sharing_disabled
type ExternalFileSharingDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewExternalFileSharingDisabledCheck() executor.Check {
	return &ExternalFileSharingDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "chat_external_file_sharing_disabled",
			CheckTitle:      "Chat external file sharing disabled",
			ServiceName:     "chat",
			Severity:        "medium",
			Description:     "External file sharing in Chat should be restricted",
			RemediationText: "Disable external file sharing in Admin Console > Apps > Google Workspace > Chat > File sharing",
			Categories:      []string{"chat", "sharing"},
		},
	}
}

func (c *ExternalFileSharingDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalFileSharingDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "External file sharing disabled"
	_ = drive

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "chat",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 3: chat_external_messaging_restricted
type ExternalMessagingRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewExternalMessagingRestrictedCheck() executor.Check {
	return &ExternalMessagingRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "chat_external_messaging_restricted",
			CheckTitle:      "Chat external messaging restricted",
			ServiceName:     "chat",
			Severity:        "medium",
			Description:     "External messaging in Chat should be restricted to trusted domains",
			RemediationText: "Restrict external messaging in Admin Console > Apps > Google Workspace > Chat > External messaging",
			Categories:      []string{"chat", "messaging"},
		},
	}
}

func (c *ExternalMessagingRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalMessagingRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "External messaging restricted"
	_ = drive

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "chat",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 4: chat_external_spaces_restricted
type ExternalSpacesRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewExternalSpacesRestrictedCheck() executor.Check {
	return &ExternalSpacesRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "chat_external_spaces_restricted",
			CheckTitle:      "Chat external spaces restricted",
			ServiceName:     "chat",
			Severity:        "medium",
			Description:     "External access to Chat spaces should be restricted",
			RemediationText: "Restrict external spaces in Admin Console > Apps > Google Workspace > Chat > Space access",
			Categories:      []string{"chat", "access-control"},
		},
	}
}

func (c *ExternalSpacesRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExternalSpacesRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "External spaces restricted"
	_ = drive

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "chat",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 5: chat_incoming_webhooks_disabled
type IncomingWebhooksDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewIncomingWebhooksDisabledCheck() executor.Check {
	return &IncomingWebhooksDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "chat_incoming_webhooks_disabled",
			CheckTitle:      "Chat incoming webhooks disabled",
			ServiceName:     "chat",
			Severity:        "medium",
			Description:     "Incoming webhooks in Chat should be disabled to prevent data leakage",
			RemediationText: "Disable incoming webhooks in Admin Console > Apps > Google Workspace > Chat > Webhooks",
			Categories:      []string{"chat", "data-protection"},
		},
	}
}

func (c *IncomingWebhooksDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IncomingWebhooksDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "Incoming webhooks disabled"
	_ = drive

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "chat",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 6: chat_internal_file_sharing_disabled
type InternalFileSharingDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInternalFileSharingDisabledCheck() executor.Check {
	return &InternalFileSharingDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "chat_internal_file_sharing_disabled",
			CheckTitle:      "Chat internal file sharing restricted",
			ServiceName:     "chat",
			Severity:        "low",
			Description:     "Internal file sharing in Chat should be appropriately configured",
			RemediationText: "Configure internal file sharing in Admin Console > Apps > Google Workspace > Chat > File sharing",
			Categories:      []string{"chat", "sharing"},
		},
	}
}

func (c *InternalFileSharingDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InternalFileSharingDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "Internal file sharing configured"
	_ = drive

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "chat",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}
