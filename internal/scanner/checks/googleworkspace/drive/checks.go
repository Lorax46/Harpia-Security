package drive

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// DriveSharedDriveMembersOnlyAccessCheck checks that Shared Drives are accessible only to members
type DriveSharedDriveMembersOnlyAccessCheck struct {
	metadata models.CheckMetadata
}

func NewDriveSharedDriveMembersOnlyAccessCheck() executor.Check {
	return &DriveSharedDriveMembersOnlyAccessCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_shared_drive_members_only_access",
			CheckTitle: "Shared Drive members-only access",
			ServiceName: "drive",
			Severity: "medium",
			Description: "Shared Drives should be accessible only to members",
			RemediationText: "Restrict Shared Drive access to members in Admin Console > Apps > Google Workspace > Drive and Docs > Sharing settings",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveSharedDriveMembersOnlyAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveSharedDriveMembersOnlyAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Shared Drive members-only access is not enforced"
	if settings != nil && settings.SharedDriveMembersOnly {
		status = models.StatusPass
		msg = "Shared Drive members-only access is enforced"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveDesktopAccessDisabledCheck checks that Google Drive desktop app access is disabled
type DriveDesktopAccessDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewDriveDesktopAccessDisabledCheck() executor.Check {
	return &DriveDesktopAccessDisabledCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_desktop_access_disabled",
			CheckTitle: "Google Drive desktop app access disabled",
			ServiceName: "drive",
			Severity: "medium",
			Description: "Google Drive desktop app access should be disabled",
			RemediationText: "Disable Drive for Desktop in Admin Console > Apps > Google Workspace > Drive and Docs > Google Drive for Desktop",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveDesktopAccessDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveDesktopAccessDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Google Drive desktop app access is not disabled"
	if settings != nil && settings.DesktopAccessDisabled {
		status = models.StatusPass
		msg = "Google Drive desktop app access is disabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveSharingAllowlistedDomainsCheck checks that sharing is restricted to allowlisted domains
type DriveSharingAllowlistedDomainsCheck struct {
	metadata models.CheckMetadata
}

func NewDriveSharingAllowlistedDomainsCheck() executor.Check {
	return &DriveSharingAllowlistedDomainsCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_sharing_allowlisted_domains",
			CheckTitle: "Drive sharing restricted to allowlisted domains",
			ServiceName: "drive",
			Severity: "high",
			Description: "Google Drive sharing should be restricted to allowlisted domains only",
			RemediationText: "Configure allowlisted domains in Admin Console > Apps > Google Workspace > Drive and Docs > Sharing settings",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveSharingAllowlistedDomainsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveSharingAllowlistedDomainsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Drive sharing is not restricted to allowlisted domains"
	if settings != nil && settings.SharingAllowlistedDomains {
		status = models.StatusPass
		msg = "Drive sharing is restricted to allowlisted domains"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveAccessCheckerRecipientsOnlyCheck checks that access checker only applies to recipients
type DriveAccessCheckerRecipientsOnlyCheck struct {
	metadata models.CheckMetadata
}

func NewDriveAccessCheckerRecipientsOnlyCheck() executor.Check {
	return &DriveAccessCheckerRecipientsOnlyCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_access_checker_recipients_only",
			CheckTitle: "Drive access checker restricted to recipients",
			ServiceName: "drive",
			Severity: "low",
			Description: "Drive access checker should only apply to file recipients",
			RemediationText: "Configure access checker to apply only to recipients in Admin Console > Apps > Google Workspace > Drive and Docs",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveAccessCheckerRecipientsOnlyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveAccessCheckerRecipientsOnlyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Drive access checker is not restricted to recipients only"
	if settings != nil && settings.AccessCheckerRecipientsOnly {
		status = models.StatusPass
		msg = "Drive access checker is restricted to recipients only"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveWorkspaceEnabledCheck checks that Google Workspace for Drive is enabled
type DriveWorkspaceEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewDriveWorkspaceEnabledCheck() executor.Check {
	return &DriveWorkspaceEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_workspace_enabled",
			CheckTitle: "Google Workspace for Drive enabled",
			ServiceName: "drive",
			Severity: "low",
			Description: "Google Workspace for Drive should be enabled for collaboration features",
			RemediationText: "Enable Google Workspace for Drive in Admin Console > Apps > Google Workspace > Drive and Docs",
			Categories: []string{"collaboration", "drive"},
		},
	}
}

func (c *DriveWorkspaceEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveWorkspaceEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Google Workspace for Drive is not enabled"
	if settings != nil && settings.WorkspaceEnabled {
		status = models.StatusPass
		msg = "Google Workspace for Drive is enabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveSharedDriveManagersCannotOverrideCheck checks that shared drive managers cannot override settings
type DriveSharedDriveManagersCannotOverrideCheck struct {
	metadata models.CheckMetadata
}

func NewDriveSharedDriveManagersCannotOverrideCheck() executor.Check {
	return &DriveSharedDriveManagersCannotOverrideCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_shared_drive_managers_cannot_override",
			CheckTitle: "Shared Drive managers cannot override settings",
			ServiceName: "drive",
			Severity: "medium",
			Description: "Shared Drive managers should not be able to override sharing settings",
			RemediationText: "Restrict Shared Drive managers from overriding settings in Admin Console > Apps > Google Workspace > Drive and Docs > Sharing settings",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveSharedDriveManagersCannotOverrideCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveSharedDriveManagersCannotOverrideCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Shared Drive managers can override sharing settings"
	if settings != nil && settings.SharedDriveManagersCannotOverride {
		status = models.StatusPass
		msg = "Shared Drive managers cannot override sharing settings"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveExternalSharingWarnUsersCheck checks that users are warned about external sharing
type DriveExternalSharingWarnUsersCheck struct {
	metadata models.CheckMetadata
}

func NewDriveExternalSharingWarnUsersCheck() executor.Check {
	return &DriveExternalSharingWarnUsersCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_external_sharing_warn_users",
			CheckTitle: "Users warned about external sharing",
			ServiceName: "drive",
			Severity: "medium",
			Description: "Users should be warned when sharing content externally",
			RemediationText: "Enable external sharing warnings in Admin Console > Apps > Google Workspace > Drive and Docs > Sharing settings",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveExternalSharingWarnUsersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveExternalSharingWarnUsersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Users are not warned about external sharing"
	if settings != nil && settings.ExternalSharingWarnUsers {
		status = models.StatusPass
		msg = "Users are warned about external sharing"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DrivePublishingFilesDisabledCheck checks that publishing files is disabled
type DrivePublishingFilesDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewDrivePublishingFilesDisabledCheck() executor.Check {
	return &DrivePublishingFilesDisabledCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_publishing_files_disabled",
			CheckTitle: "Publishing files on the web disabled",
			ServiceName: "drive",
			Severity: "high",
			Description: "Publishing files on the web should be disabled to prevent public access",
			RemediationText: "Disable publishing files in Admin Console > Apps > Google Workspace > Drive and Docs > Sharing settings",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DrivePublishingFilesDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DrivePublishingFilesDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Publishing files on the web is not disabled"
	if settings != nil && settings.PublishingFilesDisabled {
		status = models.StatusPass
		msg = "Publishing files on the web is disabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveInternalUsersDistributeContentCheck checks that internal users can distribute content
type DriveInternalUsersDistributeContentCheck struct {
	metadata models.CheckMetadata
}

func NewDriveInternalUsersDistributeContentCheck() executor.Check {
	return &DriveInternalUsersDistributeContentCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_internal_users_distribute_content",
			CheckTitle: "Internal users can distribute content",
			ServiceName: "drive",
			Severity: "low",
			Description: "Internal users should be able to distribute content within the organization",
			RemediationText: "Ensure internal content distribution is enabled in Admin Console > Apps > Google Workspace > Drive and Docs",
			Categories: []string{"collaboration", "drive"},
		},
	}
}

func (c *DriveInternalUsersDistributeContentCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveInternalUsersDistributeContentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Internal users cannot distribute content"
	if settings != nil && settings.InternalUsersDistributeContent {
		status = models.StatusPass
		msg = "Internal users can distribute content"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveSharedDriveDisableDownloadPrintCopyCheck checks that download/print/copy is disabled for shared drives
type DriveSharedDriveDisableDownloadPrintCopyCheck struct {
	metadata models.CheckMetadata
}

func NewDriveSharedDriveDisableDownloadPrintCopyCheck() executor.Check {
	return &DriveSharedDriveDisableDownloadPrintCopyCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_shared_drive_disable_download_print_copy",
			CheckTitle: "Shared Drive download, print, and copy disabled",
			ServiceName: "drive",
			Severity: "medium",
			Description: "Download, print, and copy should be disabled for Shared Drive members by default",
			RemediationText: "Disable download, print, and copy for Shared Drive members in Admin Console > Apps > Google Workspace > Drive and Docs",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveSharedDriveDisableDownloadPrintCopyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveSharedDriveDisableDownloadPrintCopyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Shared Drive download, print, and copy is not disabled"
	if settings != nil && settings.SharedDriveDisableDownloadPrintCopy {
		status = models.StatusPass
		msg = "Shared Drive download, print, and copy is disabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveSharedDriveCreationAllowedCheck checks if shared drive creation is allowed
type DriveSharedDriveCreationAllowedCheck struct {
	metadata models.CheckMetadata
}

func NewDriveSharedDriveCreationAllowedCheck() executor.Check {
	return &DriveSharedDriveCreationAllowedCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_shared_drive_creation_allowed",
			CheckTitle: "Shared Drive creation controlled",
			ServiceName: "drive",
			Severity: "low",
			Description: "Shared Drive creation should be controlled to prevent unmanaged data sprawl",
			RemediationText: "Review Shared Drive creation settings in Admin Console > Apps > Google Workspace > Drive and Docs",
			Categories: []string{"data-governance", "drive"},
		},
	}
}

func (c *DriveSharedDriveCreationAllowedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveSharedDriveCreationAllowedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusInfo
	msg := "Shared Drive creation is allowed (consider restricting if unmanaged)"

	if settings != nil {
		if settings.SharedDriveCreationAllowed {
			msg = "Shared Drive creation is allowed (consider restricting if unmanaged)"
		} else {
			status = models.StatusPass
			msg = "Shared Drive creation is restricted"
		}
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DriveWarnSharingWithAllowlistedDomainsCheck checks that users are warned when sharing with allowlisted domains
type DriveWarnSharingWithAllowlistedDomainsCheck struct {
	metadata models.CheckMetadata
}

func NewDriveWarnSharingWithAllowlistedDomainsCheck() executor.Check {
	return &DriveWarnSharingWithAllowlistedDomainsCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "drive_warn_sharing_with_allowlisted_domains",
			CheckTitle: "Warn users when sharing with allowlisted domains",
			ServiceName: "drive",
			Severity: "medium",
			Description: "Users should be warned when sharing files with allowlisted domains to prevent accidental external sharing",
			RemediationText: "Enable warning for sharing with allowlisted domains in Admin Console > Apps > Google Workspace > Drive and Docs",
			Categories: []string{"data-protection", "drive"},
		},
	}
}

func (c *DriveWarnSharingWithAllowlistedDomainsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DriveWarnSharingWithAllowlistedDomainsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	settings, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusFail
	msg := "Users are not warned when sharing with allowlisted domains"
	if settings != nil && settings.WarnSharingWithAllowlistedDomains {
		status = models.StatusPass
		msg = "Users are warned when sharing with allowlisted domains"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "drive",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}
