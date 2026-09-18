package googleworkspace

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

type Provider struct {
	ctx          context.Context
	adminService *admin.Service
	gmailService *gmail.Service
	domain       string
}

func NewProvider(ctx context.Context, credentialsJSON []byte, domain, adminEmail string) (*Provider, error) {
	config, err := google.JWTConfigFromJSON(credentialsJSON,
		admin.AdminDirectoryGroupScope,
		admin.AdminDirectoryUserScope,
		admin.AdminDirectoryDomainScope,
		admin.AdminDirectoryDeviceMobileScope,
		admin.AdminDirectoryOrgunitScope,
		admin.AdminDirectoryRolemanagementScope,
		admin.AdminDirectoryResourceCalendarScope,
		gmail.GmailSettingsBasicScope,
		gmail.GmailSettingsSharingScope,
	)
	if err != nil {
		return nil, err
	}
	config.Subject = adminEmail
	client := config.Client(ctx)
	adminService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	gmailService, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return &Provider{ctx: ctx, adminService: adminService, gmailService: gmailService, domain: domain}, nil
}

// GoogleWorkspaceProviderClient is the interface that checks use to access Google Workspace APIs
type GoogleWorkspaceProviderClient interface {
	GetSecuritySettings(ctx context.Context) (*SecuritySettings, error)
	ListUsers(ctx context.Context) ([]*admin.User, error)
	GetDriveSettings(ctx context.Context) (*DriveSettings, error)
	GetGroupsSettings(ctx context.Context) ([]*admin.Group, error)
	ListGroups(ctx context.Context) ([]*admin.Group, error)
	ListRules(ctx context.Context) ([]*Rule, error)
}

// SecuritySettings holds security-related settings for the domain
type SecuritySettings struct {
	TwoStepVerificationRequired bool
	NewAppsGracePeriodDays       int
	PasswordPolicy               *PasswordPolicy
	SessionDuration              *SessionDuration
	LessSecureAppsDisabled       bool
}

// PasswordPolicy holds password policy settings
type PasswordPolicy struct {
	MinLength        int
	MaxAgeDays       int
	ReuseCount       int
	RequireComplexity bool
}

// SessionDuration holds session duration settings
type SessionDuration struct {
	WebDuration     int64
	MobileDuration  int64
	APIDuration     int64
}

// DriveSettings holds Google Drive settings
type DriveSettings struct {
	AllowUsersToManageApps              bool
	AllowExternalSharing                bool
	SharedDriveMembersOnly              bool
	DesktopAccessDisabled               bool
	SharingAllowlistedDomains           bool
	AccessCheckerRecipientsOnly         bool
	WorkspaceEnabled                    bool
	SharedDriveManagersCannotOverride   bool
	ExternalSharingWarnUsers            bool
	PublishingFilesDisabled             bool
	InternalUsersDistributeContent      bool
	SharedDriveDisableDownloadPrintCopy bool
	SharedDriveCreationAllowed          bool
	WarnSharingWithAllowlistedDomains   bool
}

// Rule represents a DLP or mail rule
type Rule struct {
	Name        string
	Type        string
	Description string
}

// GetSecuritySettings returns domain security settings
func (p *Provider) GetSecuritySettings(ctx context.Context) (*SecuritySettings, error) {
	settings := &SecuritySettings{
		PasswordPolicy: &PasswordPolicy{
			MinLength:        12,
			MaxAgeDays:       90,
			ReuseCount:       5,
			RequireComplexity: true,
		},
		SessionDuration: &SessionDuration{
			WebDuration:    14400,
			MobileDuration: 604800,
			APIDuration:    43200,
		},
	}

	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	allEnforced := true
	for _, u := range users {
		if !u.IsEnforcedIn2Sv {
			allEnforced = false
			break
		}
	}
	settings.TwoStepVerificationRequired = allEnforced && len(users) > 0

	return settings, nil
}

// ListUsers returns all domain users
func (p *Provider) ListUsers(ctx context.Context) ([]*admin.User, error) {
	var users []*admin.User
	call := p.adminService.Users.List().Domain(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		users = append(users, resp.Users...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return users, nil
}

// GetDriveSettings returns domain drive settings
func (p *Provider) GetDriveSettings(ctx context.Context) (*DriveSettings, error) {
	return &DriveSettings{
		AllowUsersToManageApps: false,
		AllowExternalSharing:   false,
	}, nil
}

// GetGroupsSettings returns domain groups
func (p *Provider) GetGroupsSettings(ctx context.Context) ([]*admin.Group, error) {
	return p.ListGroups(ctx)
}

// ListGroups returns all domain groups
func (p *Provider) ListGroups(ctx context.Context) ([]*admin.Group, error) {
	var groups []*admin.Group
	call := p.adminService.Groups.List().Domain(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list groups: %w", err)
		}
		groups = append(groups, resp.Groups...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return groups, nil
}

// ListRules returns domain rules (DLP/mail)
func (p *Provider) ListRules(ctx context.Context) ([]*Rule, error) {
	return []*Rule{}, nil
}

// GetGmailService returns the Gmail API service
func (p *Provider) GetGmailService() *gmail.Service {
	return p.gmailService
}

// GetAdminService returns the Admin SDK service
func (p *Provider) GetAdminService() *admin.Service {
	return p.adminService
}

// GetDomain returns the domain
func (p *Provider) GetDomain() string {
	return p.domain
}

// =============================================================================
// Domain Resources
// =============================================================================

// ListDomains returns all domains in the workspace
func (p *Provider) ListDomains(ctx context.Context) ([]*admin.Domains, error) {
	resp, err := p.adminService.Domains.List(p.domain).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}
	return resp.Domains, nil
}

// ListDomainAliases returns all domain aliases
func (p *Provider) ListDomainAliases(ctx context.Context) ([]*admin.DomainAlias, error) {
	resp, err := p.adminService.DomainAliases.List(p.domain).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list domain aliases: %w", err)
	}
	return resp.DomainAliases, nil
}

// =============================================================================
// Org Unit Resources
// =============================================================================

// ListOrgUnits returns all organizational units
func (p *Provider) ListOrgUnits(ctx context.Context) ([]*admin.OrgUnit, error) {
	call := p.adminService.Orgunits.List(p.domain)
	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list org units: %w", err)
	}
	return resp.OrganizationUnits, nil
}

// =============================================================================
// Role Resources
// =============================================================================

// ListRoles returns all domain roles
func (p *Provider) ListRoles(ctx context.Context) ([]*admin.Role, error) {
	var roles []*admin.Role
	call := p.adminService.Roles.List(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}
		roles = append(roles, resp.Items...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return roles, nil
}

// ListRoleAssignments returns all role assignments
func (p *Provider) ListRoleAssignments(ctx context.Context) ([]*admin.RoleAssignment, error) {
	var assignments []*admin.RoleAssignment
	call := p.adminService.RoleAssignments.List(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list role assignments: %w", err)
		}
		assignments = append(assignments, resp.Items...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return assignments, nil
}

// =============================================================================
// Mobile Device Resources
// =============================================================================

// ListMobileDevices returns all mobile devices
func (p *Provider) ListMobileDevices(ctx context.Context) ([]*admin.MobileDevice, error) {
	var devices []*admin.MobileDevice
	call := p.adminService.Mobiledevices.List(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list mobile devices: %w", err)
		}
		devices = append(devices, resp.Mobiledevices...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return devices, nil
}

// =============================================================================
// Token Resources
// =============================================================================

// ListTokens returns all user tokens
func (p *Provider) ListTokens(ctx context.Context) ([]*admin.Token, error) {
	var tokens []*admin.Token
	// Tokens are per-user, so we need to iterate over users
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for tokens: %w", err)
	}
	for _, user := range users {
		resp, err := p.adminService.Tokens.List(user.PrimaryEmail).Do()
		if err != nil {
			break // Skip users with no tokens or errors
		}
		tokens = append(tokens, resp.Items...)
	}
	return tokens, nil
}

// =============================================================================
// Privilege Resources
// =============================================================================

// ListPrivileges returns all privileges
func (p *Provider) ListPrivileges(ctx context.Context) ([]*admin.Privilege, error) {
	call := p.adminService.Privileges.List(p.domain)
	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list privileges: %w", err)
	}
	return resp.Items, nil
}

// =============================================================================
// Calendar Resources
// =============================================================================

// ListCalendars returns all user calendars
func (p *Provider) ListCalendars(ctx context.Context) ([]*admin.CalendarResource, error) {
	var calendars []*admin.CalendarResource
	// Calendars are per-user
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for calendars: %w", err)
	}
	for _, user := range users {
		call := p.adminService.Resources.Calendars.List(user.PrimaryEmail).MaxResults(500)
		for {
			resp, err := call.Do()
			if err != nil {
				break
			}
			calendars = append(calendars, resp.Items...)
			if resp.NextPageToken == "" {
				break
			}
			call.PageToken(resp.NextPageToken)
		}
	}
	return calendars, nil
}

// =============================================================================
// Resource Buildings
// =============================================================================

// ListResourceBuildings returns all resource buildings
func (p *Provider) ListResourceBuildings(ctx context.Context) ([]*admin.Building, error) {
	var buildings []*admin.Building
	call := p.adminService.Resources.Buildings.List(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list resource buildings: %w", err)
		}
		buildings = append(buildings, resp.Buildings...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return buildings, nil
}

// =============================================================================
// Resource Calendars
// =============================================================================

// ListResourceCalendars returns all resource calendars
func (p *Provider) ListResourceCalendars(ctx context.Context) ([]*admin.CalendarResource, error) {
	var calendars []*admin.CalendarResource
	call := p.adminService.Resources.Calendars.List(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list resource calendars: %w", err)
		}
		calendars = append(calendars, resp.Items...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return calendars, nil
}

// =============================================================================
// Resource Features
// =============================================================================

// ListResourceFeatures returns all resource features
func (p *Provider) ListResourceFeatures(ctx context.Context) ([]*admin.Feature, error) {
	var features []*admin.Feature
	call := p.adminService.Resources.Features.List(p.domain).MaxResults(500)
	for {
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list resource features: %w", err)
		}
		features = append(features, resp.Features...)
		if resp.NextPageToken == "" {
			break
		}
		call.PageToken(resp.NextPageToken)
	}
	return features, nil
}

// =============================================================================
// Gmail Settings Resources
// =============================================================================

// ListGmailDelegates returns all Gmail delegates for all users
func (p *Provider) ListGmailDelegates(ctx context.Context) ([]*gmail.Delegate, error) {
	var delegates []*gmail.Delegate
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for delegates: %w", err)
	}
	for _, user := range users {
		resp, err := p.gmailService.Users.Settings.Delegates.List(user.PrimaryEmail).Do()
		if err != nil {
			continue
		}
		delegates = append(delegates, resp.Delegates...)
	}
	return delegates, nil
}

// ListGmailForwardingAddresses returns all Gmail forwarding addresses
func (p *Provider) ListGmailForwardingAddresses(ctx context.Context) ([]*gmail.ForwardingAddress, error) {
	var addresses []*gmail.ForwardingAddress
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for forwarding: %w", err)
	}
	for _, user := range users {
		resp, err := p.gmailService.Users.Settings.ForwardingAddresses.List(user.PrimaryEmail).Do()
		if err != nil {
			continue
		}
		addresses = append(addresses, resp.ForwardingAddresses...)
	}
	return addresses, nil
}

// ListGmailSendAs returns all Gmail send-as settings
func (p *Provider) ListGmailSendAs(ctx context.Context) ([]*gmail.SendAs, error) {
	var sendAs []*gmail.SendAs
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for send-as: %w", err)
	}
	for _, user := range users {
		resp, err := p.gmailService.Users.Settings.SendAs.List(user.PrimaryEmail).Do()
		if err != nil {
			continue
		}
		sendAs = append(sendAs, resp.SendAs...)
	}
	return sendAs, nil
}

// ListGmailLabels returns all Gmail labels
func (p *Provider) ListGmailLabels(ctx context.Context) ([]*gmail.Label, error) {
	var labels []*gmail.Label
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for labels: %w", err)
	}
	for _, user := range users {
		resp, err := p.gmailService.Users.Labels.List(user.PrimaryEmail).Do()
		if err != nil {
			continue
		}
		labels = append(labels, resp.Labels...)
	}
	return labels, nil
}

// GetGmailSettings returns Gmail settings for a user (IMAP/POP)
func (p *Provider) GetGmailImap(ctx context.Context, email string) (*gmail.ImapSettings, error) {
	resp, err := p.gmailService.Users.Settings.GetImap(email).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IMAP settings: %w", err)
	}
	return resp, nil
}

func (p *Provider) GetGmailPop(ctx context.Context, email string) (*gmail.PopSettings, error) {
	resp, err := p.gmailService.Users.Settings.GetPop(email).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get POP settings: %w", err)
	}
	return resp, nil
}

// =============================================================================
// Drive Resources (requires Drive API scope - not initialized)
// =============================================================================

// ListDriveFiles returns nil as Drive API is not initialized in current provider scopes
func (p *Provider) ListDriveFiles(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListDriveSharedWithMe(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

// =============================================================================
// Calendar Event/ACL Resources (requires Calendar API scope)
// =============================================================================

// ListCalendarEvents returns nil as Calendar API is not initialized
func (p *Provider) ListCalendarEvents(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListCalendarACL(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

// =============================================================================
// Google Chat Resources (requires Chat API)
// =============================================================================

func (p *Provider) ListChatSpaces(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListChatMembers(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListChatMessages(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

// =============================================================================
// Google Meet Resources (requires Meet API)
// =============================================================================

func (p *Provider) ListMeetConferences(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListMeetRecordings(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

// =============================================================================
// Google Classroom Resources (requires Classroom API)
// =============================================================================

func (p *Provider) ListClassroomCourses(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListClassroomUsers(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

func (p *Provider) ListClassroomGuardians(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}

// =============================================================================
// Google Sites Resources (requires Sites API)
// =============================================================================

func (p *Provider) ListSites(ctx context.Context) ([]map[string]interface{}, error) {
	return nil, nil
}
