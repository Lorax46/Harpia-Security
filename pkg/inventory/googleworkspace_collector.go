package inventory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/gmail/v1"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// GoogleWorkspaceCollector implementa a interface Collector para Google Workspace.
type GoogleWorkspaceCollector struct {
	provider *googleworkspace.Provider
	cache    map[string]*InventoryResult
	mu       sync.RWMutex
}

// NewGoogleWorkspaceCollector cria um novo coletor Google Workspace.
func NewGoogleWorkspaceCollector(provider *googleworkspace.Provider) *GoogleWorkspaceCollector {
	return &GoogleWorkspaceCollector{
		provider: provider,
		cache:    make(map[string]*InventoryResult),
	}
}

// Collect coleta recursos do tipo especificado.
func (c *GoogleWorkspaceCollector) Collect(ctx context.Context, resourceType string) (*InventoryResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[resourceType]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	result := &InventoryResult{
		ResourceType: resourceType,
		Provider:     "googleworkspace",
		Resources:    []Resource{},
		CollectedAt:  time.Now(),
	}

	var err error
	switch resourceType {
	case "googleworkspace_user":
		result.Resources, err = c.collectUsers(ctx)
	case "googleworkspace_group":
		result.Resources, err = c.collectGroups(ctx)
	case "googleworkspace_domain":
		result.Resources, err = c.collectDomains(ctx)
	case "googleworkspace_domain_alias":
		result.Resources, err = c.collectDomainAliases(ctx)
	case "googleworkspace_org_unit":
		result.Resources, err = c.collectOrgUnits(ctx)
	case "googleworkspace_role":
		result.Resources, err = c.collectRoles(ctx)
	case "googleworkspace_role_assignment":
		result.Resources, err = c.collectRoleAssignments(ctx)
	case "googleworkspace_mobile_device":
		result.Resources, err = c.collectMobileDevices(ctx)
	case "googleworkspace_token":
		result.Resources, err = c.collectTokens(ctx)
	case "googleworkspace_privilege":
		result.Resources, err = c.collectPrivileges(ctx)
	case "googleworkspace_calendar":
		result.Resources, err = c.collectCalendars(ctx)
	case "googleworkspace_resource_building":
		result.Resources, err = c.collectResourceBuildings(ctx)
	case "googleworkspace_resource_calendars":
		result.Resources, err = c.collectResourceCalendars(ctx)
	case "googleworkspace_resource_user_feature":
		result.Resources, err = c.collectResourceFeatures(ctx)
	case "googleworkspace_gmail_send_as":
		result.Resources, err = c.collectGmailSendAs(ctx)
	case "googleworkspace_gmail_imap":
		result.Resources, err = c.collectGmailImap(ctx)
	case "googleworkspace_gmail_pop":
		result.Resources, err = c.collectGmailPop(ctx)
	case "googleworkspace_gmail_delegate":
		result.Resources, err = c.collectGmailDelegates(ctx)
	case "googleworkspace_gmail_forwarding_address":
		result.Resources, err = c.collectGmailForwardingAddresses(ctx)
	case "googleworkspace_gmail_label":
		result.Resources, err = c.collectGmailLabels(ctx)
	case "googleworkspace_gmail_filter":
		result.Resources, err = c.collectGmailFilters(ctx)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	if err != nil {
		return nil, err
	}

	result.Total = len(result.Resources)
	c.mu.Lock()
	c.cache[resourceType] = result
	c.mu.Unlock()
	return result, nil
}

// ListResourceTypes lista todos os tipos de recursos suportados.
func (c *GoogleWorkspaceCollector) ListResourceTypes() []ResourceType {
	var resourceTypes []ResourceType
	for _, rt := range googleworkspaceResourceTypes {
		if rt.Provider == "googleworkspace" {
			resourceTypes = append(resourceTypes, rt)
		}
	}
	return resourceTypes
}

// =============================================================================
// Resource Types
// =============================================================================

var googleworkspaceResourceTypes = []ResourceType{
	{Name: "googleworkspace_user", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace users"},
	{Name: "googleworkspace_group", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace groups"},
	{Name: "googleworkspace_domain", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace domains"},
	{Name: "googleworkspace_domain_alias", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace domain aliases"},
	{Name: "googleworkspace_org_unit", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace organizational units"},
	{Name: "googleworkspace_role", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace roles"},
	{Name: "googleworkspace_role_assignment", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace role assignments"},
	{Name: "googleworkspace_mobile_device", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace mobile devices"},
	{Name: "googleworkspace_token", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace OAuth tokens"},
	{Name: "googleworkspace_privilege", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace privileges"},
	{Name: "googleworkspace_calendar", Provider: "googleworkspace", Service: "directory", Description: "Google Workspace user calendars"},
	{Name: "googleworkspace_resource_building", Provider: "googleworkspace", Service: "resources", Description: "Google Workspace resource buildings"},
	{Name: "googleworkspace_resource_calendars", Provider: "googleworkspace", Service: "resources", Description: "Google Workspace resource calendars"},
	{Name: "googleworkspace_resource_user_feature", Provider: "googleworkspace", Service: "resources", Description: "Google Workspace resource features"},
	{Name: "googleworkspace_gmail_send_as", Provider: "googleworkspace", Service: "gmail", Description: "Gmail send-as addresses"},
	{Name: "googleworkspace_gmail_imap", Provider: "googleworkspace", Service: "gmail", Description: "Gmail IMAP settings"},
	{Name: "googleworkspace_gmail_pop", Provider: "googleworkspace", Service: "gmail", Description: "Gmail POP settings"},
	{Name: "googleworkspace_gmail_delegate", Provider: "googleworkspace", Service: "gmail", Description: "Gmail delegates"},
	{Name: "googleworkspace_gmail_forwarding_address", Provider: "googleworkspace", Service: "gmail", Description: "Gmail forwarding addresses"},
	{Name: "googleworkspace_gmail_label", Provider: "googleworkspace", Service: "gmail", Description: "Gmail labels"},
	{Name: "googleworkspace_gmail_filter", Provider: "googleworkspace", Service: "gmail", Description: "Gmail filters"},
	// Placeholder types - require additional API scopes
	{Name: "googleworkspace_drive", Provider: "googleworkspace", Service: "drive", Description: "Google Drive"},
	{Name: "googleworkspace_drive_my_file", Provider: "googleworkspace", Service: "drive", Description: "Google Drive my files"},
	{Name: "googleworkspace_drive_shared_with_me", Provider: "googleworkspace", Service: "drive", Description: "Google Drive shared with me"},
	{Name: "googleworkspace_calendar_event", Provider: "googleworkspace", Service: "calendar", Description: "Google Calendar events"},
	{Name: "googleworkspace_calendar_acl", Provider: "googleworkspace", Service: "calendar", Description: "Google Calendar ACL"},
	{Name: "googleworkspace_chat_space", Provider: "googleworkspace", Service: "chat", Description: "Google Chat spaces"},
	{Name: "googleworkspace_chat_member", Provider: "googleworkspace", Service: "chat", Description: "Google Chat members"},
	{Name: "googleworkspace_chat_message", Provider: "googleworkspace", Service: "chat", Description: "Google Chat messages"},
	{Name: "googleworkspace_meet_conference", Provider: "googleworkspace", Service: "meet", Description: "Google Meet conferences"},
	{Name: "googleworkspace_meet_recording", Provider: "googleworkspace", Service: "meet", Description: "Google Meet recordings"},
	{Name: "googleworkspace_classroom_course", Provider: "googleworkspace", Service: "classroom", Description: "Google Classroom courses"},
	{Name: "googleworkspace_classroom_user", Provider: "googleworkspace", Service: "classroom", Description: "Google Classroom users"},
	{Name: "googleworkspace_classroom_guardian", Provider: "googleworkspace", Service: "classroom", Description: "Google Classroom guardians"},
	{Name: "googleworkspace_site", Provider: "googleworkspace", Service: "sites", Description: "Google Sites"},
}

// =============================================================================
// User & Group Collectors
// =============================================================================

func (c *GoogleWorkspaceCollector) collectUsers(ctx context.Context) ([]Resource, error) {
	users, err := c.provider.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, u := range users {
		resources = append(resources, Resource{
			ID:         u.PrimaryEmail,
			Name:       userFullName(u),
			Type:       "googleworkspace_user",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"is_admin":           u.IsAdmin,
				"is_delegated_admin": u.IsDelegatedAdmin,
				"suspended":          u.Suspended,
				"org_unit_path":      u.OrgUnitPath,
				"creation_time":      u.CreationTime,
				"last_login_time":    u.LastLoginTime,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGroups(ctx context.Context) ([]Resource, error) {
	groups, err := c.provider.ListGroups(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, g := range groups {
		resources = append(resources, Resource{
			ID:         g.Email,
			Name:       g.Name,
			Type:       "googleworkspace_group",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"admin_created": g.AdminCreated,
				"direct_members_count": g.DirectMembersCount,
				"description":   g.Description,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Domain Collectors
// =============================================================================

func (c *GoogleWorkspaceCollector) collectDomains(ctx context.Context) ([]Resource, error) {
	domains, err := c.provider.ListDomains(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, d := range domains {
		resources = append(resources, Resource{
			ID:         d.DomainName,
			Name:       d.DomainName,
			Type:       "googleworkspace_domain",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"is_primary":     d.IsPrimary,
				"verified":       d.Verified,
				"creation_time":  d.CreationTime,
				"domain_aliases": len(d.DomainAliases),
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectDomainAliases(ctx context.Context) ([]Resource, error) {
	aliases, err := c.provider.ListDomainAliases(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, a := range aliases {
		resources = append(resources, Resource{
			ID:         a.DomainAliasName,
			Name:       a.DomainAliasName,
			Type:       "googleworkspace_domain_alias",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"parent_domain_name": a.ParentDomainName,
				"verified":           a.Verified,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Org Unit Collectors
// =============================================================================

func (c *GoogleWorkspaceCollector) collectOrgUnits(ctx context.Context) ([]Resource, error) {
	units, err := c.provider.ListOrgUnits(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, u := range units {
		resources = append(resources, Resource{
			ID:         u.OrgUnitId,
			Name:       u.Name,
			Type:       "googleworkspace_org_unit",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"org_unit_path":        u.OrgUnitPath,
				"parent_org_unit_path": u.ParentOrgUnitPath,
				"block_inheritance":    u.BlockInheritance,
				"description":          u.Description,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Role Collectors
// =============================================================================

func (c *GoogleWorkspaceCollector) collectRoles(ctx context.Context) ([]Resource, error) {
	roles, err := c.provider.ListRoles(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, r := range roles {
		resources = append(resources, Resource{
			ID:         fmt.Sprintf("%d", r.RoleId),
			Name:       r.RoleName,
			Type:       "googleworkspace_role",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"role_description":    r.RoleDescription,
				"is_super_admin_role": r.IsSuperAdminRole,
				"is_system_role":      r.IsSystemRole,
				"privileges_count":    len(r.RolePrivileges),
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectRoleAssignments(ctx context.Context) ([]Resource, error) {
	assignments, err := c.provider.ListRoleAssignments(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ra := range assignments {
		resources = append(resources, Resource{
			ID:         fmt.Sprintf("%d-%s-%s", ra.RoleId, ra.AssignedTo, ra.ScopeType),
			Name:       fmt.Sprintf("role:%d->user:%s", ra.RoleId, ra.AssignedTo),
			Type:       "googleworkspace_role_assignment",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"role_id":     fmt.Sprintf("%d", ra.RoleId),
				"assigned_to": ra.AssignedTo,
				"scope_type":  ra.ScopeType,
				"org_unit_id": ra.OrgUnitId,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Mobile Device Collector
// =============================================================================

func (c *GoogleWorkspaceCollector) collectMobileDevices(ctx context.Context) ([]Resource, error) {
	devices, err := c.provider.ListMobileDevices(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, d := range devices {
		resources = append(resources, Resource{
			ID:         d.DeviceId,
			Name:       mobileDeviceName(d),
			Type:       "googleworkspace_mobile_device",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"email":         strings.Join(d.Email, ","),
				"device_type":   d.Type,
				"os":            d.Os,
				"model":         d.Model,
				"status":        d.Status,
				"brand":         d.Brand,
				"serial_number": d.SerialNumber,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Token Collector
// =============================================================================

func (c *GoogleWorkspaceCollector) collectTokens(ctx context.Context) ([]Resource, error) {
	tokens, err := c.provider.ListTokens(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, t := range tokens {
		resources = append(resources, Resource{
			ID:         fmt.Sprintf("%s-%s", t.UserKey, t.ClientId),
			Name:       fmt.Sprintf("%s (%s)", t.DisplayText, t.ClientId),
			Type:       "googleworkspace_token",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"user_key":     t.UserKey,
				"client_id":    t.ClientId,
				"scopes":       strings.Join(t.Scopes, ","),
				"display_text": t.DisplayText,
				"anonymous":    t.Anonymous,
				"native_app":   t.NativeApp,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Privilege Collector
// =============================================================================

func (c *GoogleWorkspaceCollector) collectPrivileges(ctx context.Context) ([]Resource, error) {
	privileges, err := c.provider.ListPrivileges(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, p := range privileges {
		resources = append(resources, Resource{
			ID:         p.ServiceId,
			Name:       p.ServiceName,
			Type:       "googleworkspace_privilege",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"service_id":        p.ServiceId,
				"service_name":      p.ServiceName,
				"child_privileges":  len(p.ChildPrivileges),
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Calendar Collectors
// =============================================================================

func (c *GoogleWorkspaceCollector) collectCalendars(ctx context.Context) ([]Resource, error) {
	calendars, err := c.provider.ListCalendars(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cal := range calendars {
		resources = append(resources, Resource{
			ID:         cal.ResourceId,
			Name:       cal.ResourceName,
			Type:       "googleworkspace_calendar",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"resource_email":       cal.ResourceEmail,
				"resource_type":        cal.ResourceType,
				"building_id":          cal.BuildingId,
				"resource_description": cal.ResourceDescription,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Resource Buildings Collector
// =============================================================================

func (c *GoogleWorkspaceCollector) collectResourceBuildings(ctx context.Context) ([]Resource, error) {
	buildings, err := c.provider.ListResourceBuildings(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, b := range buildings {
		resources = append(resources, Resource{
			ID:         b.BuildingId,
			Name:       b.BuildingName,
			Type:       "googleworkspace_resource_building",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"description": b.Description,
				"floor_names": strings.Join(b.FloorNames, ","),
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Resource Calendars Collector
// =============================================================================

func (c *GoogleWorkspaceCollector) collectResourceCalendars(ctx context.Context) ([]Resource, error) {
	calendars, err := c.provider.ListResourceCalendars(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cal := range calendars {
		resources = append(resources, Resource{
			ID:         cal.ResourceId,
			Name:       cal.ResourceName,
			Type:       "googleworkspace_resource_calendars",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"resource_email":       cal.ResourceEmail,
				"resource_type":        cal.ResourceType,
				"building_id":          cal.BuildingId,
				"resource_description": cal.ResourceDescription,
			},
		})
	}
	return resources, nil
}

// =============================================================================
// Resource Features Collector
// =============================================================================

func (c *GoogleWorkspaceCollector) collectResourceFeatures(ctx context.Context) ([]Resource, error) {
	features, err := c.provider.ListResourceFeatures(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, f := range features {
		resources = append(resources, Resource{
			ID:         f.Name,
			Name:       f.Name,
			Type:       "googleworkspace_resource_user_feature",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

// =============================================================================
// Gmail Collectors
// =============================================================================

func (c *GoogleWorkspaceCollector) collectGmailSendAs(ctx context.Context) ([]Resource, error) {
	sendAs, err := c.provider.ListGmailSendAs(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, s := range sendAs {
		resources = append(resources, Resource{
			ID:         fmt.Sprintf("%s-%s", s.SendAsEmail, "sendas"),
			Name:       s.DisplayName,
			Type:       "googleworkspace_gmail_send_as",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"send_as_email":       s.SendAsEmail,
				"reply_to_address":    s.ReplyToAddress,
				"is_primary":          s.IsPrimary,
				"treat_as_alias":      s.TreatAsAlias,
				"verification_status": s.VerificationStatus,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGmailImap(ctx context.Context) ([]Resource, error) {
	users, err := c.provider.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, u := range users {
		imap, err := c.provider.GetGmailImap(ctx, u.PrimaryEmail)
		if err != nil {
			continue
		}
		resources = append(resources, Resource{
			ID:         u.PrimaryEmail,
			Name:       u.PrimaryEmail,
			Type:       "googleworkspace_gmail_imap",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"email":            u.PrimaryEmail,
				"enabled":          imap.Enabled,
				"auto_expunge":     imap.AutoExpunge,
				"expunge_behavior": imap.ExpungeBehavior,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGmailPop(ctx context.Context) ([]Resource, error) {
	users, err := c.provider.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, u := range users {
		pop, err := c.provider.GetGmailPop(ctx, u.PrimaryEmail)
		if err != nil {
			continue
		}
		resources = append(resources, Resource{
			ID:         u.PrimaryEmail,
			Name:       u.PrimaryEmail,
			Type:       "googleworkspace_gmail_pop",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"email":         u.PrimaryEmail,
				"access_window": pop.AccessWindow,
				"disposition":   pop.Disposition,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGmailDelegates(ctx context.Context) ([]Resource, error) {
	delegates, err := c.provider.ListGmailDelegates(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, d := range delegates {
		resources = append(resources, Resource{
			ID:         fmt.Sprintf("%s-%s", d.DelegateEmail, "delegate"),
			Name:       d.DelegateEmail,
			Type:       "googleworkspace_gmail_delegate",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"delegate_email":      d.DelegateEmail,
				"verification_status": d.VerificationStatus,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGmailForwardingAddresses(ctx context.Context) ([]Resource, error) {
	addresses, err := c.provider.ListGmailForwardingAddresses(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, a := range addresses {
		resources = append(resources, Resource{
			ID:         fmt.Sprintf("%s-%s", a.ForwardingEmail, "forwarding"),
			Name:       a.ForwardingEmail,
			Type:       "googleworkspace_gmail_forwarding_address",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"forwarding_email":    a.ForwardingEmail,
				"verification_status": a.VerificationStatus,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGmailLabels(ctx context.Context) ([]Resource, error) {
	labels, err := c.provider.ListGmailLabels(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, l := range labels {
		resources = append(resources, Resource{
			ID:         l.Id,
			Name:       l.Name,
			Type:       "googleworkspace_gmail_label",
			Provider:   "googleworkspace",
			Region:     "global",
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"label_list_visibility":   l.LabelListVisibility,
				"message_list_visibility": l.MessageListVisibility,
				"type":                    l.Type,
			},
		})
	}
	return resources, nil
}

func (c *GoogleWorkspaceCollector) collectGmailFilters(ctx context.Context) ([]Resource, error) {
	// Gmail filters require individual per-user API calls not exposed in the current provider
	return []Resource{}, nil
}

// =============================================================================
// Helper functions
// =============================================================================

func userFullName(u *admin.User) string {
	if u.Name != nil {
		return u.Name.FullName
	}
	return u.PrimaryEmail
}

func mobileDeviceName(d *admin.MobileDevice) string {
	if d.Model != "" {
		return d.Model
	}
	if d.DeviceId != "" {
		return d.DeviceId
	}
	return "unknown-device"
}

// adminUserSafe returns a safe string from admin.User field
func adminUserSafe(u *admin.User, field string) string {
	switch field {
	case "primary_email":
		return u.PrimaryEmail
	case "org_unit_path":
		return u.OrgUnitPath
	}
	return ""
}

// gmailDelegateSafe returns a safe string from gmail.Delegate field
func gmailDelegateSafe(d *gmail.Delegate, field string) string {
	switch field {
	case "delegate_email":
		return d.DelegateEmail
	case "verification_status":
		return d.VerificationStatus
	}
	return ""
}

// gmailSendAsSafe returns a safe string from gmail.SendAs field
func gmailSendAsSafe(s *gmail.SendAs, field string) string {
	switch field {
	case "send_as_email":
		return s.SendAsEmail
	case "display_name":
		return s.DisplayName
	case "reply_to_address":
		return s.ReplyToAddress
	case "verification_status":
		return s.VerificationStatus
	}
	return ""
}

// gmailLabelSafe returns a safe string from gmail.Label field
func gmailLabelSafe(l *gmail.Label, field string) string {
	switch field {
	case "name":
		return l.Name
	case "id":
		return l.Id
	}
	return ""
}
