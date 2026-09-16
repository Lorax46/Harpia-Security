package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

type ociIdentityProvider interface {
	Identity() (identity.IdentityClient, error)
	TenancyId() string
}

func newCheckMetadata(id, title, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider:    "oci",
		CheckID:     id,
		CheckTitle:  title,
		ServiceName: "identity",
		Severity:    severity,
		Categories:  []string{"iam"},
	}
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func daysSinceSDK(t *common.SDKTime) int {
	if t == nil {
		return 0
	}
	return int(time.Since(t.Time).Hours() / 24)
}

func canUseConsole(u identity.User) bool {
	if u.Capabilities != nil && u.Capabilities.CanUseConsolePassword != nil {
		return *u.Capabilities.CanUseConsolePassword
	}
	return false
}

func isMfaActivated(u identity.User) bool {
	return u.IsMfaActivated != nil && *u.IsMfaActivated
}

func timePtr(t common.SDKTime) *common.SDKTime { return &t }

// === PasswordPolicyMinLengthCheck ===
type PasswordPolicyMinLengthCheck struct{ metadata models.CheckMetadata }

func NewPasswordPolicyMinLength() *PasswordPolicyMinLengthCheck {
	md := newCheckMetadata("identity_password_policy_minimum_length_14",
		"Ensure IAM password policy requires minimum length of 14 characters", "high")
	md.Description = "The IAM password policy requires a minimum password length of 14 characters"
	md.RemediationText = "Update the IAM password policy to require a minimum password length of 14 characters"
	return &PasswordPolicyMinLengthCheck{metadata: md}
}

func (c *PasswordPolicyMinLengthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyMinLengthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	request := identity.GetAuthenticationPolicyRequest{CompartmentId: &tenancyId}
	resp, err := idClient.GetAuthenticationPolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter política de senha: %w", err)
	}
	policy := resp.PasswordPolicy
	if policy == nil {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "IAM password policy is not configured",
			Provider: "oci", Service: "identity", Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		}}, nil
	}
	minLen := policy.MinimumPasswordLength
	if minLen != nil && *minLen >= 14 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: fmt.Sprintf("Password policy requires minimum length of %d characters", *minLen),
			Provider: "oci", Service: "identity", Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		}}, nil
	}
	msg := "Password policy minimum length is less than 14 characters"
	if minLen != nil {
		msg = fmt.Sprintf("Password policy minimum length is %d (should be >= 14)", *minLen)
	}
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusFail, StatusExtended: msg,
		Provider: "oci", Service: "identity", Remediation: c.metadata.RemediationText,
		Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === MFACheck ===
type MFACheck struct{ metadata models.CheckMetadata }

func NewMFACheck() *MFACheck {
	md := newCheckMetadata("identity_user_mfa_enabled_console_access",
		"User with console password has MFA enabled for console access", "high")
	md.Description = "Users with console password access should have MFA enabled."
	md.RemediationText = "Enable MFA for all users with console access."
	return &MFACheck{metadata: md}
}

func (c *MFACheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MFACheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	findings := []models.Finding{}
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	for _, user := range users.Items {
		if canUseConsole(user) {
			if isMfaActivated(user) {
				findings = append(findings, passFinding(c.metadata, user.Id, fmt.Sprintf("User %s has MFA enabled", safeString(user.Name))))
			} else {
				findings = append(findings, failFinding(c.metadata, user.Id, fmt.Sprintf("User %s does not have MFA enabled", safeString(user.Name))))
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "No users with console access found"))
	}
	return findings, nil
}

// === UserAPIKeysRotated90DaysCheck ===
type UserAPIKeysRotated90DaysCheck struct{ metadata models.CheckMetadata }

func NewUserAPIKeysRotated90Days() *UserAPIKeysRotated90DaysCheck {
	md := newCheckMetadata("identity_user_api_keys_rotated_90_days",
		"User active API key is rotated within 90 days or less", "medium")
	md.Description = "API keys should be rotated within 90 days."
	md.RemediationText = "Rotate API keys that are older than 90 days."
	return &UserAPIKeysRotated90DaysCheck{metadata: md}
}

func (c *UserAPIKeysRotated90DaysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserAPIKeysRotated90DaysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	findings := []models.Finding{}
	maxAge := time.Now().UTC().Add(-90 * 24 * time.Hour)
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	for _, user := range users.Items {
		keyReq := identity.ListApiKeysRequest{UserId: user.Id}
		keys, err := idClient.ListApiKeys(ctx, keyReq)
		if err != nil {
			continue
		}
		for _, key := range keys.Items {
			if key.TimeCreated.Before(maxAge) {
				findings = append(findings, failFinding(c.metadata, key.KeyId,
					fmt.Sprintf("User %s has API key created %d days ago", safeString(user.Name), daysSinceSDK(key.TimeCreated))))
			} else {
				findings = append(findings, passFinding(c.metadata, key.KeyId,
					fmt.Sprintf("User %s API key %s within 90-day limit", safeString(user.Name), safeString(key.Fingerprint))))
			}
		}
	}
	return findings, nil
}

// === TenancyAdminUsersNoApiKeysCheck ===
type TenancyAdminUsersNoApiKeysCheck struct{ metadata models.CheckMetadata }

func NewTenancyAdminUsersNoApiKeys() *TenancyAdminUsersNoApiKeysCheck {
	md := newCheckMetadata("identity_tenancy_admin_users_no_api_keys",
		"Tenancy administrator user has no API keys", "high")
	md.Description = "Tenancy administrator users should not have API keys."
	md.RemediationText = "Remove API keys from tenancy administrator users."
	return &TenancyAdminUsersNoApiKeysCheck{metadata: md}
}

func (c *TenancyAdminUsersNoApiKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TenancyAdminUsersNoApiKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	findings := []models.Finding{}
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	adminGroupName := "Administrators"
	for _, user := range users.Items {
		membershipsReq := identity.ListUserGroupMembershipsRequest{
			CompartmentId: &tenancyId, UserId: user.Id,
		}
		memberships, err := idClient.ListUserGroupMemberships(ctx, membershipsReq)
		if err != nil {
			continue
		}
		isAdmin := false
		for _, m := range memberships.Items {
			if m.GroupId != nil {
				groupReq := identity.GetGroupRequest{GroupId: m.GroupId}
				group, err := idClient.GetGroup(ctx, groupReq)
				if err == nil && group.Name != nil && *group.Name == adminGroupName {
					isAdmin = true
					break
				}
			}
		}
		if isAdmin {
			keyReq := identity.ListApiKeysRequest{UserId: user.Id}
			keys, err := idClient.ListApiKeys(ctx, keyReq)
			if err != nil {
				continue
			}
			if len(keys.Items) > 0 {
				findings = append(findings, failFinding(c.metadata, user.Id,
					fmt.Sprintf("Admin user %s has %d API key(s)", safeString(user.Name), len(keys.Items))))
			} else {
				findings = append(findings, passFinding(c.metadata, user.Id,
					fmt.Sprintf("Admin user %s has no API keys", safeString(user.Name))))
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "No admin users found"))
	}
	return findings, nil
}

// === NoResourcesInRootCompartmentCheck ===
type NoResourcesInRootCompartmentCheck struct{ metadata models.CheckMetadata }

func NewNoResourcesInRootCompartment() *NoResourcesInRootCompartmentCheck {
	md := newCheckMetadata("identity_no_resources_in_root_compartment",
		"No resources exist in the root compartment", "high")
	md.Description = "Resources should not be created in the root compartment."
	md.RemediationText = "Move resources from root compartment to dedicated compartments."
	return &NoResourcesInRootCompartmentCheck{metadata: md}
}

func (c *NoResourcesInRootCompartmentCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoResourcesInRootCompartmentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListCompartmentsRequest{CompartmentId: &tenancyId}
	resp, err := idClient.ListCompartments(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar compartments: %w", err)
	}
	for _, comp := range resp.Items {
		if comp.Id != nil && *comp.Id != tenancyId && comp.LifecycleState == "ACTIVE" {
			return []models.Finding{{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found non-root compartment %s - resources may exist in root", safeString(comp.Name)),
				ResourceID: safeString(comp.Id), Provider: "oci", Service: "identity",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
			}}, nil
		}
	}
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No non-root compartments found",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityInstancePrincipalUsed ===
type IdentityInstancePrincipalUsed struct{ metadata models.CheckMetadata }

func NewIdentityInstancePrincipalUsed() *IdentityInstancePrincipalUsed {
	md := newCheckMetadata("identity_instance_principal_used",
		"Instance principal authentication is configured for OCI instances", "medium")
	md.Description = "Dynamic groups should be configured with instance principal matching rules."
	md.RemediationText = "Create dynamic groups with instance principal matching rules."
	return &IdentityInstancePrincipalUsed{metadata: md}
}

func (c *IdentityInstancePrincipalUsed) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityInstancePrincipalUsed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListDynamicGroupsRequest{CompartmentId: &tenancyId}
	resp, err := idClient.ListDynamicGroups(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar dynamic groups: %w", err)
	}
	ociResources := []string{"fnfunc", "instance", "autonomousdatabase", "resource.compartment.id"}
	for _, dg := range resp.Items {
		if dg.MatchingRule == nil {
			continue
		}
		matchingRule := strings.ToUpper(*dg.MatchingRule)
		for _, res := range ociResources {
			if strings.Contains(matchingRule, strings.ToUpper(res)) {
				return []models.Finding{{
					ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
					Description: c.metadata.Description, Severity: c.metadata.Severity,
					Status: models.StatusPass, StatusExtended: fmt.Sprintf("Dynamic group %s configured for instance principal", safeString(dg.Name)),
					ResourceID: safeString(dg.Id), Provider: "oci", Service: "identity",
					Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
				}}, nil
			}
		}
	}
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusFail, StatusExtended: "No dynamic groups found with instance principal matching rules",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityIamAdminsCannotUpdateTenancyAdmins ===
type IdentityIamAdminsCannotUpdateTenancyAdmins struct{ metadata models.CheckMetadata }

func NewIdentityIamAdminsCannotUpdateTenancyAdmins() *IdentityIamAdminsCannotUpdateTenancyAdmins {
	md := newCheckMetadata("identity_iam_admins_cannot_update_tenancy_admins",
		"IAM policies restrict non-admins from managing tenancy administrators", "critical")
	md.Description = "IAM policies granting manage/use on groups or users in tenancy must restrict access to the Administrators group."
	md.RemediationText = "Add WHERE clauses to protect Administrators group in tenancy-wide policies."
	return &IdentityIamAdminsCannotUpdateTenancyAdmins{metadata: md}
}

func (c *IdentityIamAdminsCannotUpdateTenancyAdmins) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityIamAdminsCannotUpdateTenancyAdmins) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListPoliciesRequest{CompartmentId: &tenancyId}
	resp, err := idClient.ListPolicies(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar policies: %w", err)
	}
	findings := []models.Finding{}
	for _, policy := range resp.Items {
		if policy.Name != nil {
			name := strings.ToUpper(*policy.Name)
			if name == "TENANT ADMIN POLICY" || name == "PSM-ROOT-POLICY" {
				continue
			}
		}
		for _, stmt := range policy.Statements {
			stmtUpper := strings.ToUpper(stmt)
			if strings.Contains(stmtUpper, "ALLOW GROUP") && strings.Contains(stmtUpper, "TENANCY") &&
				(strings.Contains(stmtUpper, "TO MANAGE") || strings.Contains(stmtUpper, "TO USE")) &&
				(strings.Contains(stmtUpper, "ALL-RESOURCES") || (strings.Contains(stmtUpper, "GROUPS") && strings.Contains(stmtUpper, "USERS"))) {
				parts := strings.Split(strings.ToLower(stmt), "where")
				protected := false
				if len(parts) > 1 {
					whereClause := strings.ReplaceAll(parts[1], " ", "")
					whereClause = strings.ReplaceAll(whereClause, "'", "")
					whereClause = strings.ReplaceAll(whereClause, "\"", "")
					if strings.Contains(whereClause, "target.group.name!=administrators") {
						protected = true
					}
				}
				if !protected {
					findings = append(findings, failFinding(c.metadata, policy.Id,
						fmt.Sprintf("Policy %s allows non-admins to manage tenancy groups/users without Administrators protection", safeString(policy.Name))))
				}
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "No overly broad IAM policies found"))
	}
	return findings, nil
}

// === IdentityNonRootCompartmentExists ===
type IdentityNonRootCompartmentExists struct{ metadata models.CheckMetadata }

func NewIdentityNonRootCompartmentExists() *IdentityNonRootCompartmentExists {
	md := newCheckMetadata("identity_non_root_compartment_exists",
		"Tenancy has at least one active non-root compartment", "high")
	md.Description = "Non-root compartments should exist for organizing resources."
	md.RemediationText = "Create at least one non-root compartment for organizing resources."
	return &IdentityNonRootCompartmentExists{metadata: md}
}

func (c *IdentityNonRootCompartmentExists) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityNonRootCompartmentExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListCompartmentsRequest{
		CompartmentId: &tenancyId,
		AccessLevel:   identity.ListCompartmentsAccessLevelAny,
	}
	resp, err := idClient.ListCompartments(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar compartments: %w", err)
	}
	for _, comp := range resp.Items {
		if comp.Id != nil && *comp.Id != tenancyId && comp.LifecycleState == "ACTIVE" {
			return []models.Finding{{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass, StatusExtended: fmt.Sprintf("Found active non-root compartment %s", safeString(comp.Name)),
				ResourceID: safeString(comp.Id), Provider: "oci", Service: "identity",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
			}}, nil
		}
	}
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusFail, StatusExtended: "No active non-root compartments found",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityPasswordPolicyExpiresWithin365Days ===
type IdentityPasswordPolicyExpiresWithin365Days struct{ metadata models.CheckMetadata }

func NewIdentityPasswordPolicyExpiresWithin365Days() *IdentityPasswordPolicyExpiresWithin365Days {
	md := newCheckMetadata("identity_password_policy_expires_within_365_days",
		"Identity Domain password policy expires passwords within 365 days", "medium")
	md.Description = "Password expiration policies are only available in OCI Identity Domains."
	md.RemediationText = "Enable Identity Domains to configure password expiration."
	return &IdentityPasswordPolicyExpiresWithin365Days{metadata: md}
}

func (c *IdentityPasswordPolicyExpiresWithin365Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityPasswordPolicyExpiresWithin365Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	_, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Legacy IAM password policy does not support password expiration. Identity Domains required for expiration policies.",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityPasswordPolicyPreventsReuse ===
type IdentityPasswordPolicyPreventsReuse struct{ metadata models.CheckMetadata }

func NewIdentityPasswordPolicyPreventsReuse() *IdentityPasswordPolicyPreventsReuse {
	md := newCheckMetadata("identity_password_policy_prevents_reuse",
		"Identity Domain password policy prevents password reuse", "medium")
	md.Description = "Password reuse prevention is only available in OCI Identity Domains."
	md.RemediationText = "Enable Identity Domains to configure password reuse prevention."
	return &IdentityPasswordPolicyPreventsReuse{metadata: md}
}

func (c *IdentityPasswordPolicyPreventsReuse) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityPasswordPolicyPreventsReuse) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	_, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Legacy IAM password policy does not support password history. Identity Domains required for reuse prevention.",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityServiceLevelAdminsExist ===
type IdentityServiceLevelAdminsExist struct{ metadata models.CheckMetadata }

func NewIdentityServiceLevelAdminsExist() *IdentityServiceLevelAdminsExist {
	md := newCheckMetadata("identity_service_level_admins_exist",
		"Identity policy does not grant broad 'manage all-resources' permissions", "high")
	md.Description = "Service-level administrators should be created with permissions limited to specific services."
	md.RemediationText = "Replace 'manage all-resources' with specific service-family permissions."
	return &IdentityServiceLevelAdminsExist{metadata: md}
}

func (c *IdentityServiceLevelAdminsExist) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityServiceLevelAdminsExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListPoliciesRequest{CompartmentId: &tenancyId}
	resp, err := idClient.ListPolicies(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar policies: %w", err)
	}
	for _, policy := range resp.Items {
		if policy.Name != nil && strings.ToUpper(*policy.Name) == "TENANT ADMIN POLICY" {
			continue
		}
		for _, stmt := range policy.Statements {
			stmtUpper := strings.ToUpper(stmt)
			if strings.Contains(stmtUpper, "ALLOW GROUP") && strings.Contains(stmtUpper, "TO MANAGE ALL-RESOURCES") {
				return []models.Finding{{
					ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
					Description: c.metadata.Description, Severity: c.metadata.Severity,
					Status: models.StatusFail, StatusExtended: fmt.Sprintf("Policy %s grants 'manage all-resources'", safeString(policy.Name)),
					ResourceID: safeString(policy.Id), Provider: "oci", Service: "identity",
					Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
				}}, nil
			}
		}
	}
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No overly broad 'manage all-resources' policies found",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityStorageServiceLevelAdminsScoped ===
type IdentityStorageServiceLevelAdminsScoped struct{ metadata models.CheckMetadata }

func NewIdentityStorageServiceLevelAdminsScoped() *IdentityStorageServiceLevelAdminsScoped {
	md := newCheckMetadata("identity_storage_service_level_admins_scoped",
		"OCI IAM storage service-level admin policies exclude delete permissions", "medium")
	md.Description = "Storage service-level admin policies should exclude delete permissions."
	md.RemediationText = "Restrict delete permissions in storage service-level admin policies."
	return &IdentityStorageServiceLevelAdminsScoped{metadata: md}
}

func (c *IdentityStorageServiceLevelAdminsScoped) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityStorageServiceLevelAdminsScoped) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListPoliciesRequest{CompartmentId: &tenancyId}
	resp, err := idClient.ListPolicies(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar policies: %w", err)
	}
	findings := []models.Finding{}
	storageResources := []string{"volume-family", "file-family", "object-family"}
	deletePerms := []string{"VOLUME_DELETE", "VOLUME_BACKUP_DELETE", "FILE_SYSTEM_DELETE", "MOUNT_TARGET_DELETE", "EXPORT_SET_DELETE", "OBJECT_DELETE", "BUCKET_DELETE"}
	for _, policy := range resp.Items {
		for _, stmt := range policy.Statements {
			stmtUpper := strings.ToUpper(stmt)
			for _, res := range storageResources {
				if strings.Contains(stmtUpper, "ALLOW GROUP") && strings.Contains(stmtUpper, "MANAGE") && strings.Contains(stmtUpper, res) {
					whereParts := strings.Split(strings.ToLower(stmt), "where")
					hasDeleteExclusion := false
					if len(whereParts) > 1 {
						whereClause := whereParts[1]
						for _, perm := range deletePerms {
							if strings.Contains(whereClause, strings.ToLower(perm)) {
								hasDeleteExclusion = true
								break
							}
						}
					}
					if !hasDeleteExclusion {
						findings = append(findings, failFinding(c.metadata, policy.Id,
							fmt.Sprintf("Policy %s grants manage on %s without delete exclusions", safeString(policy.Name), res)))
					}
				}
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "No storage admin policies with missing delete exclusions found"))
	}
	return findings, nil
}

// === IdentityTenancyAdminPermissionsLimited ===
type IdentityTenancyAdminPermissionsLimited struct{ metadata models.CheckMetadata }

func NewIdentityTenancyAdminPermissionsLimited() *IdentityTenancyAdminPermissionsLimited {
	md := newCheckMetadata("identity_tenancy_admin_permissions_limited",
		"OCI IAM policy does not grant 'manage all-resources in tenancy' unless Tenant Admin Policy", "critical")
	md.Description = "Only the Tenant Admin Policy should grant 'manage all-resources in tenancy'."
	md.RemediationText = "Remove 'manage all-resources in tenancy' from non-admin policies."
	return &IdentityTenancyAdminPermissionsLimited{metadata: md}
}

func (c *IdentityTenancyAdminPermissionsLimited) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityTenancyAdminPermissionsLimited) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListPoliciesRequest{CompartmentId: &tenancyId}
	resp, err := idClient.ListPolicies(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar policies: %w", err)
	}
	for _, policy := range resp.Items {
		if policy.Name != nil && strings.ToUpper(*policy.Name) == "TENANT ADMIN POLICY" {
			continue
		}
		for _, stmt := range policy.Statements {
			stmtUpper := strings.ToUpper(stmt)
			if strings.Contains(stmtUpper, "ALLOW GROUP") && strings.Contains(stmtUpper, "TO MANAGE ALL-RESOURCES IN TENANCY") {
				return []models.Finding{{
					ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
					Description: c.metadata.Description, Severity: c.metadata.Severity,
					Status: models.StatusFail, StatusExtended: fmt.Sprintf("Policy %s grants 'manage all-resources in tenancy' to non-admin groups", safeString(policy.Name)),
					ResourceID: safeString(policy.Id), Provider: "oci", Service: "identity",
					Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
				}}, nil
			}
		}
	}
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Only Tenant Admin Policy has 'manage all-resources in tenancy'",
		ResourceID: tenancyId, Provider: "oci", Service: "identity",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories, FoundAt: time.Now(),
	}}, nil
}

// === IdentityUserAuthTokensRotated90Days ===
type IdentityUserAuthTokensRotated90Days struct{ metadata models.CheckMetadata }

func NewIdentityUserAuthTokensRotated90Days() *IdentityUserAuthTokensRotated90Days {
	md := newCheckMetadata("identity_user_auth_tokens_rotated_90_days",
		"User auth token age is 90 days or less", "medium")
	md.Description = "Auth tokens should be rotated within 90 days."
	md.RemediationText = "Rotate auth tokens older than 90 days."
	return &IdentityUserAuthTokensRotated90Days{metadata: md}
}

func (c *IdentityUserAuthTokensRotated90Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityUserAuthTokensRotated90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	maxAge := time.Now().UTC().Add(-90 * 24 * time.Hour)
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	findings := []models.Finding{}
	for _, user := range users.Items {
		tokenReq := identity.ListAuthTokensRequest{UserId: user.Id}
		tokens, err := idClient.ListAuthTokens(ctx, tokenReq)
		if err != nil {
			continue
		}
		for _, token := range tokens.Items {
			if token.TimeCreated.Before(maxAge) {
				findings = append(findings, failFinding(c.metadata, token.Id,
					fmt.Sprintf("User %s has auth token created %d days ago", safeString(user.Name), daysSinceSDK(token.TimeCreated))))
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "All auth tokens are within 90-day rotation period"))
	}
	return findings, nil
}

// === IdentityUserCustomerSecretKeysRotated90Days ===
type IdentityUserCustomerSecretKeysRotated90Days struct{ metadata models.CheckMetadata }

func NewIdentityUserCustomerSecretKeysRotated90Days() *IdentityUserCustomerSecretKeysRotated90Days {
	md := newCheckMetadata("identity_user_customer_secret_keys_rotated_90_days",
		"User customer secret key is rotated within 90 days or less", "medium")
	md.Description = "Customer secret keys should be rotated within 90 days."
	md.RemediationText = "Rotate customer secret keys older than 90 days."
	return &IdentityUserCustomerSecretKeysRotated90Days{metadata: md}
}

func (c *IdentityUserCustomerSecretKeysRotated90Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityUserCustomerSecretKeysRotated90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	maxAge := time.Now().UTC().Add(-90 * 24 * time.Hour)
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	findings := []models.Finding{}
	for _, user := range users.Items {
		keyReq := identity.ListCustomerSecretKeysRequest{UserId: user.Id}
		keys, err := idClient.ListCustomerSecretKeys(ctx, keyReq)
		if err != nil {
			continue
		}
		for _, key := range keys.Items {
			if key.TimeCreated.Before(maxAge) {
				findings = append(findings, failFinding(c.metadata, key.Id,
					fmt.Sprintf("User %s has customer secret key created %d days ago", safeString(user.Name), daysSinceSDK(key.TimeCreated))))
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "All customer secret keys are within 90-day rotation period"))
	}
	return findings, nil
}

// === IdentityUserDbPasswordsRotated90Days ===
type IdentityUserDbPasswordsRotated90Days struct{ metadata models.CheckMetadata }

func NewIdentityUserDbPasswordsRotated90Days() *IdentityUserDbPasswordsRotated90Days {
	md := newCheckMetadata("identity_user_db_passwords_rotated_90_days",
		"User IAM database password was created within the last 90 days", "medium")
	md.Description = "Database passwords should be rotated within 90 days."
	md.RemediationText = "Rotate database passwords older than 90 days."
	return &IdentityUserDbPasswordsRotated90Days{metadata: md}
}

func (c *IdentityUserDbPasswordsRotated90Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityUserDbPasswordsRotated90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	maxAge := time.Now().UTC().Add(-90 * 24 * time.Hour)
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	findings := []models.Finding{}
	for _, user := range users.Items {
		dbReq := identity.ListDbCredentialsRequest{UserId: user.Id}
		creds, err := idClient.ListDbCredentials(ctx, dbReq)
		if err != nil {
			continue
		}
		for _, cred := range creds.Items {
			if cred.TimeCreated.Before(maxAge) {
				findings = append(findings, failFinding(c.metadata, cred.Id,
					fmt.Sprintf("User %s has DB password created %d days ago", safeString(user.Name), daysSinceSDK(cred.TimeCreated))))
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, passFinding(c.metadata, &tenancyId, "All DB passwords are within 90-day rotation period"))
	}
	return findings, nil
}

// === IdentityUserValidEmailAddress ===
type IdentityUserValidEmailAddress struct{ metadata models.CheckMetadata }

func NewIdentityUserValidEmailAddress() *IdentityUserValidEmailAddress {
	md := newCheckMetadata("identity_user_valid_email_address",
		"IAM user has a valid email address", "low")
	md.Description = "All IAM users should have a valid email address."
	md.RemediationText = "Add a valid email address to all IAM users."
	return &IdentityUserValidEmailAddress{metadata: md}
}

func (c *IdentityUserValidEmailAddress) Metadata() models.CheckMetadata { return c.metadata }

func (c *IdentityUserValidEmailAddress) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(ociIdentityProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}
	idClient, err := p.Identity()
	if err != nil {
		return nil, err
	}
	tenancyId := p.TenancyId()
	req := identity.ListUsersRequest{CompartmentId: &tenancyId}
	users, err := idClient.ListUsers(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}
	findings := []models.Finding{}
	for _, user := range users.Items {
		email := safeString(user.Email)
		if email == "" {
			findings = append(findings, failFinding(c.metadata, user.Id,
				fmt.Sprintf("User %s has no email address", safeString(user.Name))))
		} else if !strings.Contains(email, "@") {
			findings = append(findings, failFinding(c.metadata, user.Id,
				fmt.Sprintf("User %s has invalid email address: %s", safeString(user.Name), email)))
		} else {
			findings = append(findings, passFinding(c.metadata, user.Id,
				fmt.Sprintf("User %s has valid email address", safeString(user.Name))))
		}
	}
	return findings, nil
}

// === Helpers ===
func passFindingStr(md models.CheckMetadata, resourceID string, statusExtended string) models.Finding {
return models.Finding{
	ID: md.CheckID, Title: md.CheckTitle, Description: md.Description,
	Severity: md.Severity, Status: models.StatusPass, StatusExtended: statusExtended,
	ResourceID: resourceID, Provider: "oci", Service: "identity",
	Remediation: md.RemediationText, Categories: md.Categories, FoundAt: time.Now(),
}
}

func failFindingStr(md models.CheckMetadata, resourceID string, statusExtended string) models.Finding {
return models.Finding{
	ID: md.CheckID, Title: md.CheckTitle, Description: md.Description,
	Severity: md.Severity, Status: models.StatusFail, StatusExtended: statusExtended,
	ResourceID: resourceID, Provider: "oci", Service: "identity",
	Remediation: md.RemediationText, Categories: md.Categories, FoundAt: time.Now(),
}
}

func passFinding(md models.CheckMetadata, resourceID *string, statusExtended string) models.Finding {
return passFindingStr(md, safeString(resourceID), statusExtended)
}

func failFinding(md models.CheckMetadata, resourceID *string, statusExtended string) models.Finding {
return failFindingStr(md, safeString(resourceID), statusExtended)
}
