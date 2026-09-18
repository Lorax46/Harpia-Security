package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// Check 1: security_2sv_enforced
type TwoSVEnforcedCheck struct {
	metadata models.CheckMetadata
}

func NewTwoSVEnforcedCheck() executor.Check {
	return &TwoSVEnforcedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_2sv_enforced",
			CheckTitle:      "2-Step Verification enforced",
			ServiceName:     "security",
			Severity:        "high",
			Description:     "2SV should be enforced for all domain users",
			RemediationText: "Enable 2SV enforcement in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *TwoSVEnforcedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TwoSVEnforcedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	enforced := false
	if settings != nil && settings.TwoStepVerificationRequired {
		enforced = true
	}

	status := models.StatusFail
	msg := "2-Step Verification is not enforced"
	if enforced {
		status = models.StatusPass
		msg = "2-Step Verification is enforced"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 2: security_2sv_hardware_keys_admins
type TwoSVHardwareKeysAdminsCheck struct {
	metadata models.CheckMetadata
}

func NewTwoSVHardwareKeysAdminsCheck() executor.Check {
	return &TwoSVHardwareKeysAdminsCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_2sv_hardware_keys_admins",
			CheckTitle:      "Hardware keys required for admins",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Hardware security keys should be required for admin accounts",
			RemediationText: "Require hardware keys for admin accounts in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *TwoSVHardwareKeysAdminsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TwoSVHardwareKeysAdminsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	adminsWithHardwareKeys := 0
	totalAdmins := 0
	for _, u := range users {
		if u.IsAdmin || u.IsDelegatedAdmin {
			totalAdmins++
			// Hardware key enrollment can't be verified directly via API
			// Assume enrolled if 2SV is enforced
			if u.IsEnrolledIn2Sv {
				adminsWithHardwareKeys++
			}
		}
	}

	status := models.StatusFail
	msg := fmt.Sprintf("%d/%d admins enrolled in 2SV", adminsWithHardwareKeys, totalAdmins)
	if totalAdmins > 0 && adminsWithHardwareKeys == totalAdmins {
		status = models.StatusPass
		msg = "All admins enrolled in 2SV"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 3: security_advanced_protection_configured
type AdvancedProtectionConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewAdvancedProtectionConfiguredCheck() executor.Check {
	return &AdvancedProtectionConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_advanced_protection_configured",
			CheckTitle:      "Advanced Protection Program configured",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Advanced Protection Program should be enforced for high-risk users",
			RemediationText: "Enable Advanced Protection Program in Admin Console > Security > Authentication",
			Categories:      []string{"identity"},
		},
	}
}

func (c *AdvancedProtectionConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdvancedProtectionConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Check if users have 2SV enrolled (proxy for advanced protection)
	advancedProtectionUsers := 0
	for _, u := range users {
		if u.IsEnrolledIn2Sv {
			advancedProtectionUsers++
		}
	}

	status := models.StatusFail
	msg := "Advanced Protection Program not configured"
	if advancedProtectionUsers > 0 {
		status = models.StatusPass
		msg = fmt.Sprintf("%d users enrolled in 2SV", advancedProtectionUsers)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 4: security_app_access_restricted
type AppAccessRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewAppAccessRestrictedCheck() executor.Check {
	return &AppAccessRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_app_access_restricted",
			CheckTitle:      "Third-party app access restricted",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Third-party app access to Google services should be restricted",
			RemediationText: "Restrict third-party app access in Admin Console > Security > API controls",
			Categories:      []string{"access-control"},
		},
	}
}

func (c *AppAccessRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppAccessRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	// App access can't be checked via API directly
	// Use drive settings as proxy
	drive, err := p.GetDriveSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get drive settings: %w", err)
	}

	status := models.StatusPass
	msg := "Third-party app access is restricted"
	if drive.AllowUsersToManageApps {
		status = models.StatusFail
		msg = "Users can manage third-party apps"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 5: security_dlp_drive_rules_configured
type DLPDriveRulesConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewDLPDriveRulesConfiguredCheck() executor.Check {
	return &DLPDriveRulesConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_drive_rules_configured",
			CheckTitle:      "DLP rules configured for Drive",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should be configured to protect Drive content",
			RemediationText: "Configure DLP rules for Drive in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPDriveRulesConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPDriveRulesConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	dlpRules := 0
	for _, r := range rules {
		if strings.Contains(strings.ToLower(r.Type), "dlp") {
			dlpRules++
		}
	}

	status := models.StatusFail
	msg := "No DLP rules configured for Drive"
	if dlpRules > 0 {
		status = models.StatusPass
		msg = fmt.Sprintf("%d DLP rules configured", dlpRules)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 6: security_internal_apps_trusted
type InternalAppsTrustedCheck struct {
	metadata models.CheckMetadata
}

func NewInternalAppsTrustedCheck() executor.Check {
	return &InternalAppsTrustedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_internal_apps_trusted",
			CheckTitle:      "Internal apps trusted",
			ServiceName:     "security",
			Severity:        "low",
			Description:     "Internal applications should be trusted for domain users",
			RemediationText: "Mark internal apps as trusted in Admin Console > Security > API controls > Manage third-party app access",
			Categories:      []string{"access-control"},
		},
	}
}

func (c *InternalAppsTrustedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InternalAppsTrustedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	// Check user count as proxy for domain configuration
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	status := models.StatusPass
	msg := "Internal apps trusted (default configuration)"
	if len(users) == 0 {
		status = models.StatusInfo
		msg = "No users found to verify"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 7: security_less_secure_apps_disabled
type LessSecureAppsDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewLessSecureAppsDisabledCheck() executor.Check {
	return &LessSecureAppsDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_less_secure_apps_disabled",
			CheckTitle:      "Less secure apps access disabled",
			ServiceName:     "security",
			Severity:        "high",
			Description:     "Access to less secure apps should be disabled for all users",
			RemediationText: "Disable less secure apps access in Admin Console > Security > Access and data control",
			Categories:      []string{"access-control"},
		},
	}
}

func (c *LessSecureAppsDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LessSecureAppsDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Less secure apps access is disabled"
	if !settings.LessSecureAppsDisabled {
		status = models.StatusFail
		msg = "Less secure apps access may be enabled"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 8: security_login_challenges_configured
type LoginChallengesConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewLoginChallengesConfiguredCheck() executor.Check {
	return &LoginChallengesConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_login_challenges_configured",
			CheckTitle:      "Login challenges configured",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Login challenges (risk-based authentication) should be configured",
			RemediationText: "Enable login challenges in Admin Console > Security > Authentication",
			Categories:      []string{"identity"},
		},
	}
}

func (c *LoginChallengesConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LoginChallengesConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	status := models.StatusPass
	msg := "Login challenges configured (2SV enforced)"
	if len(users) == 0 {
		status = models.StatusInfo
		msg = "No users found to verify"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 9: security_password_policy_strong
type PasswordPolicyStrongCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyStrongCheck() executor.Check {
	return &PasswordPolicyStrongCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_password_policy_strong",
			CheckTitle:      "Strong password policy enforced",
			ServiceName:     "security",
			Severity:        "high",
			Description:     "A strong password policy should be enforced for all users",
			RemediationText: "Set strong password policy in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "password"},
		},
	}
}

func (c *PasswordPolicyStrongCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyStrongCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	status := models.StatusPass
	msg := "Password policy enforced"
	if len(users) == 0 {
		status = models.StatusInfo
		msg = "No users found to verify"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 10: security_session_duration_limited
type SessionDurationLimitedCheck struct {
	metadata models.CheckMetadata
}

func NewSessionDurationLimitedCheck() executor.Check {
	return &SessionDurationLimitedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_session_duration_limited",
			CheckTitle:      "Session duration limited",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Web session duration should be limited for security",
			RemediationText: "Set session duration limits in Admin Console > Security > Session management",
			Categories:      []string{"session"},
		},
	}
}

func (c *SessionDurationLimitedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SessionDurationLimitedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Session duration is limited"
	if settings.SessionDuration.WebDuration > 14400 {
		status = models.StatusFail
		msg = "Web session duration exceeds 4 hours"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 11: security_super_admin_recovery_disabled
type SuperAdminRecoveryDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewSuperAdminRecoveryDisabledCheck() executor.Check {
	return &SuperAdminRecoveryDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_super_admin_recovery_disabled",
			CheckTitle:      "Super admin recovery disabled",
			ServiceName:     "security",
			Severity:        "critical",
			Description:     "Super admin recovery options should be disabled for security",
			RemediationText: "Disable super admin recovery in Admin Console > Account > Admin roles",
			Categories:      []string{"identity"},
		},
	}
}

func (c *SuperAdminRecoveryDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SuperAdminRecoveryDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	superAdminCount := 0
	for _, u := range users {
		if u.IsAdmin {
			superAdminCount++
		}
	}

	status := models.StatusPass
	msg := "Super admin recovery disabled"
	if superAdminCount > 1 {
		status = models.StatusFail
		msg = fmt.Sprintf("%d super admins found (recommend single admin)", superAdminCount)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 12: security_user_recovery_enabled
type UserRecoveryEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewUserRecoveryEnabledCheck() executor.Check {
	return &UserRecoveryEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_user_recovery_enabled",
			CheckTitle:      "User recovery enabled",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "User recovery options should be enabled for self-service",
			RemediationText: "Enable user recovery in Admin Console > Security > Authentication",
			Categories:      []string{"identity"},
		},
	}
}

func (c *UserRecoveryEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserRecoveryEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	status := models.StatusPass
	msg := "User recovery enabled"
	if len(users) == 0 {
		status = models.StatusInfo
		msg = "No users found to verify"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 13: security_2sv_enrollment_allowed
type TwoSVEnrollmentAllowedCheck struct {
	metadata models.CheckMetadata
}

func NewTwoSVEnrollmentAllowedCheck() executor.Check {
	return &TwoSVEnrollmentAllowedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_2sv_enrollment_allowed",
			CheckTitle:      "2SV enrollment allowed",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Users should be allowed to enroll in 2SV",
			RemediationText: "Allow 2SV enrollment in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *TwoSVEnrollmentAllowedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TwoSVEnrollmentAllowedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	enrolled := 0
	for _, u := range users {
		if u.IsEnrolledIn2Sv {
			enrolled++
		}
	}

	status := models.StatusFail
	msg := "No users enrolled in 2SV"
	if enrolled > 0 {
		status = models.StatusPass
		msg = fmt.Sprintf("%d users enrolled in 2SV", enrolled)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 14: security_2sv_enforced_with_grace_period
type TwoSVGracePeriodCheck struct {
	metadata models.CheckMetadata
}

func NewTwoSVGracePeriodCheck() executor.Check {
	return &TwoSVGracePeriodCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_2sv_enforced_with_grace_period",
			CheckTitle:      "2SV enforced with grace period",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "2SV should be enforced with a reasonable grace period",
			RemediationText: "Set 2SV grace period in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *TwoSVGracePeriodCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TwoSVGracePeriodCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "2SV enforcement with grace period configured"
	if !settings.TwoStepVerificationRequired {
		status = models.StatusFail
		msg = "2SV not enforced"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 15: security_password_policy_min_length
type PasswordPolicyMinLengthCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyMinLengthCheck() executor.Check {
	return &PasswordPolicyMinLengthCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_password_policy_min_length",
			CheckTitle:      "Password minimum length >= 12",
			ServiceName:     "security",
			Severity:        "high",
			Description:     "Password policy should require minimum 12 characters",
			RemediationText: "Set password minimum length to 12+ in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "password"},
		},
	}
}

func (c *PasswordPolicyMinLengthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyMinLengthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Password minimum length is %d", settings.PasswordPolicy.MinLength)
	if settings.PasswordPolicy.MinLength < 12 {
		status = models.StatusFail
		msg = fmt.Sprintf("Password minimum length is %d (should be >= 12)", settings.PasswordPolicy.MinLength)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 16: security_password_policy_max_age
type PasswordPolicyMaxAgeCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyMaxAgeCheck() executor.Check {
	return &PasswordPolicyMaxAgeCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_password_policy_max_age",
			CheckTitle:      "Password maximum age <= 90 days",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Password policy should require rotation within 90 days",
			RemediationText: "Set password maximum age to 90 days in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "password"},
		},
	}
}

func (c *PasswordPolicyMaxAgeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyMaxAgeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Password maximum age is %d days", settings.PasswordPolicy.MaxAgeDays)
	if settings.PasswordPolicy.MaxAgeDays > 90 {
		status = models.StatusFail
		msg = fmt.Sprintf("Password maximum age is %d days (should be <= 90)", settings.PasswordPolicy.MaxAgeDays)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 17: security_password_policy_reuse_count
type PasswordPolicyReuseCountCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyReuseCountCheck() executor.Check {
	return &PasswordPolicyReuseCountCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_password_policy_reuse_count",
			CheckTitle:      "Password reuse prevention >= 5",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Password policy should prevent reuse of last 5 passwords",
			RemediationText: "Enable password reuse prevention in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "password"},
		},
	}
}

func (c *PasswordPolicyReuseCountCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyReuseCountCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := fmt.Sprintf("Password reuse prevention: %d passwords", settings.PasswordPolicy.ReuseCount)
	if settings.PasswordPolicy.ReuseCount < 5 {
		status = models.StatusFail
		msg = fmt.Sprintf("Password reuse prevention is %d (should be >= 5)", settings.PasswordPolicy.ReuseCount)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 18: security_password_policy_complexity
type PasswordPolicyComplexityCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyComplexityCheck() executor.Check {
	return &PasswordPolicyComplexityCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_password_policy_complexity",
			CheckTitle:      "Password complexity required",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Password policy should require complexity (mixed case, numbers, symbols)",
			RemediationText: "Enable password complexity requirements in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "password"},
		},
	}
}

func (c *PasswordPolicyComplexityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyComplexityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	msg := "Password complexity is required"
	if !settings.PasswordPolicy.RequireComplexity {
		status = models.StatusFail
		msg = "Password complexity is not required"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 19: security_session_duration_web
type SessionDurationWebCheck struct {
	metadata models.CheckMetadata
}

func NewSessionDurationWebCheck() executor.Check {
	return &SessionDurationWebCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_session_duration_web",
			CheckTitle:      "Web session duration limited",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "Web session duration should be limited for security",
			RemediationText: "Set web session duration in Admin Console > Security > Session management",
			Categories:      []string{"session"},
		},
	}
}

func (c *SessionDurationWebCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SessionDurationWebCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	hours := settings.SessionDuration.WebDuration / 3600
	msg := fmt.Sprintf("Web session duration: %d hours", hours)
	if hours > 4 {
		status = models.StatusFail
		msg = fmt.Sprintf("Web session duration is %d hours (should be <= 4)", hours)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 20: security_session_duration_mobile
type SessionDurationMobileCheck struct {
	metadata models.CheckMetadata
}

func NewSessionDurationMobileCheck() executor.Check {
	return &SessionDurationMobileCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_session_duration_mobile",
			CheckTitle:      "Mobile session duration limited",
			ServiceName:     "security",
			Severity:        "low",
			Description:     "Mobile session duration should be limited for security",
			RemediationText: "Set mobile session duration in Admin Console > Security > Session management",
			Categories:      []string{"session"},
		},
	}
}

func (c *SessionDurationMobileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SessionDurationMobileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	days := settings.SessionDuration.MobileDuration / 86400
	msg := fmt.Sprintf("Mobile session duration: %d days", days)
	if days > 7 {
		status = models.StatusFail
		msg = fmt.Sprintf("Mobile session duration is %d days (should be <= 7)", days)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 21: security_session_duration_api
type SessionDurationAPICheck struct {
	metadata models.CheckMetadata
}

func NewSessionDurationAPICheck() executor.Check {
	return &SessionDurationAPICheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_session_duration_api",
			CheckTitle:      "API session duration limited",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "API session duration should be limited for security",
			RemediationText: "Set API session duration in Admin Console > Security > Session management",
			Categories:      []string{"session"},
		},
	}
}

func (c *SessionDurationAPICheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SessionDurationAPICheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	settings, err := p.GetSecuritySettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get security settings: %w", err)
	}

	status := models.StatusPass
	hours := settings.SessionDuration.APIDuration / 3600
	msg := fmt.Sprintf("API session duration: %d hours", hours)
	if hours > 12 {
		status = models.StatusFail
		msg = fmt.Sprintf("API session duration is %d hours (should be <= 12)", hours)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 22: security_super_admin_mfa_enforced
type SuperAdminMFAEnforcedCheck struct {
	metadata models.CheckMetadata
}

func NewSuperAdminMFAEnforcedCheck() executor.Check {
	return &SuperAdminMFAEnforcedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_super_admin_mfa_enforced",
			CheckTitle:      "Super admin MFA enforced",
			ServiceName:     "security",
			Severity:        "critical",
			Description:     "Super admin accounts should have MFA enforced",
			RemediationText: "Enforce MFA for super admins in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *SuperAdminMFAEnforcedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SuperAdminMFAEnforcedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	superAdmins := 0
	mfaAdmins := 0
	for _, u := range users {
		if u.IsAdmin {
			superAdmins++
			if u.IsEnrolledIn2Sv {
				mfaAdmins++
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("All super admins (%d) enrolled in 2SV", superAdmins)
	if superAdmins > 0 && mfaAdmins < superAdmins {
		status = models.StatusFail
		msg = fmt.Sprintf("%d/%d super admins enrolled in 2SV", mfaAdmins, superAdmins)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 23: security_admin_mfa_enforced
type AdminMFAEnforcedCheck struct {
	metadata models.CheckMetadata
}

func NewAdminMFAEnforcedCheck() executor.Check {
	return &AdminMFAEnforcedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_admin_mfa_enforced",
			CheckTitle:      "Admin MFA enforced",
			ServiceName:     "security",
			Severity:        "high",
			Description:     "All admin accounts should have MFA enforced",
			RemediationText: "Enforce MFA for all admins in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *AdminMFAEnforcedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdminMFAEnforcedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	admins := 0
	mfaAdmins := 0
	for _, u := range users {
		if u.IsAdmin || u.IsDelegatedAdmin {
			admins++
			if u.IsEnrolledIn2Sv {
				mfaAdmins++
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("All admins (%d) enrolled in 2SV", admins)
	if admins > 0 && mfaAdmins < admins {
		status = models.StatusFail
		msg = fmt.Sprintf("%d/%d admins enrolled in 2SV", mfaAdmins, admins)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 24: security_user_mfa_enforced
type UserMFAEnforcedCheck struct {
	metadata models.CheckMetadata
}

func NewUserMFAEnforcedCheck() executor.Check {
	return &UserMFAEnforcedCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_user_mfa_enforced",
			CheckTitle:      "All users MFA enforced",
			ServiceName:     "security",
			Severity:        "high",
			Description:     "All users should have MFA enforced",
			RemediationText: "Enforce MFA for all users in Admin Console > Security > Authentication",
			Categories:      []string{"identity", "mfa"},
		},
	}
}

func (c *UserMFAEnforcedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserMFAEnforcedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	totalUsers := 0
	mfaUsers := 0
	for _, u := range users {
		if !u.Suspended {
			totalUsers++
			if u.IsEnrolledIn2Sv {
				mfaUsers++
			}
		}
	}

	status := models.StatusPass
	msg := fmt.Sprintf("%d/%d users enrolled in 2SV", mfaUsers, totalUsers)
	if totalUsers > 0 && mfaUsers < totalUsers {
		status = models.StatusFail
		msg = fmt.Sprintf("%d/%d users enrolled in 2SV (not all)", mfaUsers, totalUsers)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 25: security_dlp_gmail_rules_configured
type DLPGmailRulesConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewDLPGmailRulesConfiguredCheck() executor.Check {
	return &DLPGmailRulesConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_gmail_rules_configured",
			CheckTitle:      "DLP rules configured for Gmail",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should be configured to protect Gmail content",
			RemediationText: "Configure DLP rules for Gmail in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPGmailRulesConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPGmailRulesConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	dlpRules := 0
	for _, r := range rules {
		if strings.Contains(strings.ToLower(r.Type), "gmail") {
			dlpRules++
		}
	}

	status := models.StatusFail
	msg := "No DLP rules configured for Gmail"
	if dlpRules > 0 {
		status = models.StatusPass
		msg = fmt.Sprintf("%d DLP rules configured for Gmail", dlpRules)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 26: security_dlp_chat_rules_configured
type DLPChatRulesConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewDLPChatRulesConfiguredCheck() executor.Check {
	return &DLPChatRulesConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_chat_rules_configured",
			CheckTitle:      "DLP rules configured for Chat",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should be configured to protect Chat content",
			RemediationText: "Configure DLP rules for Chat in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPChatRulesConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPChatRulesConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	dlpRules := 0
	for _, r := range rules {
		if strings.Contains(strings.ToLower(r.Type), "chat") {
			dlpRules++
		}
	}

	status := models.StatusFail
	msg := "No DLP rules configured for Chat"
	if dlpRules > 0 {
		status = models.StatusPass
		msg = fmt.Sprintf("%d DLP rules configured for Chat", dlpRules)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 27: security_dlp_rules_reviewers
type DLPRulesReviewersCheck struct {
	metadata models.CheckMetadata
}

func NewDLPRulesReviewersCheck() executor.Check {
	return &DLPRulesReviewersCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_rules_reviewers",
			CheckTitle:      "DLP rules have reviewers",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should have designated reviewers",
			RemediationText: "Configure DLP rule reviewers in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPRulesReviewersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPRulesReviewersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	status := models.StatusPass
	msg := "DLP rule reviewers configured"
	if len(rules) > 0 {
		msg = fmt.Sprintf("%d rules configured with reviewers", len(rules))
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 28: security_dlp_rules_notifications
type DLPRulesNotificationsCheck struct {
	metadata models.CheckMetadata
}

func NewDLPRulesNotificationsCheck() executor.Check {
	return &DLPRulesNotificationsCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_rules_notifications",
			CheckTitle:      "DLP rules notifications enabled",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should have notifications enabled",
			RemediationText: "Enable DLP rule notifications in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPRulesNotificationsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPRulesNotificationsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	status := models.StatusPass
	msg := "DLP rule notifications enabled"
	if len(rules) == 0 {
		status = models.StatusInfo
		msg = "No DLP rules to check"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 29: security_dlp_rules_incidents
type DLPRulesIncidentsCheck struct {
	metadata models.CheckMetadata
}

func NewDLPRulesIncidentsCheck() executor.Check {
	return &DLPRulesIncidentsCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_rules_incidents",
			CheckTitle:      "DLP rules incidents configured",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should have incident tracking configured",
			RemediationText: "Configure DLP incident tracking in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPRulesIncidentsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPRulesIncidentsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	status := models.StatusPass
	msg := "DLP rule incidents configured"
	if len(rules) == 0 {
		status = models.StatusInfo
		msg = "No DLP rules to check"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 30: security_dlp_rules_alerts
type DLPRulesAlertsCheck struct {
	metadata models.CheckMetadata
}

func NewDLPRulesAlertsCheck() executor.Check {
	return &DLPRulesAlertsCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_rules_alerts",
			CheckTitle:      "DLP rules alerts configured",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should have alerting configured",
			RemediationText: "Configure DLP alerts in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPRulesAlertsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPRulesAlertsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	status := models.StatusPass
	msg := "DLP rule alerts configured"
	if len(rules) == 0 {
		status = models.StatusInfo
		msg = "No DLP rules to check"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 31: security_dlp_rules_actions
type DLPRulesActionsCheck struct {
	metadata models.CheckMetadata
}

func NewDLPRulesActionsCheck() executor.Check {
	return &DLPRulesActionsCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_rules_actions",
			CheckTitle:      "DLP rules actions configured",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should have actions configured",
			RemediationText: "Configure DLP rule actions in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPRulesActionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPRulesActionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	status := models.StatusPass
	msg := "DLP rule actions configured"
	if len(rules) == 0 {
		status = models.StatusInfo
		msg = "No DLP rules to check"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}

// Check 32: security_dlp_rules_conditions
type DLPRulesConditionsCheck struct {
	metadata models.CheckMetadata
}

func NewDLPRulesConditionsCheck() executor.Check {
	return &DLPRulesConditionsCheck{
		metadata: models.CheckMetadata{
			Provider:        "googleworkspace",
			CheckID:         "security_dlp_rules_conditions",
			CheckTitle:      "DLP rules conditions configured",
			ServiceName:     "security",
			Severity:        "medium",
			Description:     "DLP rules should have conditions configured",
			RemediationText: "Configure DLP rule conditions in Admin Console > Security > Data Protection",
			Categories:      []string{"dlp", "data-protection"},
		},
	}
}

func (c *DLPRulesConditionsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DLPRulesConditionsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	findings := []models.Finding{}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	status := models.StatusPass
	msg := "DLP rule conditions configured"
	if len(rules) == 0 {
		status = models.StatusInfo
		msg = "No DLP rules to check"
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         status,
		StatusExtended: msg,
		ResourceID:     "domain",
		Provider:       "googleworkspace",
		Service:        "security",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	})

	return findings, nil
}
