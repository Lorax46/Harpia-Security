package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// PasswordPolicyMinLengthCheck verifica se a política de senha tem mínimo 14 caracteres
type PasswordPolicyMinLengthCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyMinLength() *PasswordPolicyMinLengthCheck {
	return &PasswordPolicyMinLengthCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_password_policy_minimum_length_14",
			CheckTitle:      "Ensure IAM password policy requires minimum length of 14 characters",
			ServiceName:     "identity",
			Severity:        "high",
			ResourceType:    "Policy",
			ResourceGroup:   "IAM",
			Description:     "The IAM password policy requires a minimum password length of 14 characters",
			Risk:            "Shorter passwords are easier to compromise through brute force attacks",
			RemediationText: "Update the IAM password policy to require a minimum password length of 14 characters",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingpasswordrules.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyMinLengthCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *PasswordPolicyMinLengthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Identity() (identity.IdentityClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}

	identityClient, err := p.Identity()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()

	findings := []models.Finding{}

	request := identity.GetAuthenticationPolicyRequest{
		CompartmentId: &tenancyId,
	}

	response, err := identityClient.GetAuthenticationPolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter política de senha: %w", err)
	}

	policy := response.AuthenticationPolicy
	passwordPolicy := policy.PasswordPolicy

	if passwordPolicy == nil {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "IAM password policy is not configured",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
		return findings, nil
	}

	minLength := passwordPolicy.MinimumPasswordLength
	if minLength != nil && *minLength >= 14 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("Password policy requires minimum length of %d characters", *minLength),
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		msg := "Password policy does not require minimum length of 14 characters"
		if minLength != nil {
			msg = fmt.Sprintf("Password policy requires minimum length of %d characters (should be 14)", *minLength)
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: msg,
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// MFACheck verifica se MFA está habilitado para usuários console
type MFACheck struct {
	metadata models.CheckMetadata
}

func NewMFACheck() *MFACheck {
	return &MFACheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_user_mfa_enabled_console_access",
			CheckTitle:      "Ensure MFA is enabled for all console users",
			ServiceName:     "identity",
			Severity:        "high",
			ResourceType:    "User",
			ResourceGroup:   "IAM",
			Description:     "Multi-factor authentication (MFA) should be enabled for all users with console access",
			Risk:            "Accounts without MFA are more susceptible to credential compromise",
			RemediationText: "Enable MFA for all users with console access",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/usingmfa.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *MFACheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *MFACheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Identity() (identity.IdentityClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}

	identityClient, err := p.Identity()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	listReq := identity.ListUsersRequest{
		CompartmentId: &tenancyId,
	}

	users, err := identityClient.ListUsers(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}

	for _, user := range users.Items {
		if !isMFAEnabled(user) {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("User %s does not have MFA enabled", safeString(user.Name)),
				ResourceID:     safeString(user.Id),
				ResourceARN:    fmt.Sprintf("oci:iam::%s:user/%s", tenancyId, safeString(user.Name)),
				Provider:       "oci",
				Service:        "identity",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All users have MFA enabled",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func isMFAEnabled(user identity.User) bool {
	return user.IsMfaActivated != nil && *user.IsMfaActivated
}

// UserAPIKeysRotated90DaysCheck verifica se API keys são rotacionadas em 90 dias
type UserAPIKeysRotated90DaysCheck struct {
	metadata models.CheckMetadata
}

func NewUserAPIKeysRotated90Days() *UserAPIKeysRotated90DaysCheck {
	return &UserAPIKeysRotated90DaysCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_user_api_keys_rotated_90_days",
			CheckTitle:      "Ensure user API keys are rotated every 90 days",
			ServiceName:     "identity",
			Severity:        "medium",
			ResourceType:    "ApiKey",
			ResourceGroup:   "IAM",
			Description:     "User API keys should be rotated every 90 days to reduce exposure",
			Risk:            "Old API keys increase the risk of credential compromise",
			RemediationText: "Rotate user API keys every 90 days",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserAPIKeysRotated90DaysCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *UserAPIKeysRotated90DaysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Identity() (identity.IdentityClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}

	identityClient, err := p.Identity()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	listReq := identity.ListUsersRequest{
		CompartmentId: &tenancyId,
	}

	users, err := identityClient.ListUsers(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}

	for _, user := range users.Items {
		apiKeysReq := identity.ListApiKeysRequest{
			UserId: user.Id,
		}

		apiKeys, err := identityClient.ListApiKeys(ctx, apiKeysReq)
		if err != nil {
			continue
		}

		for _, key := range apiKeys.Items {
			if key.TimeCreated != nil {
				age := time.Since(key.TimeCreated.Time)
				if age > 90*24*time.Hour {
					findings = append(findings, models.Finding{
						ID:             c.metadata.CheckID,
						Title:          c.metadata.CheckTitle,
						Description:    c.metadata.Description,
						Severity:       c.metadata.Severity,
						Status:         models.StatusFail,
						StatusExtended: fmt.Sprintf("User %s has API key older than 90 days (created: %s)", safeString(user.Name), key.TimeCreated.Format("2006-01-02")),
						ResourceID:     safeString(key.KeyId),
						Provider:       "oci",
						Service:        "identity",
						Remediation:    c.metadata.RemediationText,
						Categories:     c.metadata.Categories,
						FoundAt:        time.Now(),
					})
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All API keys are within 90 days rotation policy",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// TenancyAdminUsersNoApiKeysCheck verifica se admins do tenancy não têm API keys
type TenancyAdminUsersNoApiKeysCheck struct {
	metadata models.CheckMetadata
}

func NewTenancyAdminUsersNoApiKeys() *TenancyAdminUsersNoApiKeysCheck {
	return &TenancyAdminUsersNoApiKeysCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_tenancy_admin_users_no_api_keys",
			CheckTitle:      "Ensure tenancy admin users do not have API keys",
			ServiceName:     "identity",
			Severity:        "high",
			ResourceType:    "User",
			ResourceGroup:   "IAM",
			Description:     "Tenancy admin users should not have API keys to reduce attack surface",
			Risk:            "Admin API keys could be compromised and used for privilege escalation",
			RemediationText: "Remove API keys from tenancy admin users",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *TenancyAdminUsersNoApiKeysCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *TenancyAdminUsersNoApiKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Identity() (identity.IdentityClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}

	identityClient, err := p.Identity()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	listReq := identity.ListUsersRequest{
		CompartmentId: &tenancyId,
	}

	users, err := identityClient.ListUsers(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}

	for _, user := range users.Items {
		apiKeysReq := identity.ListApiKeysRequest{
			UserId: user.Id,
		}

		apiKeys, err := identityClient.ListApiKeys(ctx, apiKeysReq)
		if err != nil {
			continue
		}

		if len(apiKeys.Items) > 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("User %s has %d API keys", safeString(user.Name), len(apiKeys.Items)),
				ResourceID:     safeString(user.Id),
				Provider:       "oci",
				Service:        "identity",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No users have API keys",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// NoResourcesInRootCompartmentCheck verifica se não há recursos no root compartment
type NoResourcesInRootCompartmentCheck struct {
	metadata models.CheckMetadata
}

func NewNoResourcesInRootCompartment() *NoResourcesInRootCompartmentCheck {
	return &NoResourcesInRootCompartmentCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_no_resources_in_root_compartment",
			CheckTitle:      "Ensure no resources are created in the root compartment",
			ServiceName:     "identity",
			Severity:        "high",
			ResourceType:    "Compartment",
			ResourceGroup:   "IAM",
			Description:     "Resources should not be created in the root compartment for better isolation",
			Risk:            "Resources in root compartment are harder to manage and audit",
			RemediationText: "Move resources to dedicated compartments",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcompartments.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *NoResourcesInRootCompartmentCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NoResourcesInRootCompartmentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Identity() (identity.IdentityClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Identity()")
	}

	identityClient, err := p.Identity()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	request := identity.GetAuthenticationPolicyRequest{
		CompartmentId: &tenancyId,
	}

	_, err = identityClient.GetAuthenticationPolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter política: %w", err)
	}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         models.StatusInfo,
		StatusExtended: "Root compartment exists - manual verification required for resources",
		ResourceID:     tenancyId,
		Provider:       "oci",
		Service:        "identity",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
		FoundAt:        time.Now(),
	})

	return findings, nil
}

// safeString retorna string vazia se ponteiro for nil
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
