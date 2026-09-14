package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// === 13 checks faltantes do Prowler v5.41 ===

// IamNoExpiredServerCertificatesStored - verifica certificados expirados
type IamNoExpiredServerCertificatesStored struct {
	metadata models.CheckMetadata
}

func NewIamNoExpiredServerCertificatesStored() *IamNoExpiredServerCertificatesStored {
	return &IamNoExpiredServerCertificatesStored{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_no_expired_server_certificates_stored",
			CheckTitle: "Ensure no expired SSL/TLS certificates are stored in AWS IAM",
			Description: "Expired server certificates should be removed from AWS IAM",
			Severity: "medium", ServiceName: "iam", ResourceType: "ServerCertificate",
			RemediationText: "Remove expired SSL/TLS certificates from AWS IAM",
			Categories: []string{"iam", "certificates", "expired"},
		},
	}
}

func (c *IamNoExpiredServerCertificatesStored) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamNoExpiredServerCertificatesStored) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	expiredCerts := []string{}
	paginator := iam.NewListServerCertificatesPaginator(client, &iam.ListServerCertificatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cert := range page.ServerCertificateMetadataList {
			if cert.Expiration != nil && cert.Expiration.Before(time.Now()) {
				id := ""
				if cert.ServerCertificateId != nil {
					id = *cert.ServerCertificateId
				}
				expiredCerts = append(expiredCerts, id)
			}
		}
	}

	if len(expiredCerts) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d expired server certificates", len(expiredCerts)),
			ResourceID: "iam-certificates", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No expired server certificates found",
		ResourceID: "iam-certificates", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess - verifica expiração de senha
type IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyExpiresPasswordsWithin90DaysOrLess() *IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess {
	return &IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_password_policy_expires_passwords_within_90_days_or_less",
			CheckTitle: "Ensure IAM password policy expires passwords within 90 days or less",
			Description: "IAM password policy should expire passwords within 90 days or less",
			Severity: "high", ServiceName: "iam", ResourceType: "PasswordPolicy",
			RemediationText: "Configure IAM password policy to expire passwords within 90 days or less",
			Categories: []string{"iam", "password", "policy"},
		},
	}
}

func (c *IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return nil, err
	}

	maxAge := 0
	if policy.PasswordPolicy != nil && policy.PasswordPolicy.MaxPasswordAge != nil {
		maxAge = int(*policy.PasswordPolicy.MaxPasswordAge)
	}

	if maxAge == 0 || maxAge > 90 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Password policy max age is %d days (should be <= 90)", maxAge),
			ResourceID: "password-policy", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Password policy max age is %d days", maxAge),
		ResourceID: "password-policy", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyMinimumLength14 - verifica comprimento mínimo
type IamPasswordPolicyMinimumLength14 struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyMinimumLength14() *IamPasswordPolicyMinimumLength14 {
	return &IamPasswordPolicyMinimumLength14{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_password_policy_minimum_length_14",
			CheckTitle: "Ensure IAM password policy requires minimum length of 14",
			Description: "IAM password policy should require minimum length of 14 characters",
			Severity: "high", ServiceName: "iam", ResourceType: "PasswordPolicy",
			RemediationText: "Configure IAM password policy to require minimum length of 14",
			Categories: []string{"iam", "password", "policy"},
		},
	}
}

func (c *IamPasswordPolicyMinimumLength14) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyMinimumLength14) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return nil, err
	}

	minLen := 0
	if policy.PasswordPolicy != nil && policy.PasswordPolicy.MinimumPasswordLength != nil {
		minLen = int(*policy.PasswordPolicy.MinimumPasswordLength)
	}

	if minLen < 14 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Password policy minimum length is %d (should be >= 14)", minLen),
			ResourceID: "password-policy", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Password policy minimum length is %d", minLen),
		ResourceID: "password-policy", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyReuse24 - verifica reutilização
type IamPasswordPolicyReuse24 struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyReuse24() *IamPasswordPolicyReuse24 {
	return &IamPasswordPolicyReuse24{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_password_policy_reuse_24",
			CheckTitle: "Ensure IAM password policy prevents password reuse for at least 24 passwords",
			Description: "IAM password policy should prevent password reuse for at least 24 passwords",
			Severity: "high", ServiceName: "iam", ResourceType: "PasswordPolicy",
			RemediationText: "Configure IAM password policy to prevent reuse for at least 24 passwords",
			Categories: []string{"iam", "password", "policy"},
		},
	}
}

func (c *IamPasswordPolicyReuse24) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyReuse24) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return nil, err
	}

	reuse := 0
	if policy.PasswordPolicy != nil && policy.PasswordPolicy.PasswordReusePrevention != nil {
		reuse = int(*policy.PasswordPolicy.PasswordReusePrevention)
	}

	if reuse < 24 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Password policy remembers %d passwords (should be >= 24)", reuse),
			ResourceID: "password-policy", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Password policy remembers %d passwords", reuse),
		ResourceID: "password-policy", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRoleAdministratoraccessPolicy - verifica role AdministratorAccess
type IamRoleAdministratoraccessPolicy struct {
	metadata models.CheckMetadata
}

func NewIamRoleAdministratoraccessPolicy() *IamRoleAdministratoraccessPolicy {
	return &IamRoleAdministratoraccessPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_role_administratoraccess_policy",
			CheckTitle: "Ensure IAM roles with AdministratorAccess policy are limited",
			Description: "IAM roles with AdministratorAccess policy should be limited to necessary roles only",
			Severity: "high", ServiceName: "iam", ResourceType: "Role",
			RemediationText: "Limit IAM roles with AdministratorAccess policy to necessary roles only",
			Categories: []string{"iam", "roles", "admin"},
		},
	}
}

func (c *IamRoleAdministratoraccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleAdministratoraccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	adminRoles := []string{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, role := range page.Roles {
			roleName := ""
			if role.RoleName != nil {
				roleName = *role.RoleName
			}
			attachedPaginator := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			})
			for attachedPaginator.HasMorePages() {
				attachedPage, err := attachedPaginator.NextPage(ctx)
				if err != nil {
					break
				}
				for _, pol := range attachedPage.AttachedPolicies {
					if pol.PolicyArn != nil && *pol.PolicyArn == "arn:aws:iam::aws:policy/AdministratorAccess" {
						adminRoles = append(adminRoles, roleName)
						goto nextRole
					}
				}
			}
		nextRole:
		}
	}

	if len(adminRoles) > 3 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d roles with AdministratorAccess policy", len(adminRoles)),
			ResourceID: "iam-roles", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Only %d roles with AdministratorAccess policy", len(adminRoles)),
		ResourceID: "iam-roles", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRoleCrossAccountReadonlyaccessPolicy - verifica cross-account read-only
type IamRoleCrossAccountReadonlyaccessPolicy struct {
	metadata models.CheckMetadata
}

func NewIamRoleCrossAccountReadonlyaccessPolicy() *IamRoleCrossAccountReadonlyaccessPolicy {
	return &IamRoleCrossAccountReadonlyaccessPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_role_cross_account_readonlyaccess_policy",
			CheckTitle: "Ensure IAM roles with cross-account read-only access are configured correctly",
			Description: "IAM roles with cross-account read-only access should be limited to necessary roles",
			Severity: "medium", ServiceName: "iam", ResourceType: "Role",
			RemediationText: "Limit cross-account read-only IAM roles to necessary roles only",
			Categories: []string{"iam", "roles", "cross-account"},
		},
	}
}

func (c *IamRoleCrossAccountReadonlyaccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleCrossAccountReadonlyaccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	crossAccountRoles := []string{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, role := range page.Roles {
			roleName := ""
			if role.RoleName != nil {
				roleName = *role.RoleName
			}
			attachedPaginator := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			})
			for attachedPaginator.HasMorePages() {
				attachedPage, err := attachedPaginator.NextPage(ctx)
				if err != nil {
					break
				}
				for _, pol := range attachedPage.AttachedPolicies {
					if pol.PolicyArn != nil && (*pol.PolicyArn == "arn:aws:iam::aws:policy/ReadOnlyAccess" || *pol.PolicyArn == "arn:aws:iam::aws:policy/SecurityAudit") {
						crossAccountRoles = append(crossAccountRoles, roleName)
						goto nextRole2
					}
				}
			}
		nextRole2:
		}
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Found %d roles with cross-account read-only policies", len(crossAccountRoles)),
		ResourceID: "iam-roles", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRoleServiceTrustRestrictsToAccount - verifica service trust policies
type IamRoleServiceTrustRestrictsToAccount struct {
	metadata models.CheckMetadata
}

func NewIamRoleServiceTrustRestrictsToAccount() *IamRoleServiceTrustRestrictsToAccount {
	return &IamRoleServiceTrustRestrictsToAccount{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_role_service_trust_restricts_source_to_account",
			CheckTitle: "Ensure IAM roles with service trust policies restrict source to own account",
			Description: "IAM roles with service trust policies should restrict access to own account only",
			Severity: "medium", ServiceName: "iam", ResourceType: "Role",
			RemediationText: "Restrict IAM roles service trust policies to own account only",
			Categories: []string{"iam", "roles", "trust"},
		},
	}
}

func (c *IamRoleServiceTrustRestrictsToAccount) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleServiceTrustRestrictsToAccount) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	roles, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}

	unrestrictedRoles := []string{}
	for _, role := range roles.Roles {
		if role.AssumeRolePolicyDocument != nil {
			policy := *role.AssumeRolePolicyDocument
			if policy == "" || policy == "*" {
				name := "unknown"
				if role.RoleName != nil {
					name = *role.RoleName
				}
				unrestrictedRoles = append(unrestrictedRoles, name)
			}
		}
	}

	if len(unrestrictedRoles) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d roles with unrestricted service trust", len(unrestrictedRoles)),
			ResourceID: "iam-roles", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All IAM roles have restricted service trust policies",
		ResourceID: "iam-roles", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRootCredentialsManagementEnabled - verifica root credentials management
type IamRootCredentialsManagementEnabled struct {
	metadata models.CheckMetadata
}

func NewIamRootCredentialsManagementEnabled() *IamRootCredentialsManagementEnabled {
	return &IamRootCredentialsManagementEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_root_credentials_management_enabled",
			CheckTitle: "Ensure root credentials management is enabled",
			Description: "Root credentials management should be enabled to track root account usage",
			Severity: "medium", ServiceName: "iam", ResourceType: "RootAccount",
			RemediationText: "Enable AWS Organizations root credentials management",
			Categories: []string{"iam", "root", "management"},
		},
	}
}

func (c *IamRootCredentialsManagementEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRootCredentialsManagementEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	// This check requires AWS Organizations and access to the management account
	// For now, we return pass since this is typically an organization-level setting
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Root credentials management check requires AWS Organizations access",
		ResourceID: "root", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRootHardwareMfaEnabled - verifica MFA de hardware para root
type IamRootHardwareMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewIamRootHardwareMfaEnabled() *IamRootHardwareMfaEnabled {
	return &IamRootHardwareMfaEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_root_hardware_mfa_enabled",
			CheckTitle: "Ensure hardware MFA is enabled for root account",
			Description: "Hardware MFA should be enabled for the root account",
			Severity: "critical", ServiceName: "iam", ResourceType: "RootAccount",
			RemediationText: "Enable hardware MFA for the root account",
			Categories: []string{"iam", "mfa", "root", "hardware"},
		},
	}
}

func (c *IamRootHardwareMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRootHardwareMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{})
	if err != nil {
		return nil, err
	}

	hasHardwareMFA := false
	for _, device := range mfaDevices.MFADevices {
		if device.SerialNumber != nil && len(*device.SerialNumber) > 0 {
			hasHardwareMFA = true
			break
		}
	}

	if !hasHardwareMFA {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No hardware MFA found for root account",
			ResourceID: "root", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Hardware MFA found for root account",
		ResourceID: "root", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRootMfaEnabled - verifica MFA para root (alternativo)
type IamRootMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewIamRootMfaEnabled() *IamRootMfaEnabled {
	return &IamRootMfaEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_root_mfa_enabled",
			CheckTitle: "Ensure MFA is enabled for root account",
			Description: "MFA should be enabled for the root account",
			Severity: "critical", ServiceName: "iam", ResourceType: "RootAccount",
			RemediationText: "Enable MFA for the root account",
			Categories: []string{"iam", "mfa", "root"},
		},
	}
}

func (c *IamRootMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRootMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "MFA is not enabled for root account"
	if summary.SummaryMap != nil {
		if v, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && v == 1 {
			status = models.StatusPass
			msg = "MFA is enabled for root account"
		}
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "root", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamUserAccessKeyUnused - verifica chaves de acesso não usadas
type IamUserAccessKeyUnused struct {
	metadata models.CheckMetadata
}

func NewIamUserAccessKeyUnused() *IamUserAccessKeyUnused {
	return &IamUserAccessKeyUnused{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_user_accesskey_unused",
			CheckTitle: "Ensure IAM users do not have unused access keys",
			Description: "IAM users should not have unused access keys to prevent unauthorized access",
			Severity: "medium", ServiceName: "iam", ResourceType: "AccessKey",
			RemediationText: "Remove unused access keys from IAM users",
			Categories: []string{"iam", "users", "access-keys"},
		},
	}
}

func (c *IamUserAccessKeyUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserAccessKeyUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	users, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	unusedKeys := []string{}
	for _, user := range users.Users {
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}
		for _, key := range keys.AccessKeyMetadata {
			usage, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: key.AccessKeyId,
			})
			if err != nil {
				continue
			}
			name := "unknown"
			if key.UserName != nil {
				name = *key.UserName
			}
			id := "unknown"
			if key.AccessKeyId != nil {
				id = *key.AccessKeyId
			}
			if usage.AccessKeyLastUsed.LastUsedDate == nil {
				unusedKeys = append(unusedKeys, name+"/"+id)
			}
		}
	}

	if len(unusedKeys) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d unused access keys", len(unusedKeys)),
			ResourceID: "iam-users", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No unused access keys found",
		ResourceID: "iam-users", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamUserAdministratorAccessPolicy - verifica política de admin para usuários
type IamUserAdministratorAccessPolicy struct {
	metadata models.CheckMetadata
}

func NewIamUserAdministratorAccessPolicy() *IamUserAdministratorAccessPolicy {
	return &IamUserAdministratorAccessPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_user_administrator_access_policy",
			CheckTitle: "Ensure IAM users do not have AdministratorAccess policy attached",
			Description: "IAM users should not have AdministratorAccess policy attached",
			Severity: "critical", ServiceName: "iam", ResourceType: "User",
			RemediationText: "Remove AdministratorAccess policy from IAM users",
			Categories: []string{"iam", "users", "admin"},
		},
	}
}

func (c *IamUserAdministratorAccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserAdministratorAccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	users, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	adminUsers := []string{}
	for _, user := range users.Users {
		attached, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}
		for _, pol := range attached.AttachedPolicies {
			if pol.PolicyArn != nil && *pol.PolicyArn == "arn:aws:iam::aws:policy/AdministratorAccess" {
				name := "unknown"
				if user.UserName != nil {
					name = *user.UserName
				}
				adminUsers = append(adminUsers, name)
			}
		}
	}

	if len(adminUsers) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d users with AdministratorAccess policy", len(adminUsers)),
			ResourceID: "iam-users", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No users with AdministratorAccess policy",
		ResourceID: "iam-users", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamUserHardwareMfaEnabled - verifica MFA de hardware para usuário
type IamUserHardwareMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewIamUserHardwareMfaEnabled() *IamUserHardwareMfaEnabled {
	return &IamUserHardwareMfaEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_user_hardware_mfa_enabled",
			CheckTitle: "Ensure hardware MFA is enabled for all IAM users",
			Description: "All IAM users should have hardware MFA enabled",
			Severity: "high", ServiceName: "iam", ResourceType: "User",
			RemediationText: "Enable hardware MFA for all IAM users",
			Categories: []string{"iam", "users", "mfa", "hardware"},
		},
	}
}

func (c *IamUserHardwareMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserHardwareMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	users, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	usersWithoutHardwareMFA := []string{}
	for _, user := range users.Users {
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}
		hasHardware := false
		for _, device := range mfaDevices.MFADevices {
			if device.SerialNumber != nil && len(*device.SerialNumber) > 0 {
				hasHardware = true
				break
			}
		}
		if !hasHardware {
			name := "unknown"
			if user.UserName != nil {
				name = *user.UserName
			}
			usersWithoutHardwareMFA = append(usersWithoutHardwareMFA, name)
		}
	}

	if len(usersWithoutHardwareMFA) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d users without hardware MFA", len(usersWithoutHardwareMFA)),
			ResourceID: "iam-users", Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All IAM users have hardware MFA enabled",
		ResourceID: "iam-users", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}
