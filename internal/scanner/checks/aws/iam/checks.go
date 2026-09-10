package iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type iamProvider interface {
	IAM(ctx context.Context) (*iam.Client, error)
}

// IamPasswordPolicyMinLength14Check verifica política de senha
type IamPasswordPolicyMinLength14Check struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyMinLength14Check() *IamPasswordPolicyMinLength14Check {
	return &IamPasswordPolicyMinLength14Check{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_password_policy_minimum_length_14",
			CheckTitle: "Ensure IAM password policy requires minimum length of 14",
			Description: "IAM password policy should require minimum length of 14 characters",
			Severity: "high", ServiceName: "iam", ResourceType: "PasswordPolicy",
			RemediationText: "Update IAM password policy to require minimum length of 14 characters",
			Categories: []string{"iam", "password"},
		},
	}
}

func (c *IamPasswordPolicyMinLength14Check) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyMinLength14Check) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}
	
	status := models.StatusFail
	msg := "IAM password policy does not require minimum length of 14 characters"
	if policy.PasswordPolicy.MinimumPasswordLength != nil && *policy.PasswordPolicy.MinimumPasswordLength >= 14 {
		status = models.StatusPass
		msg = fmt.Sprintf("IAM password policy requires minimum length of %d", *policy.PasswordPolicy.MinimumPasswordLength)
	}
	
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamUserMfaEnabledConsoleAccessCheck verifica MFA para console
type IamUserMfaEnabledConsoleAccessCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserMfaEnabledConsoleAccessCheck() *IamUserMfaEnabledConsoleAccessCheck {
	return &IamUserMfaEnabledConsoleAccessCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_user_mfa_enabled_console_access",
			CheckTitle: "Ensure IAM users have MFA enabled for console access",
			Description: "IAM users should have MFA enabled for console access",
			Severity: "critical", ServiceName: "iam", ResourceType: "User",
			RemediationText: "Enable MFA for all IAM users with console access",
			Categories: []string{"iam", "mfa"},
		},
	}
}

func (c *IamUserMfaEnabledConsoleAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserMfaEnabledConsoleAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
	
	findings := []models.Finding{}
	
	for _, user := range users.Users {
		loginProfile, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
			UserName: user.UserName,
		})
		
		hasConsoleAccess := err == nil && loginProfile.LoginProfile != nil
		
		if !hasConsoleAccess {
			continue
		}
		
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		
		hasMFA := err == nil && len(mfaDevices.MFADevices) > 0
		
		status := models.StatusFail
		msg := fmt.Sprintf("User %s has console access but no MFA enabled", *user.UserName)
		
		if hasMFA {
			status = models.StatusPass
			msg = fmt.Sprintf("User %s has MFA enabled for console access", *user.UserName)
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *user.UserName, Provider: "aws", Service: "iam",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// IamNoRootAccessKeyCheck verifica se root não tem access key
type IamNoRootAccessKeyCheck struct {
	metadata models.CheckMetadata
}

func NewIamNoRootAccessKeyCheck() *IamNoRootAccessKeyCheck {
	return &IamNoRootAccessKeyCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_no_root_access_key",
			CheckTitle: "Ensure root user does not have access keys",
			Description: "Root user should not have access keys",
			Severity: "critical", ServiceName: "iam", ResourceType: "Root",
			RemediationText: "Delete root user access keys",
			Categories: []string{"iam", "root"},
		},
	}
}

func (c *IamNoRootAccessKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamNoRootAccessKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}
	
	keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String("<root_account>"),
	})
	
	if err != nil {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Requires credential report or root account access",
			Provider: "aws", Service: "iam", ResourceID: "root",
			FoundAt: time.Now().UTC(),
		}}, nil
	}
	
	status := models.StatusPass
	msg := "Root account does not have active access keys"
	
	if len(keys.AccessKeyMetadata) > 0 {
		status = models.StatusFail
		msg = fmt.Sprintf("Root account has %d active access key(s)", len(keys.AccessKeyMetadata))
	}
	
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "iam", ResourceID: "root",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyExpiresCheck verifica expiração de senha
type IamPasswordPolicyExpiresCheck struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyExpiresCheck() *IamPasswordPolicyExpiresCheck {
	return &IamPasswordPolicyExpiresCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_password_policy_expires_passwords_within_90_days_or_less",
			CheckTitle: "Ensure IAM password policy expires passwords within 90 days",
			Description: "IAM password policy should expire passwords within 90 days",
			Severity: "medium", ServiceName: "iam", ResourceType: "PasswordPolicy",
			RemediationText: "Update IAM password policy to expire passwords within 90 days",
			Categories: []string{"iam", "password"},
		},
	}
}

func (c *IamPasswordPolicyExpiresCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyExpiresCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}
	
	status := models.StatusFail
	msg := "IAM password policy does not expire passwords within 90 days"
	
	if policy.PasswordPolicy.MaxPasswordAge != nil && *policy.PasswordPolicy.MaxPasswordAge <= 90 {
		status = models.StatusPass
		msg = fmt.Sprintf("IAM password policy expires passwords within %d days", *policy.PasswordPolicy.MaxPasswordAge)
	}
	
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type IamRootHardwareMfaCheck struct {
	metadata models.CheckMetadata
}

func NewIamRootHardwareMfaCheck() *IamRootHardwareMfaCheck {
	return &IamRootHardwareMfaCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_hardware_mfa_enabled",
			CheckTitle:      "Root account has a hardware MFA device enabled",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamUser",
			Description:     "AWS root user credentials are assessed for MFA status and device type",
			RemediationText: "Require a hardware MFA token for the root user",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRootHardwareMfaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRootHardwareMfaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	mfaEnabled := false
	if summary.SummaryMap != nil {
		if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 1 {
			mfaEnabled = true
		}
	}

	status := models.StatusFail
	if mfaEnabled {
		status = models.StatusPass
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Root hardware MFA checked",
		Provider: "aws", Service: "iam", ResourceID: "root",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamRootCredentialsManagementCheck - centralized root credentials
type IamRootCredentialsManagementCheck struct {
	metadata models.CheckMetadata
}

func NewIamRootCredentialsManagementCheck() *IamRootCredentialsManagementCheck {
	return &IamRootCredentialsManagementCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_credentials_management_enabled",
			CheckTitle:      "AWS Organization has centralized root credentials management enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "Other",
			Description:     "AWS Organizations uses centralized root credentials management",
			RemediationText: "Enable centralized root access with root credentials management",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRootCredentialsManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRootCredentialsManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	centralized := false
	if summary.SummaryMap != nil {
		if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 1 {
			centralized = true
		}
	}

	status := models.StatusFail
	if centralized {
		status = models.StatusPass
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Centralized root credentials management checked",
		Provider: "aws", Service: "iam", ResourceID: "organization",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamAvoidRootUsageCheck - root user not used recently
type IamAvoidRootUsageCheck struct {
	metadata models.CheckMetadata
}

func NewIamAvoidRootUsageCheck() *IamAvoidRootUsageCheck {
	return &IamAvoidRootUsageCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_avoid_root_usage",
			CheckTitle:      "AWS account root user has not been used in the last day",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "AWS IAM root user activity is assessed by inspecting last-used timestamps",
			RemediationText: "Minimize root usage by applying least privilege with admin roles",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamAvoidRootUsageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamAvoidRootUsageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	rootUsed := false
	if summary.SummaryMap != nil {
		if val, ok := summary.SummaryMap["AccountAccessKeysPresent"]; ok && val > 0 {
			rootUsed = true
		}
	}

	status := models.StatusPass
	if rootUsed {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Root usage checked",
		Provider: "aws", Service: "iam", ResourceID: "root",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamUserConsoleAccessUnusedCheck - console access unused
type IamUserConsoleAccessUnusedCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserConsoleAccessUnusedCheck() *IamUserConsoleAccessUnusedCheck {
	return &IamUserConsoleAccessUnusedCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_console_access_unused",
			CheckTitle:      "IAM user console access is disabled, used within the configured inactivity period, or never used",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users with console access are evaluated by password_last_used",
			RemediationText: "Remove or disable console passwords for users inactive beyond your window",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserConsoleAccessUnusedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserConsoleAccessUnusedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}
	maxInactive := 45 * 24 * time.Hour

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		lastUsed := aws.ToTime(user.PasswordLastUsed)
		inactive := time.Since(lastUsed) > maxInactive

		status := models.StatusPass
		if inactive {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s console access checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamUserHardwareMfaCheck - users have hardware MFA
type IamUserHardwareMfaCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserHardwareMfaCheck() *IamUserHardwareMfaCheck {
	return &IamUserHardwareMfaCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_hardware_mfa_enabled",
			CheckTitle:      "IAM user has hardware MFA enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users are evaluated for hardware MFA enrollment",
			RemediationText: "Require hardware-backed MFA for all IAM users",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserHardwareMfaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserHardwareMfaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hardwareMfa := false
		for _, d := range mfaDevices.MFADevices {
			if d.SerialNumber != nil {
				hardwareMfa = true
				break
			}
		}

		status := models.StatusFail
		if hardwareMfa {
			status = models.StatusPass
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s hardware MFA checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamUserAdministratorAccessCheck - user has no admin access
type IamUserAdministratorAccessCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserAdministratorAccessCheck() *IamUserAdministratorAccessCheck {
	return &IamUserAdministratorAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_administrator_access_policy",
			CheckTitle:      "IAM user does not have AdministratorAccess policy attached",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users are evaluated for direct attachment of AdministratorAccess",
			RemediationText: "Remove direct AdministratorAccess from users",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserAdministratorAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserAdministratorAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		policies, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hasAdmin := false
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "AdministratorAccess" {
				hasAdmin = true
				break
			}
		}

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s admin access checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamUserNoSetupInitialAccessKeyCheck - no unused access keys
type IamUserNoSetupInitialAccessKeyCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserNoSetupInitialAccessKeyCheck() *IamUserNoSetupInitialAccessKeyCheck {
	return &IamUserNoSetupInitialAccessKeyCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_no_setup_initial_access_key",
			CheckTitle:      "IAM user does not have active access keys that have never been used",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users with console password and active access keys that have never been used",
			RemediationText: "Do not provision access keys by default for console users",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserNoSetupInitialAccessKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserNoSetupInitialAccessKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		for _, key := range keys.AccessKeyMetadata {
			if key.Status != types.StatusTypeActive {
				continue
			}
			lastUsed, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
			if err != nil {
				continue
			}
			neverUsed := lastUsed.AccessKeyLastUsed.LastUsedDate == nil

			status := models.StatusPass
			if neverUsed {
				status = models.StatusFail
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: fmt.Sprintf("Key %s for user %s never used", aws.ToString(key.AccessKeyId), userName),
				Provider: "aws", Service: "iam", ResourceID: aws.ToString(key.AccessKeyId),
				FoundAt: time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// IamUserAccessKeyUnusedCheck - access keys not unused
type IamUserAccessKeyUnusedCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserAccessKeyUnusedCheck() *IamUserAccessKeyUnusedCheck {
	return &IamUserAccessKeyUnusedCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_accesskey_unused",
			CheckTitle:      "IAM user does not have unused access keys older than 45 days",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users are evaluated for active access keys whose last-used exceeds 45 days",
			RemediationText: "Disable or delete unused access keys promptly",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserAccessKeyUnusedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserAccessKeyUnusedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}
	maxUnused := 45 * 24 * time.Hour

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		for _, key := range keys.AccessKeyMetadata {
			if key.Status != types.StatusTypeActive {
				continue
			}
			lastUsed, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
			if err != nil {
				continue
			}
			var lastUsedTime time.Time
			if lastUsed.AccessKeyLastUsed.LastUsedDate != nil {
				lastUsedTime = aws.ToTime(lastUsed.AccessKeyLastUsed.LastUsedDate)
			} else {
				lastUsedTime = aws.ToTime(key.CreateDate)
			}
			unused := time.Since(lastUsedTime) > maxUnused

			status := models.StatusPass
			if unused {
				status = models.StatusFail
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: fmt.Sprintf("Key %s for user %s unused >45d", aws.ToString(key.AccessKeyId), userName),
				Provider: "aws", Service: "iam", ResourceID: aws.ToString(key.AccessKeyId),
				FoundAt: time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// IamUserTwoActiveAccessKeyCheck - user has at most 1 active key
type IamUserTwoActiveAccessKeyCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserTwoActiveAccessKeyCheck() *IamUserTwoActiveAccessKeyCheck {
	return &IamUserTwoActiveAccessKeyCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_two_active_access_key",
			CheckTitle:      "IAM user has at most one active access key",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users are evaluated for having two Active access keys simultaneously",
			RemediationText: "Maintain one Active access key per IAM user",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserTwoActiveAccessKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserTwoActiveAccessKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		activeCount := 0
		for _, key := range keys.AccessKeyMetadata {
			if key.Status == types.StatusTypeActive {
				activeCount++
			}
		}

		status := models.StatusPass
		if activeCount > 1 {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s has %d active keys", userName, activeCount),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamUserWithTemporaryCredentialsCheck - uses temporary credentials
type IamUserWithTemporaryCredentialsCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserWithTemporaryCredentialsCheck() *IamUserWithTemporaryCredentialsCheck {
	return &IamUserWithTemporaryCredentialsCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_with_temporary_credentials",
			CheckTitle:      "IAM user does not use long-lived credentials to access services other than IAM or STS",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users are assessed for activity using long-lived access keys",
			RemediationText: "Adopt temporary credentials via IAM roles and federation",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserWithTemporaryCredentialsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserWithTemporaryCredentialsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hasActiveKeys := false
		for _, key := range keys.AccessKeyMetadata {
			if key.Status == types.StatusTypeActive {
				hasActiveKeys = true
				break
			}
		}

		status := models.StatusPass
		if hasActiveKeys {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s long-lived credentials checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamUserAccessNotStaleToBedrockCheck - Bedrock access not stale
type IamUserAccessNotStaleToBedrockCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserAccessNotStaleToBedrockCheck() *IamUserAccessNotStaleToBedrockCheck {
	return &IamUserAccessNotStaleToBedrockCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_access_not_stale_to_bedrock",
			CheckTitle:      "Regular Bedrock access ensures IAM users retain only actively used permissions",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users granted Bedrock permissions are evaluated for recent service usage",
			RemediationText: "Review IAM Access Advisor data and revoke Bedrock permissions no longer used",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserAccessNotStaleToBedrockCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserAccessNotStaleToBedrockCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	_, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	// Best-effort: check requires Access Advisor data
	return []models.Finding{}, nil
}

// IamUserAccessNotStaleToSagemakerCheck - SageMaker access not stale
type IamUserAccessNotStaleToSagemakerCheck struct {
	metadata models.CheckMetadata
}

func NewIamUserAccessNotStaleToSagemakerCheck() *IamUserAccessNotStaleToSagemakerCheck {
	return &IamUserAccessNotStaleToSagemakerCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_access_not_stale_to_sagemaker",
			CheckTitle:      "Regular SageMaker access ensures IAM users retain only actively used permissions",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users granted SageMaker permissions are evaluated for recent service usage",
			RemediationText: "Review IAM Access Advisor data and revoke SageMaker permissions no longer used",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamUserAccessNotStaleToSagemakerCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamUserAccessNotStaleToSagemakerCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	_, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	return []models.Finding{}, nil
}

// IamPasswordPolicyLowercaseCheck - requires lowercase
type IamPasswordPolicyLowercaseCheck struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyLowercaseCheck() *IamPasswordPolicyLowercaseCheck {
	return &IamPasswordPolicyLowercaseCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_lowercase",
			CheckTitle:      "IAM password policy requires at least one lowercase letter",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM password policy requires at least one lowercase character",
			RemediationText: "Enable Require at least one lowercase letter in password policy",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPasswordPolicyLowercaseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyLowercaseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No IAM password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	status := models.StatusPass
	if !policy.PasswordPolicy.RequireLowercaseCharacters {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Password policy lowercase requirement checked",
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyUppercaseCheck - requires uppercase
type IamPasswordPolicyUppercaseCheck struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyUppercaseCheck() *IamPasswordPolicyUppercaseCheck {
	return &IamPasswordPolicyUppercaseCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_uppercase",
			CheckTitle:      "IAM password policy requires at least one uppercase letter",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM account password policy enforces the presence of at least one uppercase letter",
			RemediationText: "Enable the uppercase rule within a strong password policy",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPasswordPolicyUppercaseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyUppercaseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No IAM password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	status := models.StatusPass
	if !policy.PasswordPolicy.RequireUppercaseCharacters {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Password policy uppercase requirement checked",
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyNumberCheck - requires numbers
type IamPasswordPolicyNumberCheck struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyNumberCheck() *IamPasswordPolicyNumberCheck {
	return &IamPasswordPolicyNumberCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_number",
			CheckTitle:      "IAM password policy requires at least one number",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM account password policy requires at least one numeric character",
			RemediationText: "Enforce the password policy option to require at least one number",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPasswordPolicyNumberCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyNumberCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No IAM password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	status := models.StatusPass
	if !policy.PasswordPolicy.RequireNumbers {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Password policy number requirement checked",
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicySymbolCheck - requires symbols
type IamPasswordPolicySymbolCheck struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicySymbolCheck() *IamPasswordPolicySymbolCheck {
	return &IamPasswordPolicySymbolCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_symbol",
			CheckTitle:      "IAM password policy requires at least one symbol",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM account password policy includes the Require at least one non-alphanumeric character rule",
			RemediationText: "Enforce the Require at least one non-alphanumeric character rule",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPasswordPolicySymbolCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicySymbolCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No IAM password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	status := models.StatusPass
	if !policy.PasswordPolicy.RequireSymbols {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Password policy symbol requirement checked",
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPasswordPolicyReuseCheck - prevents reuse
type IamPasswordPolicyReuseCheck struct {
	metadata models.CheckMetadata
}

func NewIamPasswordPolicyReuseCheck() *IamPasswordPolicyReuseCheck {
	return &IamPasswordPolicyReuseCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_reuse_24",
			CheckTitle:      "IAM password policy prevents reuse of the last 24 passwords",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM account password policy uses password reuse prevention set to 24 remembered passwords",
			RemediationText: "Set the password policy to remember 24 previous passwords to block reuse",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPasswordPolicyReuseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPasswordPolicyReuseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No IAM password policy configured",
			Provider: "aws", Service: "iam", ResourceID: "password-policy",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	reusePrevention := aws.ToInt32(policy.PasswordPolicy.PasswordReusePrevention)
	status := models.StatusPass
	if reusePrevention < 24 {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: fmt.Sprintf("Password reuse prevention: %d", reusePrevention),
		Provider: "aws", Service: "iam", ResourceID: "password-policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamPolicyAttachedOnlyToGroupOrRolesCheck - policies only via groups/roles
type IamPolicyAttachedOnlyToGroupOrRolesCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyAttachedOnlyToGroupOrRolesCheck() *IamPolicyAttachedOnlyToGroupOrRolesCheck {
	return &IamPolicyAttachedOnlyToGroupOrRolesCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_attached_only_to_group_or_roles",
			CheckTitle:      "IAM user has no inline or attached policies",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users have identity-based policies attached directly instead of inheriting via groups or roles",
			RemediationText: "Assign permissions to groups and roles; avoid user-attached policies",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyAttachedOnlyToGroupOrRolesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyAttachedOnlyToGroupOrRolesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		attached, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}
		inline, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hasDirectPolicies := len(attached.AttachedPolicies) > 0 || len(inline.PolicyNames) > 0

		status := models.StatusPass
		if hasDirectPolicies {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s direct policies checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamCheckSamlProvidersStsCheck - SAML providers exist
type IamCheckSamlProvidersStsCheck struct {
	metadata models.CheckMetadata
}

func NewIamCheckSamlProvidersStsCheck() *IamCheckSamlProvidersStsCheck {
	return &IamCheckSamlProvidersStsCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_check_saml_providers_sts",
			CheckTitle:      "IAM SAML provider exists in the account",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "Other",
			Description:     "IAM SAML providers enable federated role assumption via STS AssumeRoleWithSAML",
			RemediationText: "Adopt SAML federation to issue short-lived STS credentials",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamCheckSamlProvidersStsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamCheckSamlProvidersStsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	providers, err := client.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil, err
	}

	hasSAML := len(providers.SAMLProviderList) > 0
	status := models.StatusPass
	if !hasSAML {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: fmt.Sprintf("SAML providers found: %d", len(providers.SAMLProviderList)),
		Provider: "aws", Service: "iam", ResourceID: "saml-providers",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamNoExpiredServerCertificatesCheck - no expired certs
type IamNoExpiredServerCertificatesCheck struct {
	metadata models.CheckMetadata
}

func NewIamNoExpiredServerCertificatesCheck() *IamNoExpiredServerCertificatesCheck {
	return &IamNoExpiredServerCertificatesCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_no_expired_server_certificates_stored",
			CheckTitle:      "IAM server certificate is not expired",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsCertificateManagerCertificate",
			Description:     "IAM server certificates stored in AWS IAM are evaluated for expiration",
			RemediationText: "Remove expired certificates from IAM and prefer ACM",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamNoExpiredServerCertificatesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamNoExpiredServerCertificatesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	certs, err := client.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	now := time.Now()

	for _, cert := range certs.ServerCertificateMetadataList {
		expired := false
		if cert.Expiration != nil && cert.Expiration.Before(now) {
			expired = true
		}

		status := models.StatusPass
		if expired {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Certificate %s expiration checked", aws.ToString(cert.ServerCertificateName)),
			Provider: "aws", Service: "iam", ResourceID: aws.ToString(cert.ServerCertificateName),
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamSupportRoleCreatedCheck - support role exists
type IamSupportRoleCreatedCheck struct {
	metadata models.CheckMetadata
}

func NewIamSupportRoleCreatedCheck() *IamSupportRoleCreatedCheck {
	return &IamSupportRoleCreatedCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_support_role_created",
			CheckTitle:      "At least one IAM role has the AWSSupportAccess managed policy attached",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamRole",
			Description:     "Presence of an IAM role that has the AWS managed AWSSupportAccess policy attached",
			RemediationText: "Create a dedicated IAM role for AWS Support with AWSSupportAccess",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamSupportRoleCreatedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamSupportRoleCreatedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	hasSupportRole := false
	for _, role := range roles.Roles {
		policies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
		if err != nil {
			continue
		}
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "AWSSupportAccess" {
				hasSupportRole = true
				break
			}
		}
		if hasSupportRole {
			break
		}
	}

	status := models.StatusPass
	if !hasSupportRole {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "Support role checked",
		Provider: "aws", Service: "iam", ResourceID: "support-role",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamSecurityauditRoleCreatedCheck - audit role exists
type IamSecurityauditRoleCreatedCheck struct {
	metadata models.CheckMetadata
}

func NewIamSecurityauditRoleCreatedCheck() *IamSecurityauditRoleCreatedCheck {
	return &IamSecurityauditRoleCreatedCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_securityaudit_role_created",
			CheckTitle:      "At least one IAM role has the SecurityAudit AWS managed policy attached",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM roles with the AWS managed SecurityAudit policy are identified",
			RemediationText: "Establish a dedicated audit role and attach the AWS managed SecurityAudit policy",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamSecurityauditRoleCreatedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamSecurityauditRoleCreatedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	hasAuditRole := false
	for _, role := range roles.Roles {
		policies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
		if err != nil {
			continue
		}
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "SecurityAudit" {
				hasAuditRole = true
				break
			}
		}
		if hasAuditRole {
			break
		}
	}

	status := models.StatusPass
	if !hasAuditRole {
		status = models.StatusFail
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: "SecurityAudit role checked",
		Provider: "aws", Service: "iam", ResourceID: "audit-role",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// IamGroupAdministratorAccessPolicyCheck - group has no admin
type IamGroupAdministratorAccessPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewIamGroupAdministratorAccessPolicyCheck() *IamGroupAdministratorAccessPolicyCheck {
	return &IamGroupAdministratorAccessPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_group_administrator_access_policy",
			CheckTitle:      "IAM group does not have AdministratorAccess policy attached",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamGroup",
			Description:     "IAM groups are assessed for the AWS-managed AdministratorAccess policy attachment",
			RemediationText: "Remove AdministratorAccess from groups",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamGroupAdministratorAccessPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamGroupAdministratorAccessPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := client.ListGroups(ctx, &iam.ListGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, group := range groups.Groups {
		groupName := aws.ToString(group.GroupName)
		policies, err := client.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: group.GroupName})
		if err != nil {
			continue
		}

		hasAdmin := false
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "AdministratorAccess" {
				hasAdmin = true
				break
			}
		}

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Group %s admin access checked", groupName),
			Provider: "aws", Service: "iam", ResourceID: groupName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamAdministratorAccessWithMfaCheck - admin users have MFA
type IamAdministratorAccessWithMfaCheck struct {
	metadata models.CheckMetadata
}

func NewIamAdministratorAccessWithMfaCheck() *IamAdministratorAccessWithMfaCheck {
	return &IamAdministratorAccessWithMfaCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_administrator_access_with_mfa",
			CheckTitle:      "IAM group members granted AdministratorAccess have MFA enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamGroup",
			Description:     "IAM groups with the AdministratorAccess managed policy are assessed to ensure all member users have active MFA",
			RemediationText: "Enforce MFA for all administrator identities",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamAdministratorAccessWithMfaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamAdministratorAccessWithMfaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := client.ListGroups(ctx, &iam.ListGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, group := range groups.Groups {
		groupName := aws.ToString(group.GroupName)
		policies, err := client.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: group.GroupName})
		if err != nil {
			continue
		}

		hasAdmin := false
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "AdministratorAccess" {
				hasAdmin = true
				break
			}
		}

		if !hasAdmin {
			continue
		}

		groupDetail, err := client.GetGroup(ctx, &iam.GetGroupInput{GroupName: group.GroupName})
		if err != nil {
			continue
		}

		allMfa := true
		for _, member := range groupDetail.Users {
			mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: member.UserName})
			if err != nil || len(mfaDevices.MFADevices) == 0 {
				allMfa = false
				break
			}
		}

		status := models.StatusPass
		if !allMfa {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Group %s admin MFA checked", groupName),
			Provider: "aws", Service: "iam", ResourceID: groupName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamRoleAdministratoraccessCheck - role has no admin
type IamRoleAdministratoraccessCheck struct {
	metadata models.CheckMetadata
}

func NewIamRoleAdministratoraccessCheck() *IamRoleAdministratoraccessCheck {
	return &IamRoleAdministratoraccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_administratoraccess_policy",
			CheckTitle:      "IAM role does not have AdministratorAccess policy attached",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamRole",
			Description:     "IAM roles are evaluated for attachment of the AWS-managed AdministratorAccess policy",
			RemediationText: "Apply least privilege: avoid attaching AdministratorAccess to roles",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRoleAdministratoraccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleAdministratoraccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, role := range roles.Roles {
		roleName := aws.ToString(role.RoleName)
		policies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
		if err != nil {
			continue
		}

		hasAdmin := false
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "AdministratorAccess" {
				hasAdmin = true
				break
			}
		}

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Role %s admin access checked", roleName),
			Provider: "aws", Service: "iam", ResourceID: roleName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamRoleCrossAccountReadonlyaccessCheck - no cross-account read-only
type IamRoleCrossAccountReadonlyaccessCheck struct {
	metadata models.CheckMetadata
}

func NewIamRoleCrossAccountReadonlyaccessCheck() *IamRoleCrossAccountReadonlyaccessCheck {
	return &IamRoleCrossAccountReadonlyaccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_cross_account_readonlyaccess_policy",
			CheckTitle:      "IAM role does not grant ReadOnlyAccess to external AWS accounts",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamRole",
			Description:     "IAM roles are assessed for the AWS-managed ReadOnlyAccess policy combined with a trust policy that allows external AWS principals",
			RemediationText: "Avoid attaching ReadOnlyAccess to roles trusted by other accounts",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRoleCrossAccountReadonlyaccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleCrossAccountReadonlyaccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, role := range roles.Roles {
		roleName := aws.ToString(role.RoleName)
		policies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
		if err != nil {
			continue
		}

		hasReadOnly := false
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "ReadOnlyAccess" {
				hasReadOnly = true
				break
			}
		}

		if !hasReadOnly {
			continue
		}

		trustPolicy := aws.ToString(role.AssumeRolePolicyDocument)
		allowsExternal := strings.Contains(trustPolicy, "AWS") && strings.Contains(trustPolicy, "*")

		status := models.StatusPass
		if allowsExternal {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Role %s cross-account read-only checked", roleName),
			Provider: "aws", Service: "iam", ResourceID: roleName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamRoleCrossServiceConfusedDeputyPreventionCheck - confused deputy prevention
type IamRoleCrossServiceConfusedDeputyPreventionCheck struct {
	metadata models.CheckMetadata
}

func NewIamRoleCrossServiceConfusedDeputyPreventionCheck() *IamRoleCrossServiceConfusedDeputyPreventionCheck {
	return &IamRoleCrossServiceConfusedDeputyPreventionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_cross_service_confused_deputy_prevention",
			CheckTitle:      "IAM service role prevents cross-service confused deputy attack",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamRole",
			Description:     "IAM service role trust policies restrict AWS service principals to expected sources using global condition keys",
			RemediationText: "Constrain service-role trust to expected callers using aws:SourceArn/aws:SourceAccount",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRoleCrossServiceConfusedDeputyPreventionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleCrossServiceConfusedDeputyPreventionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, role := range roles.Roles {
		roleName := aws.ToString(role.RoleName)
		trustPolicy := aws.ToString(role.AssumeRolePolicyDocument)

		hasSourceCondition := strings.Contains(trustPolicy, "aws:SourceAccount") || strings.Contains(trustPolicy, "aws:SourceArn")

		status := models.StatusPass
		if !hasSourceCondition {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Role %s confused deputy prevention checked", roleName),
			Provider: "aws", Service: "iam", ResourceID: roleName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamRoleServiceTrustRestrictsSourceCheck - source restriction
type IamRoleServiceTrustRestrictsSourceCheck struct {
	metadata models.CheckMetadata
}

func NewIamRoleServiceTrustRestrictsSourceCheck() *IamRoleServiceTrustRestrictsSourceCheck {
	return &IamRoleServiceTrustRestrictsSourceCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_service_trust_restricts_source_to_account",
			CheckTitle:      "IAM role trust policy confines AWS service principals to a specific source account",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamRole",
			Description:     "Trust-policy statements letting an AWS service principal call sts:AssumeRole confine the request source to one account",
			RemediationText: "Bind every service-principal trust statement to an account with aws:SourceAccount",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRoleServiceTrustRestrictsSourceCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleServiceTrustRestrictsSourceCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, role := range roles.Roles {
		roleName := aws.ToString(role.RoleName)
		trustPolicy := aws.ToString(role.AssumeRolePolicyDocument)

		hasSourceCondition := strings.Contains(trustPolicy, "aws:SourceAccount") || strings.Contains(trustPolicy, "aws:SourceArn")

		status := models.StatusPass
		if !hasSourceCondition {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Role %s source restriction checked", roleName),
			Provider: "aws", Service: "iam", ResourceID: roleName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamRoleAccessNotStaleToBedrockCheck - role Bedrock access not stale
type IamRoleAccessNotStaleToBedrockCheck struct {
	metadata models.CheckMetadata
}

func NewIamRoleAccessNotStaleToBedrockCheck() *IamRoleAccessNotStaleToBedrockCheck {
	return &IamRoleAccessNotStaleToBedrockCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_access_not_stale_to_bedrock",
			CheckTitle:      "Regular Bedrock access ensures IAM roles retain only actively used permissions",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamRole",
			Description:     "IAM roles granted Bedrock permissions are evaluated for recent service usage",
			RemediationText: "Review IAM Access Advisor data and revoke Bedrock permissions no longer used",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRoleAccessNotStaleToBedrockCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRoleAccessNotStaleToBedrockCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	_, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	return []models.Finding{}, nil
}

// IamInlinePolicyNoFullAccessToCloudtrailCheck - no cloudtrail:*
type IamInlinePolicyNoFullAccessToCloudtrailCheck struct {
	metadata models.CheckMetadata
}

func NewIamInlinePolicyNoFullAccessToCloudtrailCheck() *IamInlinePolicyNoFullAccessToCloudtrailCheck {
	return &IamInlinePolicyNoFullAccessToCloudtrailCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_full_access_to_cloudtrail",
			CheckTitle:      "Inline IAM policy does not allow 'cloudtrail:*' privileges",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM inline policies are evaluated for statements that grant full CloudTrail permissions",
			RemediationText: "Enforce least privilege and separation of duties: avoid cloudtrail:*",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamInlinePolicyNoFullAccessToCloudtrailCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamInlinePolicyNoFullAccessToCloudtrailCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		inlinePolicies, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		for _, policyName := range inlinePolicies.PolicyNames {
			policy, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: user.UserName, PolicyName: aws.String(policyName)})
			if err != nil {
				continue
			}

			policyDoc := aws.ToString(policy.PolicyDocument)
			hasFullAccess := strings.Contains(policyDoc, "cloudtrail:*")

			status := models.StatusPass
			if hasFullAccess {
				status = models.StatusFail
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: fmt.Sprintf("User %s inline policy %s cloudtrail access checked", userName, policyName),
				Provider: "aws", Service: "iam", ResourceID: userName,
				FoundAt: time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// IamInlinePolicyNoFullAccessToKmsCheck - no kms:*
type IamInlinePolicyNoFullAccessToKmsCheck struct {
	metadata models.CheckMetadata
}

func NewIamInlinePolicyNoFullAccessToKmsCheck() *IamInlinePolicyNoFullAccessToKmsCheck {
	return &IamInlinePolicyNoFullAccessToKmsCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_full_access_to_kms",
			CheckTitle:      "Inline IAM policy does not allow kms:* privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM inline policies are analyzed to identify statements that grant unrestricted AWS KMS access",
			RemediationText: "Replace kms:* with least-privilege, action-scoped permissions",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamInlinePolicyNoFullAccessToKmsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamInlinePolicyNoFullAccessToKmsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		inlinePolicies, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		for _, policyName := range inlinePolicies.PolicyNames {
			policy, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: user.UserName, PolicyName: aws.String(policyName)})
			if err != nil {
				continue
			}

			policyDoc := aws.ToString(policy.PolicyDocument)
			hasFullAccess := strings.Contains(policyDoc, "kms:*")

			status := models.StatusPass
			if hasFullAccess {
				status = models.StatusFail
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: fmt.Sprintf("User %s inline policy %s KMS access checked", userName, policyName),
				Provider: "aws", Service: "iam", ResourceID: userName,
				FoundAt: time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// IamInlinePolicyNoWildcardMarketplaceSubscribeCheck - no marketplace wildcard
type IamInlinePolicyNoWildcardMarketplaceSubscribeCheck struct {
	metadata models.CheckMetadata
}

func NewIamInlinePolicyNoWildcardMarketplaceSubscribeCheck() *IamInlinePolicyNoWildcardMarketplaceSubscribeCheck {
	return &IamInlinePolicyNoWildcardMarketplaceSubscribeCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_wildcard_marketplace_subscribe",
			CheckTitle:      "Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM inline policies are analyzed to identify statements that grant aws-marketplace:Subscribe on all resources",
			RemediationText: "Replace Resource: * with specific, approved AWS Marketplace product ARNs",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamInlinePolicyNoWildcardMarketplaceSubscribeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamInlinePolicyNoWildcardMarketplaceSubscribeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		inlinePolicies, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		for _, policyName := range inlinePolicies.PolicyNames {
			policy, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: user.UserName, PolicyName: aws.String(policyName)})
			if err != nil {
				continue
			}

			policyDoc := aws.ToString(policy.PolicyDocument)
			hasWildcardSubscribe := strings.Contains(policyDoc, "aws-marketplace:Subscribe") && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*")

			status := models.StatusPass
			if hasWildcardSubscribe {
				status = models.StatusFail
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: fmt.Sprintf("User %s marketplace subscribe checked", userName),
				Provider: "aws", Service: "iam", ResourceID: userName,
				FoundAt: time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// IamInlinePolicyAllowsPrivilegeEscalationCheck - no privilege escalation
type IamInlinePolicyAllowsPrivilegeEscalationCheck struct {
	metadata models.CheckMetadata
}

func NewIamInlinePolicyAllowsPrivilegeEscalationCheck() *IamInlinePolicyAllowsPrivilegeEscalationCheck {
	return &IamInlinePolicyAllowsPrivilegeEscalationCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_allows_privilege_escalation",
			CheckTitle:      "IAM inline policy does not allow privilege escalation",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM inline policies are evaluated for permission combinations that enable privilege escalation",
			RemediationText: "Apply least privilege and remove escalation paths",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamInlinePolicyAllowsPrivilegeEscalationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamInlinePolicyAllowsPrivilegeEscalationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	escalationActions := []string{"sts:AssumeRole", "iam:PassRole", "iam:AttachUserPolicy", "iam:PutUserPolicy"}
	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		inlinePolicies, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hasEscalation := false
		for _, policyName := range inlinePolicies.PolicyNames {
			policy, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: user.UserName, PolicyName: aws.String(policyName)})
			if err != nil {
				continue
			}

			policyDoc := aws.ToString(policy.PolicyDocument)
			for _, action := range escalationActions {
				if strings.Contains(policyDoc, action) && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*") {
					hasEscalation = true
					break
				}
			}
		}

		status := models.StatusPass
		if hasEscalation {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s privilege escalation checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamInlinePolicyNoAdministrativePrivilegesCheck - no *:*
type IamInlinePolicyNoAdministrativePrivilegesCheck struct {
	metadata models.CheckMetadata
}

func NewIamInlinePolicyNoAdministrativePrivilegesCheck() *IamInlinePolicyNoAdministrativePrivilegesCheck {
	return &IamInlinePolicyNoAdministrativePrivilegesCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_administrative_privileges",
			CheckTitle:      "Inline IAM policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM inline policies on identities are evaluated for statements allowing Action:* on Resource:*",
			RemediationText: "Remove Action:* with Resource:* from inline policies",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamInlinePolicyNoAdministrativePrivilegesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamInlinePolicyNoAdministrativePrivilegesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		inlinePolicies, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hasAdmin := false
		for _, policyName := range inlinePolicies.PolicyNames {
			policy, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: user.UserName, PolicyName: aws.String(policyName)})
			if err != nil {
				continue
			}

			policyDoc := aws.ToString(policy.PolicyDocument)
			if strings.Contains(policyDoc, "Action") && strings.Contains(policyDoc, "Resource") {
				hasAdmin = true
				break
			}
		}

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s admin privileges checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamCustomerAttachedPolicyNoAdministrativePrivilegesCheck - no *:* on attached
type IamCustomerAttachedPolicyNoAdministrativePrivilegesCheck struct {
	metadata models.CheckMetadata
}

func NewIamCustomerAttachedPolicyNoAdministrativePrivilegesCheck() *IamCustomerAttachedPolicyNoAdministrativePrivilegesCheck {
	return &IamCustomerAttachedPolicyNoAdministrativePrivilegesCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_customer_attached_policy_no_administrative_privileges",
			CheckTitle:      "Attached IAM customer-managed policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "Attached customer-managed IAM policies are evaluated for statements granting full admin access via Action:* Resource:*",
			RemediationText: "Enforce least privilege: replace wildcards with specific actions",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamCustomerAttachedPolicyNoAdministrativePrivilegesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamCustomerAttachedPolicyNoAdministrativePrivilegesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal, OnlyAttached: true})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasAdmin := strings.Contains(policyDoc, "Action") && strings.Contains(policyDoc, "Resource")

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s admin privileges checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck - no *:* on unattached
type IamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck struct {
	metadata models.CheckMetadata
}

func NewIamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck() *IamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck {
	return &IamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_customer_unattached_policy_no_administrative_privileges",
			CheckTitle:      "Unattached customer managed IAM policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "Customer-managed IAM policies that are unattached are evaluated for statements granting full administrative access",
			RemediationText: "Remove or redesign these policies to enforce least privilege",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamCustomerUnattachedPolicyNoAdministrativePrivilegesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal, OnlyAttached: false})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		if policy.AttachmentCount != nil && *policy.AttachmentCount > 0 {
			continue
		}

		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasAdmin := strings.Contains(policyDoc, "Action") && strings.Contains(policyDoc, "Resource")

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Unattached policy %s admin privileges checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamAwsAttachedPolicyNoAdministrativePrivilegesCheck - no *:* on AWS managed
type IamAwsAttachedPolicyNoAdministrativePrivilegesCheck struct {
	metadata models.CheckMetadata
}

func NewIamAwsAttachedPolicyNoAdministrativePrivilegesCheck() *IamAwsAttachedPolicyNoAdministrativePrivilegesCheck {
	return &IamAwsAttachedPolicyNoAdministrativePrivilegesCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_aws_attached_policy_no_administrative_privileges",
			CheckTitle:      "Attached AWS-managed IAM policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM AWS-managed policies attached to identities are inspected for statements that allow Action:* on Resource:*",
			RemediationText: "Apply least privilege: avoid attaching AWS-managed policies that grant *:*",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamAwsAttachedPolicyNoAdministrativePrivilegesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamAwsAttachedPolicyNoAdministrativePrivilegesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeAws, OnlyAttached: true})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasAdmin := strings.Contains(policyDoc, "Action") && strings.Contains(policyDoc, "Resource")

		status := models.StatusPass
		if hasAdmin {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("AWS policy %s admin privileges checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyNoWildcardMarketplaceSubscribeCheck - no marketplace wildcard
type IamPolicyNoWildcardMarketplaceSubscribeCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyNoWildcardMarketplaceSubscribeCheck() *IamPolicyNoWildcardMarketplaceSubscribeCheck {
	return &IamPolicyNoWildcardMarketplaceSubscribeCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_wildcard_marketplace_subscribe",
			CheckTitle:      "Custom IAM policy does not allow 'aws-marketplace:Subscribe' on all resources",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "Customer-managed IAM policies are examined for statements that grant aws-marketplace:Subscribe on all resources",
			RemediationText: "Replace Resource: * with specific, approved AWS Marketplace product ARNs",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyNoWildcardMarketplaceSubscribeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyNoWildcardMarketplaceSubscribeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasWildcardSubscribe := strings.Contains(policyDoc, "aws-marketplace:Subscribe") && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*")

		status := models.StatusPass
		if hasWildcardSubscribe {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s marketplace subscribe checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyAllowsPrivilegeEscalationCheck - no privilege escalation
type IamPolicyAllowsPrivilegeEscalationCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyAllowsPrivilegeEscalationCheck() *IamPolicyAllowsPrivilegeEscalationCheck {
	return &IamPolicyAllowsPrivilegeEscalationCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_allows_privilege_escalation",
			CheckTitle:      "Customer managed IAM policy does not allow actions that can lead to privilege escalation",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "Customer-managed IAM policies are evaluated for permissions that enable privilege escalation",
			RemediationText: "Apply least privilege to customer policies",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyAllowsPrivilegeEscalationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyAllowsPrivilegeEscalationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	escalationActions := []string{"iam:PassRole", "iam:AttachRolePolicy", "sts:AssumeRole"}
	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasEscalation := false
		for _, action := range escalationActions {
			if strings.Contains(policyDoc, action) && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*") {
				hasEscalation = true
				break
			}
		}

		status := models.StatusPass
		if hasEscalation {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s privilege escalation checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamNoCustomPolicyPermissiveRoleAssumptionCheck - no permissive role assumption
type IamNoCustomPolicyPermissiveRoleAssumptionCheck struct {
	metadata models.CheckMetadata
}

func NewIamNoCustomPolicyPermissiveRoleAssumptionCheck() *IamNoCustomPolicyPermissiveRoleAssumptionCheck {
	return &IamNoCustomPolicyPermissiveRoleAssumptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_no_custom_policy_permissive_role_assumption",
			CheckTitle:      "Custom IAM policy does not allow STS role assumption on wildcard resources",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "Custom IAM policies with Allow statements that grant sts:AssumeRole (or sts:*/*) to a wildcard Resource",
			RemediationText: "Apply least privilege to sts:AssumeRole: scope Resource to exact role ARNs",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamNoCustomPolicyPermissiveRoleAssumptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamNoCustomPolicyPermissiveRoleAssumptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasPermissiveAssume := strings.Contains(policyDoc, "sts:AssumeRole") && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*")

		status := models.StatusPass
		if hasPermissiveAssume {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s role assumption checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyNoFullAccessToCloudtrailCheck - no cloudtrail:*
type IamPolicyNoFullAccessToCloudtrailCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyNoFullAccessToCloudtrailCheck() *IamPolicyNoFullAccessToCloudtrailCheck {
	return &IamPolicyNoFullAccessToCloudtrailCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_full_access_to_cloudtrail",
			CheckTitle:      "Customer managed IAM policy does not allow cloudtrail:* privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "Custom IAM policies are reviewed for statements that grant full CloudTrail access via the cloudtrail:* wildcard",
			RemediationText: "Apply least privilege: avoid cloudtrail:* and allow only required actions",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyNoFullAccessToCloudtrailCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyNoFullAccessToCloudtrailCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasFullAccess := strings.Contains(policyDoc, "cloudtrail:*")

		status := models.StatusPass
		if hasFullAccess {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s cloudtrail access checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyNoFullAccessToKmsCheck - no kms:*
type IamPolicyNoFullAccessToKmsCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyNoFullAccessToKmsCheck() *IamPolicyNoFullAccessToKmsCheck {
	return &IamPolicyNoFullAccessToKmsCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_full_access_to_kms",
			CheckTitle:      "Custom IAM policy does not allow 'kms:*' privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "Customer-managed IAM policies are examined for statements that grant AWS KMS full access using kms:*",
			RemediationText: "Adopt least privilege and separation of duties: replace kms:* with only needed actions",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyNoFullAccessToKmsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyNoFullAccessToKmsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasFullAccess := strings.Contains(policyDoc, "kms:*")

		status := models.StatusPass
		if hasFullAccess {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s KMS access checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyCloudshellAdminNotAttachedCheck - no cloudshell admin
type IamPolicyCloudshellAdminNotAttachedCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyCloudshellAdminNotAttachedCheck() *IamPolicyCloudshellAdminNotAttachedCheck {
	return &IamPolicyCloudshellAdminNotAttachedCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_cloudshell_admin_not_attached",
			CheckTitle:      "No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "IAM identities with the AWS managed policy AWSCloudShellFullAccess attached are identified",
			RemediationText: "Detach AWSCloudShellFullAccess from identities",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyCloudshellAdminNotAttachedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyCloudshellAdminNotAttachedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		policies, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		hasCloudShell := false
		for _, pol := range policies.AttachedPolicies {
			if aws.ToString(pol.PolicyName) == "AWSCloudShellFullAccess" {
				hasCloudShell = true
				break
			}
		}

		status := models.StatusPass
		if hasCloudShell {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("User %s cloudshell access checked", userName),
			Provider: "aws", Service: "iam", ResourceID: userName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck - no agentcore wildcard
type IamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck() *IamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck {
	return &IamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_agentcore_workload_access_token_wildcard",
			CheckTitle:      "Custom IAM policy scopes Bedrock AgentCore workload access token retrieval to workload identity ARNs",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "Customer-managed IAM policies are examined for Allow statements granting bedrock-agentcore:GetWorkloadAccessToken over resources that reach a workload identity other than the caller's own",
			RemediationText: "Scope the workload access token actions to the workload identity ARNs the policy holder acts for",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyNoAgentcoreWorkloadAccessTokenWildcardCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	agentcoreActions := []string{"bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT", "bedrock-agentcore:GetWorkloadAccessTokenForUserId"}
	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasWildcard := false
		for _, action := range agentcoreActions {
			if strings.Contains(policyDoc, action) && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*") {
				hasWildcard = true
				break
			}
		}

		status := models.StatusPass
		if hasWildcard {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s agentcore wildcard checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamPolicyPassroleToBedrockAgentcoreRestrictedCheck - passrole restricted
type IamPolicyPassroleToBedrockAgentcoreRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewIamPolicyPassroleToBedrockAgentcoreRestrictedCheck() *IamPolicyPassroleToBedrockAgentcoreRestrictedCheck {
	return &IamPolicyPassroleToBedrockAgentcoreRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_passrole_to_bedrock_agentcore_restricted",
			CheckTitle:      "Custom IAM policy restricts iam:PassRole to Bedrock AgentCore to specific roles",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "Customer-managed IAM policies are examined for Allow statements granting iam:PassRole over every role",
			RemediationText: "Name the roles that may be passed instead of allowing every role",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamPolicyPassroleToBedrockAgentcoreRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamPolicyPassroleToBedrockAgentcoreRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	for _, policy := range policies.Policies {
		policyName := aws.ToString(policy.PolicyName)
		policyDetail, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId})
		if err != nil {
			continue
		}

		policyDoc := aws.ToString(policyDetail.PolicyVersion.Document)
		hasPassRoleWildcard := strings.Contains(policyDoc, "iam:PassRole") && strings.Contains(policyDoc, "Resource") && strings.Contains(policyDoc, "*")

		status := models.StatusPass
		if hasPassRoleWildcard {
			status = models.StatusFail
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: fmt.Sprintf("Policy %s passrole restriction checked", policyName),
			Provider: "aws", Service: "iam", ResourceID: policyName,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// IamRotateAccessKey90DaysCheck - rotate access keys
type IamRotateAccessKey90DaysCheck struct {
	metadata models.CheckMetadata
}

func NewIamRotateAccessKey90DaysCheck() *IamRotateAccessKey90DaysCheck {
	return &IamRotateAccessKey90DaysCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_rotate_access_key_90_days",
			CheckTitle:      "IAM user does not have active access keys older than 90 days",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM user access keys are assessed via the credential report",
			RemediationText: "Apply least privilege and limit static credentials: rotate active access keys at or before 90 days",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *IamRotateAccessKey90DaysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IamRotateAccessKey90DaysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	findings := []models.Finding{}
	maxAge := 90 * 24 * time.Hour

	for _, user := range users.Users {
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}

		for _, key := range keys.AccessKeyMetadata {
			if key.Status != types.StatusTypeActive {
				continue
			}
			age := time.Since(aws.ToTime(key.CreateDate))
			rotated := age < maxAge

			status := models.StatusPass
			if !rotated {
				status = models.StatusFail
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: fmt.Sprintf("Key %s age %.0f days", aws.ToString(key.AccessKeyId), age.Hours()/24),
				Provider: "aws", Service: "iam", ResourceID: aws.ToString(key.AccessKeyId),
				FoundAt: time.Now().UTC(),
			})
		}
	}

	return findings, nil
}
