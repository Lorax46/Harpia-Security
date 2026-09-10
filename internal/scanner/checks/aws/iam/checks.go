package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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
