package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type iamProvider interface {
	IAM(ctx context.Context) (*iam.Client, error)
}

// RootAccountMfaCheck - verifica se root tem MFA habilitado
type RootAccountMfaCheck struct {
	metadata models.CheckMetadata
}

func NewRootAccountMfaCheck() *RootAccountMfaCheck {
	return &RootAccountMfaCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_account_mfa_enabled",
			CheckTitle:      "Root account MFA should be enabled",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "Account",
			Description:     "Root account should have MFA enabled",
			RemediationText: "Enable MFA for root account",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *RootAccountMfaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RootAccountMfaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	iamClient, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// GetAccountSummary retorna informações sobre MFA do root
	summary, err := iamClient.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao obter account summary: %w", err)
	}

	mfaEnabled := false
	if summary.SummaryMap != nil {
		if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 1 {
			mfaEnabled = true
		}
	}

	status := models.StatusFail
	ext := "Root account does not have MFA enabled"
	if mfaEnabled {
		status = models.StatusPass
		ext = "Root account has MFA enabled"
	}

	findings = append(findings, models.Finding{
		ID:              c.metadata.CheckID,
		Title:           c.metadata.CheckTitle,
		Description:     c.metadata.Description,
		Severity:        c.metadata.Severity,
		Status:          status,
		StatusExtended:  ext,
		Provider:        "aws",
		Service:         "iam",
		ResourceID:      "root",
		Remediation:     c.metadata.RemediationText,
		Categories:      c.metadata.Categories,
		FoundAt:         time.Now(),
	})

	return findings, nil
}

// RootAccountAccessKeysCheck - verifica se root tem access keys
type RootAccountAccessKeysCheck struct {
	metadata models.CheckMetadata
}

func NewRootAccountAccessKeysCheck() *RootAccountAccessKeysCheck {
	return &RootAccountAccessKeysCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_account_no_access_keys",
			CheckTitle:      "Root account should not have access keys",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "Account",
			Description:     "Root account should not have access keys",
			RemediationText: "Delete root account access keys",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *RootAccountAccessKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RootAccountAccessKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	iamClient, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// ListAccessKeys com user vazio retorna keys do root
	keys, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar access keys: %w", err)
	}

	hasKeys := keys != nil && len(keys.AccessKeyMetadata) > 0

	status := models.StatusPass
	ext := "Root account does not have access keys"
	if hasKeys {
		status = models.StatusFail
		ext = "Root account has access keys"
	}

	findings = append(findings, models.Finding{
		ID:              c.metadata.CheckID,
		Title:           c.metadata.CheckTitle,
		Description:     c.metadata.Description,
		Severity:        c.metadata.Severity,
		Status:          status,
		StatusExtended:  ext,
		Provider:        "aws",
		Service:         "iam",
		ResourceID:      "root",
		Remediation:     c.metadata.RemediationText,
		Categories:      c.metadata.Categories,
		FoundAt:         time.Now(),
	})

	return findings, nil
}

// UserMfaEnabledCheck - verifica se usuários têm MFA habilitado
type UserMfaEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewUserMfaEnabledCheck() *UserMfaEnabledCheck {
	return &UserMfaEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_mfa_enabled",
			CheckTitle:      "IAM users should have MFA enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "User",
			Description:     "IAM users should have MFA enabled",
			RemediationText: "Enable MFA for IAM users",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *UserMfaEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserMfaEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	iamClient, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// ListUsers para iterar sobre usuários
	users, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}

	for _, user := range users.Users {
		// ListMFADevices para cada usuário
		mfaDevices, err := iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}

		mfaEnabled := len(mfaDevices.MFADevices) > 0

		status := models.StatusFail
		ext := fmt.Sprintf("User %s does not have MFA enabled", aws.ToString(user.UserName))
		if mfaEnabled {
			status = models.StatusPass
			ext = fmt.Sprintf("User %s has MFA enabled", aws.ToString(user.UserName))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "iam",
			ResourceID:      aws.ToString(user.UserName),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// PasswordPolicyCheck - verifica política de senha
type PasswordPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyCheck() *PasswordPolicyCheck {
	return &PasswordPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy",
			CheckTitle:      "IAM password policy should be strong",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "Account",
			Description:     "IAM password policy should require strong passwords",
			RemediationText: "Configure strong IAM password policy",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *PasswordPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	iamClient, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	policy, err := iamClient.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          models.StatusFail,
			StatusExtended:  "No IAM password policy configured",
			Provider:        "aws",
			Service:         "iam",
			ResourceID:      "password-policy",
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
		return findings, nil
	}

	// Verificar requisitos mínimos
	strongPolicy := true
	ext := "Password policy is strong"

	if policy.PasswordPolicy.MinimumPasswordLength == nil || *policy.PasswordPolicy.MinimumPasswordLength < 14 {
		strongPolicy = false
		ext = fmt.Sprintf("Password policy requires only %d characters (minimum 14)", aws.ToInt32(policy.PasswordPolicy.MinimumPasswordLength))
	}
	if !policy.PasswordPolicy.RequireSymbols {
		strongPolicy = false
		ext = "Password policy does not require symbols"
	}
	if !policy.PasswordPolicy.RequireNumbers {
		strongPolicy = false
		ext = "Password policy does not require numbers"
	}
	if !policy.PasswordPolicy.RequireUppercaseCharacters {
		strongPolicy = false
		ext = "Password policy does not require uppercase characters"
	}
	if !policy.PasswordPolicy.RequireLowercaseCharacters {
		strongPolicy = false
		ext = "Password policy does not require lowercase characters"
	}

	status := models.StatusPass
	if !strongPolicy {
		status = models.StatusFail
	}

	findings = append(findings, models.Finding{
		ID:              c.metadata.CheckID,
		Title:           c.metadata.CheckTitle,
		Description:     c.metadata.Description,
		Severity:        c.metadata.Severity,
		Status:          status,
		StatusExtended:  ext,
		Provider:        "aws",
		Service:         "iam",
		ResourceID:      "password-policy",
		Remediation:     c.metadata.RemediationText,
		Categories:      c.metadata.Categories,
		FoundAt:         time.Now(),
	})

	return findings, nil
}

// AccessKeyRotationCheck - verifica rotação de access keys
type AccessKeyRotationCheck struct {
	metadata models.CheckMetadata
}

func NewAccessKeyRotationCheck() *AccessKeyRotationCheck {
	return &AccessKeyRotationCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_access_key_rotation",
			CheckTitle:      "IAM access keys should be rotated every 90 days",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AccessKey",
			Description:     "IAM access keys should be rotated every 90 days",
			RemediationText: "Rotate IAM access keys regularly",
			Categories:      []string{"iam", "security"},
		},
	}
}

func (c *AccessKeyRotationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessKeyRotationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	iamClient, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	users, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}

	maxAge := 90 * 24 * time.Hour

	for _, user := range users.Users {
		keys, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}

		for _, key := range keys.AccessKeyMetadata {
			age := time.Since(aws.ToTime(key.CreateDate))
			rotated := age < maxAge

			status := models.StatusPass
			ext := fmt.Sprintf("Key %s for user %s is %.0f days old (rotated)", aws.ToString(key.AccessKeyId), aws.ToString(user.UserName), age.Hours()/24)
			if !rotated {
				status = models.StatusFail
				ext = fmt.Sprintf("Key %s for user %s is %.0f days old (needs rotation)", aws.ToString(key.AccessKeyId), aws.ToString(user.UserName), age.Hours()/24)
			}

			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "aws",
				Service:         "iam",
				ResourceID:      aws.ToString(key.AccessKeyId),
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}

	return findings, nil
}

// RootHardwareMfaEnabled - Root account has a hardware MFA device enabled
type RootHardwareMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewRootHardwareMfaEnabled() *RootHardwareMfaEnabled {
	return &RootHardwareMfaEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_hardware_mfa_enabled",
			CheckTitle:      "Root account has a hardware MFA device enabled",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamUser",
			Description:     "**AWS root user** credentials are assessed for **MFA status** and device type. The check detects whether MFA is absent or implemented with a **virtual device** instead of **hardware MFA** on the root user, and notes when centralized root credential management is in effect.",
			RemediationText: "Require a **hardware MFA token** for the root user and remove any virtual MFA. Apply **least privilege**: avoid using root, disable access keys, and eliminate long-term credentials. In organizations, **centralize root management**. Keep a controlled break-glass process with strict recovery checks and continuous monitoring.",
			Categories:      []string{"iam", "iam"},
		},
	}
}

func (c *RootHardwareMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RootHardwareMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_root_hardware_mfa_enabled
	_ = client

	return findings, nil
}

// RootCredentialsManagementEnabled - AWS Organization has centralized root credentials management enabled
type RootCredentialsManagementEnabled struct {
	metadata models.CheckMetadata
}

func NewRootCredentialsManagementEnabled() *RootCredentialsManagementEnabled {
	return &RootCredentialsManagementEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_credentials_management_enabled",
			CheckTitle:      "AWS Organization has centralized root credentials management enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "Other",
			Description:     "**AWS Organizations** uses **centralized root credentials management** to control root user credentials across member accounts. This finding evaluates whether the organization has enabled the `RootCredentialsManagement` feature to centrally govern presence and recovery of root passwords, access keys, signing certificates, and MFA.",
			RemediationText: "Enable centralized root access with **root credentials management** and assign a **delegated administrator**. Apply **least privilege** and **separation of duties** by deleting long-term root credentials in members, limiting privileged tasks to short-lived sessions, enforcing **MFA**, and auditing root-related activity for **defense in depth**.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RootCredentialsManagementEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RootCredentialsManagementEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_root_credentials_management_enabled
	_ = client

	return findings, nil
}

// RoleAccessNotStaleToBedrock - Regular Bedrock access ensures IAM roles retain only actively used permissions
type RoleAccessNotStaleToBedrock struct {
	metadata models.CheckMetadata
}

func NewRoleAccessNotStaleToBedrock() *RoleAccessNotStaleToBedrock {
	return &RoleAccessNotStaleToBedrock{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_access_not_stale_to_bedrock",
			CheckTitle:      "Regular Bedrock access ensures IAM roles retain only actively used permissions",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamRole",
			Description:     "IAM roles granted **Bedrock** permissions are evaluated for recent service usage. Roles whose last Bedrock access exceeds the configured threshold (default **60 days**) or that have **never** accessed Bedrock are flagged, indicating stale permissions that should be reviewed.",
			RemediationText: "Apply the **principle of least privilege** by regularly reviewing IAM Access Advisor data and revoking Bedrock permissions that are no longer actively used. Establish a periodic access review process and automate alerts for stale permissions to maintain a minimal attack surface.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RoleAccessNotStaleToBedrock) Metadata() models.CheckMetadata { return c.metadata }

func (c *RoleAccessNotStaleToBedrock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_role_access_not_stale_to_bedrock
	_ = client

	return findings, nil
}

// UserConsoleAccessUnused - IAM user console access is disabled, used within the configured inactivity period, or never used
type UserConsoleAccessUnused struct {
	metadata models.CheckMetadata
}

func NewUserConsoleAccessUnused() *UserConsoleAccessUnused {
	return &UserConsoleAccessUnused{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_console_access_unused",
			CheckTitle:      "IAM user console access is disabled, used within the configured inactivity period, or never used",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** with console access are evaluated by `password_last_used`. Inactivity beyond `max_console_access_days` (default `45`) marks **stale console access**. *Users without console access are excluded*.",
			RemediationText: "Remove or disable console passwords for users inactive beyond your window (e.g., `45` days). Prefer roles or federation over long-lived IAM users. Enforce **least privilege**, require **MFA** for remaining console users, and run periodic reviews and deprovisioning to prevent unused credentials.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserConsoleAccessUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserConsoleAccessUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_console_access_unused
	_ = client

	return findings, nil
}

// PolicyNoWildcardMarketplaceSubscribe - Custom IAM policy does not allow 'aws-marketplace:Subscribe' on all resources
type PolicyNoWildcardMarketplaceSubscribe struct {
	metadata models.CheckMetadata
}

func NewPolicyNoWildcardMarketplaceSubscribe() *PolicyNoWildcardMarketplaceSubscribe {
	return &PolicyNoWildcardMarketplaceSubscribe{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_wildcard_marketplace_subscribe",
			CheckTitle:      "Custom IAM policy does not allow 'aws-marketplace:Subscribe' on all resources",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Customer-managed IAM policies** are examined for statements that grant `aws-marketplace:Subscribe` on all resources (`*`). This action controls the ability to subscribe to AWS Marketplace products, including **Amazon Bedrock foundation models**, and should be scoped to specific product ARNs to enforce least privilege.",
			RemediationText: "Replace `Resource: \"*\"` with specific, approved AWS Marketplace product ARNs. Apply the principle of least privilege to `aws-marketplace:Subscribe` permissions to prevent unauthorized subscriptions to costly Bedrock models and other Marketplace products.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyNoWildcardMarketplaceSubscribe) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyNoWildcardMarketplaceSubscribe) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_no_wildcard_marketplace_subscribe
	_ = client

	return findings, nil
}

// InlinePolicyNoFullAccessToCloudtrail - Inline IAM policy does not allow 'cloudtrail:*' privileges
type InlinePolicyNoFullAccessToCloudtrail struct {
	metadata models.CheckMetadata
}

func NewInlinePolicyNoFullAccessToCloudtrail() *InlinePolicyNoFullAccessToCloudtrail {
	return &InlinePolicyNoFullAccessToCloudtrail{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_full_access_to_cloudtrail",
			CheckTitle:      "Inline IAM policy does not allow 'cloudtrail:*' privileges",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM inline policies** are evaluated for statements that grant **full CloudTrail permissions** (`cloudtrail:*`) to all resources. The finding flags identity policies that provide unrestricted control over CloudTrail operations.",
			RemediationText: "Enforce **least privilege** and **separation of duties**: avoid `cloudtrail:*`; grant only specific actions needed (prefer read-only where possible). Add guardrails or boundaries to block destructive actions. Use managed, centrally governed policies and periodically right-size permissions based on usage.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *InlinePolicyNoFullAccessToCloudtrail) Metadata() models.CheckMetadata { return c.metadata }

func (c *InlinePolicyNoFullAccessToCloudtrail) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_inline_policy_no_full_access_to_cloudtrail
	_ = client

	return findings, nil
}

// PasswordPolicyMinimumLength14 - IAM password policy requires passwords to be at least 14 characters long
type PasswordPolicyMinimumLength14 struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyMinimumLength14() *PasswordPolicyMinimumLength14 {
	return &PasswordPolicyMinimumLength14{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_minimum_length_14",
			CheckTitle:      "IAM password policy requires passwords to be at least 14 characters long",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM password policy** is assessed for the **minimum password length** setting, confirming it meets `>= 14` characters for IAM console users.",
			RemediationText: "Set the **minimum password length** to `>= 14` (prefer `16+`). - Require mixed character types and prevent reuse - Enforce **MFA** for all console users - Prefer SSO over local IAM users - Apply least privilege and monitor authentication events",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyMinimumLength14) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyMinimumLength14) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_minimum_length_14
	_ = client

	return findings, nil
}

// InlinePolicyAllowsPrivilegeEscalation - IAM inline policy does not allow privilege escalation
type InlinePolicyAllowsPrivilegeEscalation struct {
	metadata models.CheckMetadata
}

func NewInlinePolicyAllowsPrivilegeEscalation() *InlinePolicyAllowsPrivilegeEscalation {
	return &InlinePolicyAllowsPrivilegeEscalation{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_allows_privilege_escalation",
			CheckTitle:      "IAM inline policy does not allow privilege escalation",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM inline policies** are evaluated for permission combinations that enable **privilege escalation**, such as `sts:AssumeRole`, `iam:PassRole`, attaching/editing policies, or broad wildcards. The result highlights inline policies that allow a principal to obtain higher effective access.",
			RemediationText: "Apply **least privilege** and remove escalation paths: - Avoid wildcards and sensitive actions like `sts:AssumeRole`, `iam:PassRole`, or policy modification without tight scope - Restrict by resource and `Condition` - Prefer managed, versioned policies; use permissions boundaries/SCPs - Require reviews and MFA for admins",
			Categories:      []string{"iam"},
		},
	}
}

func (c *InlinePolicyAllowsPrivilegeEscalation) Metadata() models.CheckMetadata { return c.metadata }

func (c *InlinePolicyAllowsPrivilegeEscalation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_inline_policy_allows_privilege_escalation
	_ = client

	return findings, nil
}

// CustomerAttachedPolicyNoAdministrativePrivileges - Attached IAM customer-managed policy does not allow '*:*' administrative privileges
type CustomerAttachedPolicyNoAdministrativePrivileges struct {
	metadata models.CheckMetadata
}

func NewCustomerAttachedPolicyNoAdministrativePrivileges() *CustomerAttachedPolicyNoAdministrativePrivileges {
	return &CustomerAttachedPolicyNoAdministrativePrivileges{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_customer_attached_policy_no_administrative_privileges",
			CheckTitle:      "Attached IAM customer-managed policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "Attached **customer-managed IAM policies** are evaluated for statements granting full admin access via `Action: \"*\"`, `Resource: \"*\"`, i.e., `*:*`. Only policies you created and attached to identities are considered.",
			RemediationText: "Enforce **least privilege**: replace wildcards with specific actions, scope `Resource` to needed ARNs, and add restrictive `Condition`s. Prefer role-based access and separation of duties. Use **permissions boundaries** and organization guardrails, and regularly review policies with policy validation and Access Analyzer.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *CustomerAttachedPolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CustomerAttachedPolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_customer_attached_policy_no_administrative_privileges
	_ = client

	return findings, nil
}

// CheckSamlProvidersSts - IAM SAML provider exists in the account
type CheckSamlProvidersSts struct {
	metadata models.CheckMetadata
}

func NewCheckSamlProvidersSts() *CheckSamlProvidersSts {
	return &CheckSamlProvidersSts{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_check_saml_providers_sts",
			CheckTitle:      "IAM SAML provider exists in the account",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "Other",
			Description:     "**IAM SAML providers** enable **federated role assumption** via STS `AssumeRoleWithSAML`. This evaluates whether such providers exist in the account.",
			RemediationText: "Adopt **SAML federation** to issue **short-lived STS credentials**. Map users to roles with **least privilege**, enforce **MFA** at the IdP, and set conservative session durations. Retire IAM user access keys for interactive use and monitor role sessions as **defense in depth**. *If federation isn't possible*, tightly scope, rotate, and audit keys.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *CheckSamlProvidersSts) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckSamlProvidersSts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_check_saml_providers_sts
	_ = client

	return findings, nil
}

// RotateAccessKey90Days - IAM user does not have active access keys older than 90 days
type RotateAccessKey90Days struct {
	metadata models.CheckMetadata
}

func NewRotateAccessKey90Days() *RotateAccessKey90Days {
	return &RotateAccessKey90Days{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_rotate_access_key_90_days",
			CheckTitle:      "IAM user does not have active access keys older than 90 days",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM user access keys** are assessed via the credential report. For each active key, the `last_rotated` timestamp is compared to `90 days`; keys exceeding this age are identified. Users without keys or with only recent rotations are noted.",
			RemediationText: "Apply **least privilege** and limit static credentials: - Rotate active access keys at or before `90 days` - Prefer **IAM roles** with short-lived tokens - Maintain only one active key during rotation; delete the old one - Monitor `last_used` and remove dormant keys - Automate alerts and periodic reviews of key age",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RotateAccessKey90Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *RotateAccessKey90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_rotate_access_key_90_days
	_ = client

	return findings, nil
}

// UserHardwareMfaEnabled - IAM user has hardware MFA enabled
type UserHardwareMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewUserHardwareMfaEnabled() *UserHardwareMfaEnabled {
	return &UserHardwareMfaEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_hardware_mfa_enabled",
			CheckTitle:      "IAM user has hardware MFA enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** are evaluated for **hardware MFA** enrollment, identifying physical tokens or security keys and distinguishing them from *virtual* or *SMS* MFA, as well as users without any MFA.",
			RemediationText: "Require **hardware-backed MFA** for all IAM users. Prefer **FIDO2 security keys** for phishing resistance over TOTP or SMS. Disallow SMS/virtual MFA for privileged roles. Enforce MFA for all access paths, apply **least privilege**, and provision multiple MFA devices per user for continuity.",
			Categories:      []string{"iam", "iam"},
		},
	}
}

func (c *UserHardwareMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserHardwareMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_hardware_mfa_enabled
	_ = client

	return findings, nil
}

// PasswordPolicyLowercase - IAM password policy requires at least one lowercase letter
type PasswordPolicyLowercase struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyLowercase() *PasswordPolicyLowercase {
	return &PasswordPolicyLowercase{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_lowercase",
			CheckTitle:      "IAM password policy requires at least one lowercase letter",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM password policy** requires at least one **lowercase** character in user passwords via the `Require lowercase` setting",
			RemediationText: "Adopt a strong password policy that: - Enables `Require at least one lowercase letter` plus uppercase, number, and symbol - Sets sufficient length and blocks reuse - Requires **MFA** for all users - Applies **least privilege** to limit blast radius",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyLowercase) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyLowercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_lowercase
	_ = client

	return findings, nil
}

// PolicyAttachedOnlyToGroupOrRoles - IAM user has no inline or attached policies
type PolicyAttachedOnlyToGroupOrRoles struct {
	metadata models.CheckMetadata
}

func NewPolicyAttachedOnlyToGroupOrRoles() *PolicyAttachedOnlyToGroupOrRoles {
	return &PolicyAttachedOnlyToGroupOrRoles{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_attached_only_to_group_or_roles",
			CheckTitle:      "IAM user has no inline or attached policies",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** have identity-based policies attached directly (managed or inline) instead of inheriting permissions via **groups** or **roles**.",
			RemediationText: "Assign permissions to **groups** (humans) and **roles** (workloads); avoid user-attached policies. Enforce **least privilege**, prefer federation and temporary credentials, and use tags or **permissions boundaries** to constrain scope. Review regularly to remove direct user policies and right-size access.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyAttachedOnlyToGroupOrRoles) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyAttachedOnlyToGroupOrRoles) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_attached_only_to_group_or_roles
	_ = client

	return findings, nil
}

// RootMfaEnabled - Root account has MFA enabled
type RootMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewRootMfaEnabled() *RootMfaEnabled {
	return &RootMfaEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_root_mfa_enabled",
			CheckTitle:      "Root account has MFA enabled",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamUser",
			Description:     "**AWS root user** with active credentials is assessed for **MFA activation**. The evaluation considers whether the root identity has a password or access keys and whether **MFA is enabled**. *If centralized root access is enabled in Organizations, the presence of individual root credentials is also noted.*",
			RemediationText: "Enable **MFA** for the root user, preferably **hardware-based** or a dedicated, managed device. Remove root access keys and avoid using root for daily tasks. Apply **least privilege** with IAM Identity Center for admins, and use Organizations to **centralize root access** and eliminate long-lived root credentials.",
			Categories:      []string{"iam", "iam"},
		},
	}
}

func (c *RootMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RootMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_root_mfa_enabled
	_ = client

	return findings, nil
}

// NoCustomPolicyPermissiveRoleAssumption - Custom IAM policy does not allow STS role assumption on wildcard resources
type NoCustomPolicyPermissiveRoleAssumption struct {
	metadata models.CheckMetadata
}

func NewNoCustomPolicyPermissiveRoleAssumption() *NoCustomPolicyPermissiveRoleAssumption {
	return &NoCustomPolicyPermissiveRoleAssumption{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_no_custom_policy_permissive_role_assumption",
			CheckTitle:      "Custom IAM policy does not allow STS role assumption on wildcard resources",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Custom IAM policies** with `Allow` statements that grant `sts:AssumeRole` (or `sts:*`/`*`) to a wildcard `Resource`.",
			RemediationText: "Apply **least privilege** to `sts:AssumeRole`: - Scope `Resource` to exact role ARNs - Require **MFA** and, for third parties, `ExternalId` - Enforce **permissions boundaries** and **SCPs** to block wildcards - Regularly remove unused role-assumption rights and **separate duties**",
			Categories:      []string{"iam"},
		},
	}
}

func (c *NoCustomPolicyPermissiveRoleAssumption) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoCustomPolicyPermissiveRoleAssumption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_no_custom_policy_permissive_role_assumption
	_ = client

	return findings, nil
}

// NoExpiredServerCertificatesStored - IAM server certificate is not expired
type NoExpiredServerCertificatesStored struct {
	metadata models.CheckMetadata
}

func NewNoExpiredServerCertificatesStored() *NoExpiredServerCertificatesStored {
	return &NoExpiredServerCertificatesStored{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_no_expired_server_certificates_stored",
			CheckTitle:      "IAM server certificate is not expired",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsCertificateManagerCertificate",
			Description:     "IAM server certificates stored in **AWS IAM** are evaluated for **expiration** by comparing their validity period to the current time. Certificates with a `NotAfter` date in the past are identified as expired.",
			RemediationText: "Remove **expired certificates** from IAM and ensure endpoints use current, trusted TLS. Prefer **AWS Certificate Manager** for issuance and auto-renewal, enforce **lifecycle management** with inventory, tagging, and alerts, and apply **least privilege** to certificate access with standardized rotation policies.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *NoExpiredServerCertificatesStored) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoExpiredServerCertificatesStored) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_no_expired_server_certificates_stored
	_ = client

	return findings, nil
}

// PasswordPolicyUppercase - IAM password policy requires at least one uppercase letter
type PasswordPolicyUppercase struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyUppercase() *PasswordPolicyUppercase {
	return &PasswordPolicyUppercase{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_uppercase",
			CheckTitle:      "IAM password policy requires at least one uppercase letter",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM account password policy** enforces the presence of **at least one uppercase letter** (`A-Z`) in IAM user passwords. *This evaluates whether the uppercase complexity rule is enabled for console passwords.*",
			RemediationText: "Enable the uppercase rule within a **strong password policy** that also requires length, lowercase, numbers, and symbols. Pair with **MFA** and **least privilege** to reduce blast radius. Regularly review policy effectiveness and prefer **federated SSO** to minimize long-lived IAM passwords.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyUppercase) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyUppercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_uppercase
	_ = client

	return findings, nil
}

// RoleCrossServiceConfusedDeputyPrevention - IAM service role prevents cross-service confused deputy attack
type RoleCrossServiceConfusedDeputyPrevention struct {
	metadata models.CheckMetadata
}

func NewRoleCrossServiceConfusedDeputyPrevention() *RoleCrossServiceConfusedDeputyPrevention {
	return &RoleCrossServiceConfusedDeputyPrevention{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_cross_service_confused_deputy_prevention",
			CheckTitle:      "IAM service role prevents cross-service confused deputy attack",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamRole",
			Description:     "**IAM service role** trust policies restrict **AWS service principals** to expected sources using global condition keys like `aws:SourceArn` or `aws:SourceAccount`, avoiding overly broad `sts:AssumeRole` trust relationships.",
			RemediationText: "Constrain service-role trust to expected callers using `aws:SourceArn`/`aws:SourceAccount` to bind service principals to specific resources or accounts. If unsupported, apply equivalent limits in resource-based policies or org-level controls. Apply **least privilege** and review trust relationships regularly.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RoleCrossServiceConfusedDeputyPrevention) Metadata() models.CheckMetadata { return c.metadata }

func (c *RoleCrossServiceConfusedDeputyPrevention) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_role_cross_service_confused_deputy_prevention
	_ = client

	return findings, nil
}

// CustomerUnattachedPolicyNoAdministrativePrivileges - Unattached customer managed IAM policy does not allow '*:*' administrative privileges
type CustomerUnattachedPolicyNoAdministrativePrivileges struct {
	metadata models.CheckMetadata
}

func NewCustomerUnattachedPolicyNoAdministrativePrivileges() *CustomerUnattachedPolicyNoAdministrativePrivileges {
	return &CustomerUnattachedPolicyNoAdministrativePrivileges{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_customer_unattached_policy_no_administrative_privileges",
			CheckTitle:      "Unattached customer managed IAM policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Customer-managed IAM policies** that are **unattached** are evaluated for statements granting **full administrative access** using `*:*` wildcards. The focus is on policies whose documents include unrestricted actions on all resources.",
			RemediationText: "Remove or redesign these policies to enforce **least privilege**: - Avoid `*` in actions/resources; scope precisely and use conditions - Apply **permissions boundaries** and **SCPs** as guardrails - Require peer review and policy validation before attachment - Use analysis tools to refine permissions and delete unused policies",
			Categories:      []string{"iam"},
		},
	}
}

func (c *CustomerUnattachedPolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CustomerUnattachedPolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_customer_unattached_policy_no_administrative_privileges
	_ = client

	return findings, nil
}

// InlinePolicyNoWildcardMarketplaceSubscribe - Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources
type InlinePolicyNoWildcardMarketplaceSubscribe struct {
	metadata models.CheckMetadata
}

func NewInlinePolicyNoWildcardMarketplaceSubscribe() *InlinePolicyNoWildcardMarketplaceSubscribe {
	return &InlinePolicyNoWildcardMarketplaceSubscribe{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_wildcard_marketplace_subscribe",
			CheckTitle:      "Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM inline policies** are analyzed to identify statements that grant `aws-marketplace:Subscribe` on all resources (`*`). This action controls the ability to subscribe to AWS Marketplace products, including **Amazon Bedrock foundation models**, and should be scoped to specific product ARNs to enforce least privilege.",
			RemediationText: "Replace `Resource: \"*\"` with specific, approved AWS Marketplace product ARNs. Prefer managed policies over inline and apply the principle of least privilege to `aws-marketplace:Subscribe` permissions to prevent unauthorized subscriptions to costly Bedrock models and other Marketplace products.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *InlinePolicyNoWildcardMarketplaceSubscribe) Metadata() models.CheckMetadata { return c.metadata }

func (c *InlinePolicyNoWildcardMarketplaceSubscribe) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_inline_policy_no_wildcard_marketplace_subscribe
	_ = client

	return findings, nil
}

// PolicyAllowsPrivilegeEscalation - Customer managed IAM policy does not allow actions that can lead to privilege escalation
type PolicyAllowsPrivilegeEscalation struct {
	metadata models.CheckMetadata
}

func NewPolicyAllowsPrivilegeEscalation() *PolicyAllowsPrivilegeEscalation {
	return &PolicyAllowsPrivilegeEscalation{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_allows_privilege_escalation",
			CheckTitle:      "Customer managed IAM policy does not allow actions that can lead to privilege escalation",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Customer-managed IAM policies** are evaluated for **permissions that enable privilege escalation**, including creating or updating policies, altering role trust, attaching higher-privilege policies, or using `iam:PassRole` to obtain broader access.",
			RemediationText: "Apply **least privilege** to customer policies: - Avoid wildcards in `Action` and `Resource` - Remove or tightly scope `iam:PassRole`, policy attach/update, and trust-policy changes - Use conditions like `iam:PassedToService` and tags to constrain use - Enforce **permissions boundaries** and **SCPs** - Separate duties with change review",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyAllowsPrivilegeEscalation) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyAllowsPrivilegeEscalation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_allows_privilege_escalation
	_ = client

	return findings, nil
}

// PasswordPolicyNumber - IAM password policy requires at least one number
type PasswordPolicyNumber struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyNumber() *PasswordPolicyNumber {
	return &PasswordPolicyNumber{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_number",
			CheckTitle:      "IAM password policy requires at least one number",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM account password policy** requires at least one **numeric character** (`0-9`) in IAM user passwords",
			RemediationText: "Enforce the password policy option to `require at least one number`. Combine with strong length, mixed case, and symbols, and prevent reuse. Enable **MFA** for all users and prefer **federated access** to limit static credentials, supporting **defense in depth** against guessing attacks.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyNumber) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyNumber) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_number
	_ = client

	return findings, nil
}

// PasswordPolicySymbol - IAM password policy requires at least one symbol
type PasswordPolicySymbol struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicySymbol() *PasswordPolicySymbol {
	return &PasswordPolicySymbol{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_symbol",
			CheckTitle:      "IAM password policy requires at least one symbol",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM account password policy** includes the `Require at least one non-alphanumeric character` rule for IAM user passwords",
			RemediationText: "Enforce the `Require at least one non-alphanumeric character` rule in the **IAM password policy**, alongside strong minimum length, mixed character sets, and password reuse prevention. Apply **MFA** for all human users and uphold **least privilege** to limit impact. *Consider periodic rotation based on risk.*",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicySymbol) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicySymbol) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_symbol
	_ = client

	return findings, nil
}

// GroupAdministratorAccessPolicy - IAM group does not have AdministratorAccess policy attached
type GroupAdministratorAccessPolicy struct {
	metadata models.CheckMetadata
}

func NewGroupAdministratorAccessPolicy() *GroupAdministratorAccessPolicy {
	return &GroupAdministratorAccessPolicy{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_group_administrator_access_policy",
			CheckTitle:      "IAM group does not have AdministratorAccess policy attached",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamGroup",
			Description:     "**IAM groups** are assessed for the AWS-managed `AdministratorAccess` policy attachment. The finding reports any group that has this policy among its attached permissions.",
			RemediationText: "Remove `AdministratorAccess` from groups. Apply **least privilege** with task-scoped, customer-managed policies and **separation of duties**. Use roles for admin tasks with MFA, time-bound elevation, and auditing. Regularly review group membership and permissions; prefer **defense-in-depth** guardrails.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *GroupAdministratorAccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *GroupAdministratorAccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_group_administrator_access_policy
	_ = client

	return findings, nil
}

// AwsAttachedPolicyNoAdministrativePrivileges - Attached AWS-managed IAM policy does not allow '*:*' administrative privileges
type AwsAttachedPolicyNoAdministrativePrivileges struct {
	metadata models.CheckMetadata
}

func NewAwsAttachedPolicyNoAdministrativePrivileges() *AwsAttachedPolicyNoAdministrativePrivileges {
	return &AwsAttachedPolicyNoAdministrativePrivileges{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_aws_attached_policy_no_administrative_privileges",
			CheckTitle:      "Attached AWS-managed IAM policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM AWS-managed policies** attached to identities are inspected for statements that allow `Action:'*'` on `Resource:'*'`-i.e., full administrative `*:*` permissions",
			RemediationText: "Apply **least privilege**: avoid attaching AWS-managed policies that grant `*:*`. - Use **customer-managed, scoped policies** per role - Enforce **separation of duties** and **permissions boundaries** - Prefer **temporary, time-bound elevation** for emergencies with MFA - Regularly review access and use conditions to constrain context",
			Categories:      []string{"iam"},
		},
	}
}

func (c *AwsAttachedPolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata { return c.metadata }

func (c *AwsAttachedPolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_aws_attached_policy_no_administrative_privileges
	_ = client

	return findings, nil
}

// AvoidRootUsage - AWS account root user has not been used in the last day
type AvoidRootUsage struct {
	metadata models.CheckMetadata
}

func NewAvoidRootUsage() *AvoidRootUsage {
	return &AvoidRootUsage{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_avoid_root_usage",
			CheckTitle:      "AWS account root user has not been used in the last day",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "**AWS IAM root user** activity is assessed by inspecting `last-used` timestamps for the root password and access keys. The finding indicates when the root identity has been used recently for console or programmatic access.",
			RemediationText: "Minimize `root` usage by applying **least privilege** with admin roles or federated SSO and temporary credentials. - Enforce **MFA** on root - Avoid or remove root access keys - Require multi-person approval - **Monitor and alert** on any root sign-in - Use org guardrails for **defense in depth**",
			Categories:      []string{"iam"},
		},
	}
}

func (c *AvoidRootUsage) Metadata() models.CheckMetadata { return c.metadata }

func (c *AvoidRootUsage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_avoid_root_usage
	_ = client

	return findings, nil
}

// UserAccessNotStaleToSagemaker - Regular SageMaker access ensures IAM users retain only actively used permissions
type UserAccessNotStaleToSagemaker struct {
	metadata models.CheckMetadata
}

func NewUserAccessNotStaleToSagemaker() *UserAccessNotStaleToSagemaker {
	return &UserAccessNotStaleToSagemaker{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_access_not_stale_to_sagemaker",
			CheckTitle:      "Regular SageMaker access ensures IAM users retain only actively used permissions",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users granted **SageMaker** permissions are evaluated for recent service usage. Users whose last SageMaker access exceeds the configured threshold (default **90 days**) or that have **never** accessed SageMaker are flagged, indicating stale permissions that should be reviewed.",
			RemediationText: "Apply the **principle of least privilege** by regularly reviewing IAM Access Advisor data and revoking SageMaker permissions that are no longer actively used. Establish a periodic access review process and automate alerts for stale permissions to maintain a minimal attack surface.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserAccessNotStaleToSagemaker) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserAccessNotStaleToSagemaker) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_access_not_stale_to_sagemaker
	_ = client

	return findings, nil
}

// PasswordPolicyReuse24 - IAM password policy prevents reuse of the last 24 passwords
type PasswordPolicyReuse24 struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyReuse24() *PasswordPolicyReuse24 {
	return &PasswordPolicyReuse24{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_reuse_24",
			CheckTitle:      "IAM password policy prevents reuse of the last 24 passwords",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM account password policy** uses **password reuse prevention** set to `24` remembered passwords (maximum history) for IAM users",
			RemediationText: "Set the password policy to remember `24` previous passwords to block reuse. Combine with **MFA**, strong length and complexity, and avoid rotation practices that encourage predictable patterns. Apply **least privilege** and monitor authentication events as part of **defense in depth**.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyReuse24) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyReuse24) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_reuse_24
	_ = client

	return findings, nil
}

// UserNoSetupInitialAccessKey - IAM user does not have active access keys that have never been used
type UserNoSetupInitialAccessKey struct {
	metadata models.CheckMetadata
}

func NewUserNoSetupInitialAccessKey() *UserNoSetupInitialAccessKey {
	return &UserNoSetupInitialAccessKey{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_no_setup_initial_access_key",
			CheckTitle:      "IAM user does not have active access keys that have never been used",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** with a console password and active **access keys** that have `last_used` as `N/A` are identified. This highlights accounts where programmatic credentials exist but have never been exercised.",
			RemediationText: "Apply **least privilege** to programmatic access: - Do not provision access keys by default for console users - Prefer **IAM roles** and temporary credentials - Require justification and time-bounded key creation - Regularly review usage and disable/delete unused keys - Limit to one active key per user and enforce rotation with monitoring",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserNoSetupInitialAccessKey) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserNoSetupInitialAccessKey) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_no_setup_initial_access_key
	_ = client

	return findings, nil
}

// UserAdministratorAccessPolicy - IAM user does not have AdministratorAccess policy attached
type UserAdministratorAccessPolicy struct {
	metadata models.CheckMetadata
}

func NewUserAdministratorAccessPolicy() *UserAdministratorAccessPolicy {
	return &UserAdministratorAccessPolicy{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_administrator_access_policy",
			CheckTitle:      "IAM user does not have AdministratorAccess policy attached",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** are evaluated for a direct attachment of the AWS managed policy `AdministratorAccess`. The finding identifies identities where this policy appears among the user's attached policies.",
			RemediationText: "Remove direct `AdministratorAccess` from users. - Apply **least privilege** with scoped policies - Use **federation** and **roles** for temporary admin access - Enforce **separation of duties** and approvals - Add guardrails (SCPs, permissions boundaries) - Require **MFA** and rotate any remaining long-lived credentials",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserAdministratorAccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserAdministratorAccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_administrator_access_policy
	_ = client

	return findings, nil
}

// RoleCrossAccountReadonlyaccessPolicy - IAM role does not grant ReadOnlyAccess to external AWS accounts
type RoleCrossAccountReadonlyaccessPolicy struct {
	metadata models.CheckMetadata
}

func NewRoleCrossAccountReadonlyaccessPolicy() *RoleCrossAccountReadonlyaccessPolicy {
	return &RoleCrossAccountReadonlyaccessPolicy{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_cross_account_readonlyaccess_policy",
			CheckTitle:      "IAM role does not grant ReadOnlyAccess to external AWS accounts",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamRole",
			Description:     "**IAM roles** are assessed for the AWS-managed **ReadOnlyAccess** policy combined with a trust policy that allows **external AWS principals** or `*`. This identifies roles that expose broad read permissions to other accounts.",
			RemediationText: "Avoid attaching `ReadOnlyAccess` to roles trusted by other accounts. Apply **least privilege** with custom, tightly scoped policies. Restrict trust to explicit principals, avoid `*`, and use conditions like `aws:PrincipalOrgID` and `sts:ExternalId` for **defense in depth**.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RoleCrossAccountReadonlyaccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *RoleCrossAccountReadonlyaccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_role_cross_account_readonlyaccess_policy
	_ = client

	return findings, nil
}

// PolicyNoAgentcoreWorkloadAccessTokenWildcard - Custom IAM policy scopes Bedrock AgentCore workload access token retrieval to workload identity ARNs
type PolicyNoAgentcoreWorkloadAccessTokenWildcard struct {
	metadata models.CheckMetadata
}

func NewPolicyNoAgentcoreWorkloadAccessTokenWildcard() *PolicyNoAgentcoreWorkloadAccessTokenWildcard {
	return &PolicyNoAgentcoreWorkloadAccessTokenWildcard{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_agentcore_workload_access_token_wildcard",
			CheckTitle:      "Custom IAM policy scopes Bedrock AgentCore workload access token retrieval to workload identity ARNs",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Customer-managed IAM policies** are examined for `Allow` statements granting `bedrock-agentcore:GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT` or `GetWorkloadAccessTokenForUserId` over resources that reach a workload identity other than the caller's own -- `*`, or an AgentCore ARN whose resource field wildcards past `workload-identity-directory`.",
			RemediationText: "Scope the workload access token actions to the workload identity ARNs the policy holder acts for, never `*`. AWS states the security binding of `GetWorkloadAccessTokenForUserId` rests on IAM scope, since the platform treats the user ID as an opaque unverified string: **do not grant it broadly via managed policies or wildcard resource statements**. Prefer `GetWorkloadAccessTokenForJWT` and deny the user-ID path where a JWT is always available.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyNoAgentcoreWorkloadAccessTokenWildcard) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyNoAgentcoreWorkloadAccessTokenWildcard) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_no_agentcore_workload_access_token_wildcard
	_ = client

	return findings, nil
}

// InlinePolicyNoFullAccessToKms - Inline IAM policy does not allow kms:* privileges
type InlinePolicyNoFullAccessToKms struct {
	metadata models.CheckMetadata
}

func NewInlinePolicyNoFullAccessToKms() *InlinePolicyNoFullAccessToKms {
	return &InlinePolicyNoFullAccessToKms{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_full_access_to_kms",
			CheckTitle:      "Inline IAM policy does not allow kms:* privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM inline policies** are analyzed to identify statements that grant **unrestricted AWS KMS access** via the wildcard action `kms:*`.",
			RemediationText: "Replace `kms:*` with **least-privilege**, action-scoped permissions limited to required operations and specific key ARNs. Enforce **separation of duties** for key admins vs users. Prefer **managed policies** over inline and apply guardrails (permissions boundaries/SCPs). Add conditions to constrain service, region, and encryption context.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *InlinePolicyNoFullAccessToKms) Metadata() models.CheckMetadata { return c.metadata }

func (c *InlinePolicyNoFullAccessToKms) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_inline_policy_no_full_access_to_kms
	_ = client

	return findings, nil
}

// RoleAdministratoraccessPolicy - IAM role does not have AdministratorAccess policy attached
type RoleAdministratoraccessPolicy struct {
	metadata models.CheckMetadata
}

func NewRoleAdministratoraccessPolicy() *RoleAdministratoraccessPolicy {
	return &RoleAdministratoraccessPolicy{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_administratoraccess_policy",
			CheckTitle:      "IAM role does not have AdministratorAccess policy attached",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamRole",
			Description:     "**IAM roles** (excluding service roles) are evaluated for attachment of the AWS-managed `AdministratorAccess` policy. Attachment indicates the role holds unrestricted permissions across services and resources.",
			RemediationText: "Apply **least privilege**: avoid attaching `AdministratorAccess` to roles. Grant only task-scoped permissions with custom policies and enforce **separation of duties**. Use **permissions boundaries**, **SCPs**, and policy conditions to constrain power. Require MFA for break-glass admins, time-bound elevation with approval, and refine access using **Access Analyzer**.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RoleAdministratoraccessPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *RoleAdministratoraccessPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_role_administratoraccess_policy
	_ = client

	return findings, nil
}

// PolicyNoFullAccessToCloudtrail - Customer managed IAM policy does not allow cloudtrail:* privileges
type PolicyNoFullAccessToCloudtrail struct {
	metadata models.CheckMetadata
}

func NewPolicyNoFullAccessToCloudtrail() *PolicyNoFullAccessToCloudtrail {
	return &PolicyNoFullAccessToCloudtrail{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_full_access_to_cloudtrail",
			CheckTitle:      "Customer managed IAM policy does not allow cloudtrail:* privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "Custom IAM policies are reviewed for statements that grant **full CloudTrail access** via the `cloudtrail:*` wildcard, indicating unrestricted permission to all CloudTrail actions.",
			RemediationText: "Apply **least privilege**: avoid `cloudtrail:*` and allow only required actions. Enforce **separation of duties** for trail management. Use **permissions boundaries** or **SCPs** to block broad CloudTrail access, and validate policies regularly to refine scopes.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyNoFullAccessToCloudtrail) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyNoFullAccessToCloudtrail) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_no_full_access_to_cloudtrail
	_ = client

	return findings, nil
}

// PolicyNoFullAccessToKms - Custom IAM policy does not allow 'kms:*' privileges
type PolicyNoFullAccessToKms struct {
	metadata models.CheckMetadata
}

func NewPolicyNoFullAccessToKms() *PolicyNoFullAccessToKms {
	return &PolicyNoFullAccessToKms{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_no_full_access_to_kms",
			CheckTitle:      "Custom IAM policy does not allow 'kms:*' privileges",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Customer-managed IAM policies** are examined for statements that grant **AWS KMS** full access using `kms:*`. The focus is on policies allowing service-wide actions rather than narrowly scoped, key-specific permissions.",
			RemediationText: "Adopt **least privilege** and **separation of duties**: - Replace `kms:*` with only needed actions scoped to specific key ARNs - Apply policy conditions (e.g., `kms:ViaService`) and guardrails (permissions boundaries/SCPs) - Monitor KMS usage and refine access based on activity",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyNoFullAccessToKms) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyNoFullAccessToKms) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_no_full_access_to_kms
	_ = client

	return findings, nil
}

// PolicyCloudshellAdminNotAttached - No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached
type PolicyCloudshellAdminNotAttached struct {
	metadata models.CheckMetadata
}

func NewPolicyCloudshellAdminNotAttached() *PolicyCloudshellAdminNotAttached {
	return &PolicyCloudshellAdminNotAttached{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_cloudshell_admin_not_attached",
			CheckTitle:      "No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM identities** with the AWS managed policy `AWSCloudShellFullAccess` attached are identified across users, groups, and roles. This indicates principals are granted `cloudshell:*` on `*`, enabling full CloudShell features, including environment startup and file transfer.",
			RemediationText: "Detach `AWSCloudShellFullAccess` from identities. Apply **least privilege**: permit CloudShell only when necessary via narrowly scoped permissions, restricted roles, short-lived sessions, and approvals. Prefer controlled alternatives (local CLI, bastion, or Session Manager). Enforce **separation of duties** and monitor usage.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyCloudshellAdminNotAttached) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyCloudshellAdminNotAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_cloudshell_admin_not_attached
	_ = client

	return findings, nil
}

// RoleServiceTrustRestrictsSourceToAccount - IAM role trust policy confines AWS service principals to a specific source account
type RoleServiceTrustRestrictsSourceToAccount struct {
	metadata models.CheckMetadata
}

func NewRoleServiceTrustRestrictsSourceToAccount() *RoleServiceTrustRestrictsSourceToAccount {
	return &RoleServiceTrustRestrictsSourceToAccount{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_role_service_trust_restricts_source_to_account",
			CheckTitle:      "IAM role trust policy confines AWS service principals to a specific source account",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamRole",
			Description:     "Trust-policy statements letting an **AWS service principal** call `sts:AssumeRole` confine the request source to one account -- via `aws:SourceAccount`, an account-bearing `aws:SourceArn`, or an organization-scoped source. Scope: statements whose condition binds no account, and trust policies that are not a plain service role. Unconditional service roles go to the related check.",
			RemediationText: "Bind every service-principal trust statement to an account with `aws:SourceAccount`, or with an `aws:SourceArn` whose account field holds the account ID. AWS documents `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID` and `aws:SourceOrgPaths` as alternatives, so any one of them satisfies this check -- except an ARN with no account field, which needs `aws:SourceAccount` alongside it.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *RoleServiceTrustRestrictsSourceToAccount) Metadata() models.CheckMetadata { return c.metadata }

func (c *RoleServiceTrustRestrictsSourceToAccount) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_role_service_trust_restricts_source_to_account
	_ = client

	return findings, nil
}

// UserWithTemporaryCredentials - IAM user does not use long-lived credentials to access services other than IAM or STS
type UserWithTemporaryCredentials struct {
	metadata models.CheckMetadata
}

func NewUserWithTemporaryCredentials() *UserWithTemporaryCredentials {
	return &UserWithTemporaryCredentials{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_with_temporary_credentials",
			CheckTitle:      "IAM user does not use long-lived credentials to access services other than IAM or STS",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users are assessed for activity using **long-lived access keys**. Use of static credentials to access services other than IAM or STS indicates reliance on permanent keys instead of **temporary role-based credentials**.",
			RemediationText: "Adopt **temporary credentials** via IAM roles and federation for humans and workloads. Remove or restrict long-term keys; *if unavoidable*, apply **least privilege**, require **MFA**, rotate aggressively, and monitor usage. Prefer short session durations and session conditions to limit blast radius.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserWithTemporaryCredentials) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserWithTemporaryCredentials) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_with_temporary_credentials
	_ = client

	return findings, nil
}

// PolicyPassroleToBedrockAgentcoreRestricted - Custom IAM policy restricts iam:PassRole to Bedrock AgentCore to specific roles
type PolicyPassroleToBedrockAgentcoreRestricted struct {
	metadata models.CheckMetadata
}

func NewPolicyPassroleToBedrockAgentcoreRestricted() *PolicyPassroleToBedrockAgentcoreRestricted {
	return &PolicyPassroleToBedrockAgentcoreRestricted{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_policy_passrole_to_bedrock_agentcore_restricted",
			CheckTitle:      "Custom IAM policy restricts iam:PassRole to Bedrock AgentCore to specific roles",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamPolicy",
			Description:     "**Customer-managed IAM policies** are examined for `Allow` statements granting `iam:PassRole` over every role -- `Resource` `*`, or an IAM ARN whose resource field is nothing but wildcards -- where the passed role can reach **Bedrock AgentCore**: the statement pins `iam:PassedToService` to an AgentCore principal, or sets no such condition while the policy allows an AgentCore action.",
			RemediationText: "Name the roles that may be passed instead of allowing every role. AWS's own AgentCore Evaluations reference policy shows the shape: `iam:PassRole` on `arn:aws:iam::*:role/AgentCoreEvaluationRole*` under `StringEquals iam:PassedToService = bedrock-agentcore.amazonaws.com`. A role-name prefix satisfies this check; `*` and `role/*` do not. Keep the condition as well, so the same roles cannot be handed to another service.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PolicyPassroleToBedrockAgentcoreRestricted) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyPassroleToBedrockAgentcoreRestricted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_policy_passrole_to_bedrock_agentcore_restricted
	_ = client

	return findings, nil
}

// SupportRoleCreated - At least one IAM role has the AWSSupportAccess managed policy attached
type SupportRoleCreated struct {
	metadata models.CheckMetadata
}

func NewSupportRoleCreated() *SupportRoleCreated {
	return &SupportRoleCreated{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_support_role_created",
			CheckTitle:      "At least one IAM role has the AWSSupportAccess managed policy attached",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamRole",
			Description:     "Presence of an **IAM role** that has the AWS managed `AWSSupportAccess` policy attached, designating a support role for interacting with **AWS Support Center** and related tooling.",
			RemediationText: "Create a dedicated IAM role for AWS Support with `AWSSupportAccess` and: - Restrict who can assume it; require MFA and time-bound access - Enforce **least privilege** and **separation of duties** - Monitor usage via audit logs and review assignments regularly",
			Categories:      []string{"iam"},
		},
	}
}

func (c *SupportRoleCreated) Metadata() models.CheckMetadata { return c.metadata }

func (c *SupportRoleCreated) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_support_role_created
	_ = client

	return findings, nil
}

// UserAccesskeyUnused - IAM user does not have unused access keys older than 45 days
type UserAccesskeyUnused struct {
	metadata models.CheckMetadata
}

func NewUserAccesskeyUnused() *UserAccesskeyUnused {
	return &UserAccesskeyUnused{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_accesskey_unused",
			CheckTitle:      "IAM user does not have unused access keys older than 45 days",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** are evaluated for **active access keys** whose `last-used` timestamp exceeds `max_unused_access_keys_days` (default `45`). Users without access keys, or whose keys were used within this window, are reported separately.",
			RemediationText: "Disable or delete **unused access keys** promptly and prefer **IAM roles** with temporary credentials. Enforce **least privilege**, rotation, and time-bounded access. Monitor `last-used` metadata and automate deactivation of idle keys. Use federation/SSO to avoid long-lived user keys.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserAccesskeyUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserAccesskeyUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_accesskey_unused
	_ = client

	return findings, nil
}

// AdministratorAccessWithMfa - IAM group members granted AdministratorAccess have MFA enabled
type AdministratorAccessWithMfa struct {
	metadata models.CheckMetadata
}

func NewAdministratorAccessWithMfa() *AdministratorAccessWithMfa {
	return &AdministratorAccessWithMfa{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_administrator_access_with_mfa",
			CheckTitle:      "IAM group members granted AdministratorAccess have MFA enabled",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamGroup",
			Description:     "**IAM groups** with the `AdministratorAccess` managed policy are assessed to ensure all member users have **active MFA**. The finding highlights any administrator group that includes a user without MFA enrollment or activation.",
			RemediationText: "Enforce **MFA** for all administrator identities. - Add conditions (e.g., `aws:MultiFactorAuthPresent`) to privileged permissions - Prefer **hardware/FIDO2** devices - Apply **least privilege** and favor **roles/SSO** over users - Continuously monitor MFA status and remove unused admin access",
			Categories:      []string{"iam", "iam"},
		},
	}
}

func (c *AdministratorAccessWithMfa) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdministratorAccessWithMfa) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_administrator_access_with_mfa
	_ = client

	return findings, nil
}

// UserAccessNotStaleToBedrock - Regular Bedrock access ensures IAM users retain only actively used permissions
type UserAccessNotStaleToBedrock struct {
	metadata models.CheckMetadata
}

func NewUserAccessNotStaleToBedrock() *UserAccessNotStaleToBedrock {
	return &UserAccessNotStaleToBedrock{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_access_not_stale_to_bedrock",
			CheckTitle:      "Regular Bedrock access ensures IAM users retain only actively used permissions",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "IAM users granted **Bedrock** permissions are evaluated for recent service usage. Users whose last Bedrock access exceeds the configured threshold (default **60 days**) or that have **never** accessed Bedrock are flagged, indicating stale permissions that should be reviewed.",
			RemediationText: "Apply the **principle of least privilege** by regularly reviewing IAM Access Advisor data and revoking Bedrock permissions that are no longer actively used. Establish a periodic access review process and automate alerts for stale permissions to maintain a minimal attack surface.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserAccessNotStaleToBedrock) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserAccessNotStaleToBedrock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_access_not_stale_to_bedrock
	_ = client

	return findings, nil
}

// InlinePolicyNoAdministrativePrivileges - Inline IAM policy does not allow '*:*' administrative privileges
type InlinePolicyNoAdministrativePrivileges struct {
	metadata models.CheckMetadata
}

func NewInlinePolicyNoAdministrativePrivileges() *InlinePolicyNoAdministrativePrivileges {
	return &InlinePolicyNoAdministrativePrivileges{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_inline_policy_no_administrative_privileges",
			CheckTitle:      "Inline IAM policy does not allow '*:*' administrative privileges",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM inline policies** on identities are evaluated for statements allowing `Action:\"*\"` on `Resource:\"*\"`, which indicates **unrestricted administrative access**.",
			RemediationText: "Remove `Action:\"*\"` with `Resource:\"*\"` from inline policies. Apply **least privilege** with granular actions scoped to specific resources and conditions. Prefer versioned customer-managed policies over broad inline ones, enforce **separation of duties**, and use **permissions boundaries** or guardrails to prevent accidental admin grants.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *InlinePolicyNoAdministrativePrivileges) Metadata() models.CheckMetadata { return c.metadata }

func (c *InlinePolicyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_inline_policy_no_administrative_privileges
	_ = client

	return findings, nil
}

// NoRootAccessKey - Root account has no active access keys
type NoRootAccessKey struct {
	metadata models.CheckMetadata
}

func NewNoRootAccessKey() *NoRootAccessKey {
	return &NoRootAccessKey{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_no_root_access_key",
			CheckTitle:      "Root account has no active access keys",
			ServiceName:     "iam",
			Severity:        "critical",
			ResourceType:    "AwsIamAccessKey",
			Description:     "**AWS root user** is evaluated for **active access keys**. It identifies whether the root identity has one or two programmatic credentials and notes when organization-level root credential management is present.",
			RemediationText: "Delete and prohibit **root access keys**. Use **IAM roles** and temporary credentials with **least privilege** for all automation. Enable **MFA on root**, limit root to break-glass use, and continuously monitor for any new root keys. *Where applicable*, apply organization-wide controls to enforce this.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *NoRootAccessKey) Metadata() models.CheckMetadata { return c.metadata }

func (c *NoRootAccessKey) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_no_root_access_key
	_ = client

	return findings, nil
}

// UserMfaEnabledConsoleAccess - IAM user has MFA enabled for console access or no console password is set
type UserMfaEnabledConsoleAccess struct {
	metadata models.CheckMetadata
}

func NewUserMfaEnabledConsoleAccess() *UserMfaEnabledConsoleAccess {
	return &UserMfaEnabledConsoleAccess{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_mfa_enabled_console_access",
			CheckTitle:      "IAM user has MFA enabled for console access or no console password is set",
			ServiceName:     "iam",
			Severity:        "high",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** that have a console password are expected to have **multi-factor authentication** enabled. The evaluation identifies users who can sign in to the AWS Management Console but do not have an active MFA device associated.",
			RemediationText: "Enforce **MFA** for all console-capable IAM users; prefer **phishing-resistant** authenticators (FIDO2/security keys) and register backups. Remove console passwords for users that don't need them and favor **federation/SSO**. Apply least privilege and require MFA for sensitive actions to prevent unauthorized changes.",
			Categories:      []string{"iam", "iam"},
		},
	}
}

func (c *UserMfaEnabledConsoleAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserMfaEnabledConsoleAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_mfa_enabled_console_access
	_ = client

	return findings, nil
}

// PasswordPolicyExpiresPasswordsWithin90DaysOrLess - IAM account password policy enforces password expiration within 90 days or less
type PasswordPolicyExpiresPasswordsWithin90DaysOrLess struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyExpiresPasswordsWithin90DaysOrLess() *PasswordPolicyExpiresPasswordsWithin90DaysOrLess {
	return &PasswordPolicyExpiresPasswordsWithin90DaysOrLess{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_password_policy_expires_passwords_within_90_days_or_less",
			CheckTitle:      "IAM account password policy enforces password expiration within 90 days or less",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM account password policy** sets a **password expiration period** for IAM user console logins; configuration is aligned when rotation is enabled and set to `<= 90` days.",
			RemediationText: "Enforce **password rotation** at `<= 90` days and **prevent reuse**. Pair with **MFA**, strong length/complexity, and prefer **federation/SSO** to reduce static passwords. Apply **least privilege**, monitor sign-ins, and remove inactive console passwords to limit exposure.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyExpiresPasswordsWithin90DaysOrLess) Metadata() models.CheckMetadata { return c.metadata }

func (c *PasswordPolicyExpiresPasswordsWithin90DaysOrLess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_password_policy_expires_passwords_within_90_days_or_less
	_ = client

	return findings, nil
}

// SecurityauditRoleCreated - At least one IAM role has the SecurityAudit AWS managed policy attached
type SecurityauditRoleCreated struct {
	metadata models.CheckMetadata
}

func NewSecurityauditRoleCreated() *SecurityauditRoleCreated {
	return &SecurityauditRoleCreated{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_securityaudit_role_created",
			CheckTitle:      "At least one IAM role has the SecurityAudit AWS managed policy attached",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamPolicy",
			Description:     "**IAM roles** with the AWS managed `SecurityAudit` policy (`arn:aws:iam::aws:policy/SecurityAudit`) are identified. The focus is on whether a role exists that grants read-only visibility into security-relevant configuration across AWS services.",
			RemediationText: "Establish a dedicated **audit role** and attach the AWS managed `SecurityAudit` policy. Enforce **least privilege** and **separation of duties**: restrict who can assume it, require **MFA**, monitor usage, and avoid write permissions. Prefer **federated access** and regularly review and rotate access.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *SecurityauditRoleCreated) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecurityauditRoleCreated) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_securityaudit_role_created
	_ = client

	return findings, nil
}

// UserTwoActiveAccessKey - IAM user has at most one active access key
type UserTwoActiveAccessKey struct {
	metadata models.CheckMetadata
}

func NewUserTwoActiveAccessKey() *UserTwoActiveAccessKey {
	return &UserTwoActiveAccessKey{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_user_two_active_access_key",
			CheckTitle:      "IAM user has at most one active access key",
			ServiceName:     "iam",
			Severity:        "medium",
			ResourceType:    "AwsIamUser",
			Description:     "**IAM users** are evaluated for having **two `Active` access keys** simultaneously. The check identifies users whose two access key slots are enabled at the same time.",
			RemediationText: "Maintain **one `Active` access key** per IAM user; permit only a brief overlap for rotation, then promptly deactivate and delete the old key. Prefer **temporary credentials** via roles/federation over long-lived keys. Apply **least privilege**, periodic rotation, and monitor for unused or aged keys.",
			Categories:      []string{"iam"},
		},
	}
}

func (c *UserTwoActiveAccessKey) Metadata() models.CheckMetadata { return c.metadata }

func (c *UserTwoActiveAccessKey) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for iam_user_two_active_access_key
	_ = client

	return findings, nil
}
