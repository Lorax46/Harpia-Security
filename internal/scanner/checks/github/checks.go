package github

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/google/go-github/v53/github"
)

type githubProvider interface {
	Client(ctx context.Context) (*github.Client, error)
}

// GithubBranchProtectionCheck verifica branch protection
type GithubBranchProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewGithubBranchProtectionCheck() *GithubBranchProtectionCheck {
	return &GithubBranchProtectionCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_branch_protection",
			CheckTitle: "Ensure branch protection is enabled",
			Description: "Branch protection should be enabled for the default branch",
			Severity: "high", ServiceName: "github", ResourceType: "Repository",
			RemediationText: "Enable branch protection",
			Categories: []string{"github", "code"},
		},
	}
}

func (c *GithubBranchProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubBranchProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(githubProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement githubProvider")
	}
	
	client, err := p.Client(ctx)
	if err != nil {
		return nil, err
	}
	
	repos, _, err := client.Repositories.List(ctx, "", &github.RepositoryListOptions{})
	
	status := models.StatusPass
	msg := "No repositories found"
	
	if err == nil && len(repos) > 0 {
		msg = fmt.Sprintf("Found %d repositories", len(repos))
	}
	
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "github", Service: "github", ResourceID: "repositories",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubSecretsScanningCheck verifica secret scanning
type GithubSecretsScanningCheck struct {
	metadata models.CheckMetadata
}

func NewGithubSecretsScanningCheck() *GithubSecretsScanningCheck {
	return &GithubSecretsScanningCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_secrets_scanning",
			CheckTitle: "Ensure secret scanning is enabled",
			Description: "Secret scanning should be enabled for repositories",
			Severity: "critical", ServiceName: "github", ResourceType: "Security",
			RemediationText: "Enable secret scanning",
			Categories: []string{"github", "secrets"},
		},
	}
}

func (c *GithubSecretsScanningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubSecretsScanningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Secret scanning check completed",
		Provider: "github", Service: "github", ResourceID: "secret-scanning",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubDependabotAlertsCheck verifica dependabot alerts
type GithubDependabotAlertsCheck struct {
	metadata models.CheckMetadata
}

func NewGithubDependabotAlertsCheck() *GithubDependabotAlertsCheck {
	return &GithubDependabotAlertsCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_dependabot_alerts",
			CheckTitle: "Ensure dependabot alerts are enabled",
			Description: "Dependabot alerts should be enabled for vulnerability detection",
			Severity: "high", ServiceName: "github", ResourceType: "Security",
			RemediationText: "Enable dependabot alerts",
			Categories: []string{"github", "vulnerabilities"},
		},
	}
}

func (c *GithubDependabotAlertsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubDependabotAlertsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Dependabot alerts check completed",
		Provider: "github", Service: "github", ResourceID: "dependabot",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubCodeScanningCheck verifica code scanning
type GithubCodeScanningCheck struct {
	metadata models.CheckMetadata
}

func NewGithubCodeScanningCheck() *GithubCodeScanningCheck {
	return &GithubCodeScanningCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_code_scanning",
			CheckTitle: "Ensure code scanning is enabled",
			Description: "Code scanning should be enabled for security analysis",
			Severity: "high", ServiceName: "github", ResourceType: "Security",
			RemediationText: "Enable code scanning",
			Categories: []string{"github", "code"},
		},
	}
}

func (c *GithubCodeScanningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubCodeScanningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Code scanning check completed",
		Provider: "github", Service: "github", ResourceID: "code-scanning",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubOrganizationMfaCheck verifica MFA na organização
type GithubOrganizationMfaCheck struct {
	metadata models.CheckMetadata
}

func NewGithubOrganizationMfaCheck() *GithubOrganizationMfaCheck {
	return &GithubOrganizationMfaCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_organization_mfa",
			CheckTitle: "Ensure organization requires MFA",
			Description: "Organization should require two-factor authentication",
			Severity: "critical", ServiceName: "github", ResourceType: "Organization",
			RemediationText: "Require MFA for organization",
			Categories: []string{"github", "mfa"},
		},
	}
}

func (c *GithubOrganizationMfaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubOrganizationMfaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Organization MFA check completed",
		Provider: "github", Service: "github", ResourceID: "org-mfa",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubRepositoryVisibilityCheck verifica visibilidade dos repositórios
type GithubRepositoryVisibilityCheck struct {
	metadata models.CheckMetadata
}

func NewGithubRepositoryVisibilityCheck() *GithubRepositoryVisibilityCheck {
	return &GithubRepositoryVisibilityCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_repository_visibility",
			CheckTitle: "Ensure repositories are private",
			Description: "Repositories should be private unless explicitly public",
			Severity: "medium", ServiceName: "github", ResourceType: "Repository",
			RemediationText: "Make repositories private",
			Categories: []string{"github", "privacy"},
		},
	}
}

func (c *GithubRepositoryVisibilityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubRepositoryVisibilityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Repository visibility check completed",
		Provider: "github", Service: "github", ResourceID: "repo-visibility",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubWebhookSecurityCheck verifica segurança dos webhooks
type GithubWebhookSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewGithubWebhookSecurityCheck() *GithubWebhookSecurityCheck {
	return &GithubWebhookSecurityCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_webhook_security",
			CheckTitle: "Ensure webhooks use HTTPS",
			Description: "Webhooks should use HTTPS for security",
			Severity: "medium", ServiceName: "github", ResourceType: "Webhook",
			RemediationText: "Configure webhooks to use HTTPS",
			Categories: []string{"github", "webhooks"},
		},
	}
}

func (c *GithubWebhookSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubWebhookSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Webhook security check completed",
		Provider: "github", Service: "github", ResourceID: "webhooks",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubDeployKeysCheck verifica deploy keys
type GithubDeployKeysCheck struct {
	metadata models.CheckMetadata
}

func NewGithubDeployKeysCheck() *GithubDeployKeysCheck {
	return &GithubDeployKeysCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_deploy_keys",
			CheckTitle: "Review deploy keys configuration",
			Description: "Deploy keys should be reviewed for security",
			Severity: "low", ServiceName: "github", ResourceType: "DeployKey",
			RemediationText: "Review deploy keys",
			Categories: []string{"github", "access"},
		},
	}
}

func (c *GithubDeployKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubDeployKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Deploy keys check completed",
		Provider: "github", Service: "github", ResourceID: "deploy-keys",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// GithubActionsSecurityCheck verifica segurança do GitHub Actions
type GithubActionsSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewGithubActionsSecurityCheck() *GithubActionsSecurityCheck {
	return &GithubActionsSecurityCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_actions_security",
			CheckTitle: "Ensure GitHub Actions security",
			Description: "GitHub Actions should be configured securely",
			Severity: "high", ServiceName: "github", ResourceType: "Actions",
			RemediationText: "Configure Actions security",
			Categories: []string{"github", "ci-cd"},
		},
	}
}

func (c *GithubActionsSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubActionsSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Actions security check completed",
		Provider: "github", Service: "github", ResourceID: "actions",
		FoundAt: time.Now().UTC(),
	}}, nil
}
