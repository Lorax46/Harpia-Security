// Package saas provides SaaS platform security checks.
package saas

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// NewSAASChecks returns all SaaS security checks.
func NewSAASChecks() []CheckFactory {
	return []CheckFactory{
		// GitHub checks
		{ID: "github_branch_protection", New: func() Checker { return NewGitHubBranchProtectionCheck() }},
		{ID: "github_2fa", New: func() Checker { return NewGitHub2FACheck() }},
		{ID: "github_secrets_scanning", New: func() Checker { return NewGitHubSecretsScanningCheck() }},
		{ID: "github_dependabot", New: func() Checker { return NewGitHubDependabotCheck() }},
		{ID: "github_actions_security", New: func() Checker { return NewGitHubActionsSecurityCheck() }},

		// GitLab checks
		{ID: "gitlab_branch_protection", New: func() Checker { return NewGitLabBranchProtectionCheck() }},
		{ID: "gitlab_2fa", New: func() Checker { return NewGitLab2FACheck() }},
		{ID: "gitlab_secrets_detection", New: func() Checker { return NewGitLabSecretsDetectionCheck() }},

		// Datadog checks
		{ID: "datadog_monitoring", New: func() Checker { return NewDatadogMonitoringCheck() }},
		{ID: "datadog_logging", New: func() Checker { return NewDatadogLoggingCheck() }},

		// Okta checks
		{ID: "okta_mfa", New: func() Checker { return NewOktaMFACheck() }},
		{ID: "okta_password_policy", New: func() Checker { return NewOktaPasswordPolicyCheck() }},

		// Slack checks
		{ID: "slack_2fa", New: func() Checker { return NewSlack2FACheck() }},
		{ID: "slack_app_management", New: func() Checker { return NewSlackAppManagementCheck() }},
	}
}

// CheckFactory creates new check instances.
type CheckFactory struct {
	ID  string
	New func() Checker
}

// Checker is the interface for SaaS security checks.
type Checker interface {
	Metadata() models.CheckMetadata
	Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
}

// GitHubBranchProtectionCheck ensures branch protection is enabled.
type GitHubBranchProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewGitHubBranchProtectionCheck() *GitHubBranchProtectionCheck {
	return &GitHubBranchProtectionCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_branch_protection",
			CheckTitle: "Ensure branch protection is enabled",
			Description: "GitHub repositories should have branch protection enabled for main/master branches",
			ServiceName: "github", Severity: "high", ResourceType: "Repository",
			Categories: []string{"github", "branch-protection"},
		},
	}
}

func (c *GitHubBranchProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitHubBranchProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProvider")
	}
	findings := []models.Finding{}
	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		if !repo.BranchProtectionEnabled {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s does not have branch protection enabled", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Repository %s has branch protection enabled", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// GitHub2FACheck ensures 2FA is enabled for organization.
type GitHub2FACheck struct {
	metadata models.CheckMetadata
}

func NewGitHub2FACheck() *GitHub2FACheck {
	return &GitHub2FACheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_2fa",
			CheckTitle: "Ensure 2FA is enabled for organization",
			Description: "GitHub organizations should require 2FA for all members",
			ServiceName: "github", Severity: "critical", ResourceType: "Organization",
			Categories: []string{"github", "2fa"},
		},
	}
}

func (c *GitHub2FACheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitHub2FACheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProvider")
	}
	findings := []models.Finding{}
	orgs, err := p.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if !org.Require2FA {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Organization %s does not require 2FA", org.Name),
				ResourceID: org.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Organization %s requires 2FA", org.Name),
				ResourceID: org.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// GitHubSecretsScanningCheck ensures secrets scanning is enabled.
type GitHubSecretsScanningCheck struct {
	metadata models.CheckMetadata
}

func NewGitHubSecretsScanningCheck() *GitHubSecretsScanningCheck {
	return &GitHubSecretsScanningCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_secrets_scanning",
			CheckTitle: "Ensure secrets scanning is enabled",
			Description: "GitHub repositories should have secrets scanning enabled",
			ServiceName: "github", Severity: "high", ResourceType: "Repository",
			Categories: []string{"github", "secrets"},
		},
	}
}

func (c *GitHubSecretsScanningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitHubSecretsScanningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProvider")
	}
	findings := []models.Finding{}
	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		if !repo.SecretsScanningEnabled {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s does not have secrets scanning enabled", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Repository %s has secrets scanning enabled", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// GitHubDependabotCheck ensures Dependabot is enabled.
type GitHubDependabotCheck struct {
	metadata models.CheckMetadata
}

func NewGitHubDependabotCheck() *GitHubDependabotCheck {
	return &GitHubDependabotCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_dependabot",
			CheckTitle: "Ensure Dependabot is enabled",
			Description: "GitHub repositories should have Dependabot enabled for security updates",
			ServiceName: "github", Severity: "medium", ResourceType: "Repository",
			Categories: []string{"github", "dependencies"},
		},
	}
}

func (c *GitHubDependabotCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitHubDependabotCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProvider")
	}
	findings := []models.Finding{}
	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		if !repo.DependabotEnabled {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s does not have Dependabot enabled", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Repository %s has Dependabot enabled", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// GitHubActionsSecurityCheck ensures GitHub Actions security.
type GitHubActionsSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewGitHubActionsSecurityCheck() *GitHubActionsSecurityCheck {
	return &GitHubActionsSecurityCheck{
		metadata: models.CheckMetadata{
			Provider: "github", CheckID: "github_actions_security",
			CheckTitle: "Ensure GitHub Actions security",
			Description: "GitHub Actions should be configured securely",
			ServiceName: "github", Severity: "high", ResourceType: "Repository",
			Categories: []string{"github", "ci-cd"},
		},
	}
}

func (c *GitHubActionsSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitHubActionsSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProvider")
	}
	findings := []models.Finding{}
	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		if !repo.ActionsSecure {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s has insecure Actions configuration", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Repository %s has secure Actions configuration", repo.Name),
				ResourceID: repo.Name, Provider: "github", Service: "github",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// GitLabBranchProtectionCheck ensures GitLab branch protection.
type GitLabBranchProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewGitLabBranchProtectionCheck() *GitLabBranchProtectionCheck {
	return &GitLabBranchProtectionCheck{
		metadata: models.CheckMetadata{
			Provider: "gitlab", CheckID: "gitlab_branch_protection",
			CheckTitle: "Ensure GitLab branch protection",
			Description: "GitLab projects should have branch protection enabled",
			ServiceName: "gitlab", Severity: "high", ResourceType: "Project",
			Categories: []string{"gitlab", "branch-protection"},
		},
	}
}

func (c *GitLabBranchProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitLabBranchProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitLabProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitLabProvider")
	}
	findings := []models.Finding{}
	projects, err := p.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	for _, proj := range projects {
		if !proj.BranchProtectionEnabled {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Project %s does not have branch protection", proj.Name),
				ResourceID: proj.Name, Provider: "gitlab", Service: "gitlab",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Project %s has branch protection", proj.Name),
				ResourceID: proj.Name, Provider: "gitlab", Service: "gitlab",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// GitLab2FACheck ensures GitLab 2FA.
type GitLab2FACheck struct {
	metadata models.CheckMetadata
}

func NewGitLab2FACheck() *GitLab2FACheck {
	return &GitLab2FACheck{
		metadata: models.CheckMetadata{
			Provider: "gitlab", CheckID: "gitlab_2fa",
			CheckTitle: "Ensure GitLab 2FA is enabled",
			Description: "GitLab should require 2FA for all users",
			ServiceName: "gitlab", Severity: "critical", ResourceType: "Instance",
			Categories: []string{"gitlab", "2fa"},
		},
	}
}

func (c *GitLab2FACheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitLab2FACheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitLabProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitLabProvider")
	}
	findings := []models.Finding{}
	instance, err := p.GetInstance(ctx)
	if err != nil {
		return nil, err
	}
	if !instance.Require2FA {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "GitLab instance does not require 2FA",
			Provider: "gitlab", Service: "gitlab",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "GitLab instance requires 2FA",
			Provider: "gitlab", Service: "gitlab",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// GitLabSecretsDetectionCheck ensures GitLab secrets detection.
type GitLabSecretsDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewGitLabSecretsDetectionCheck() *GitLabSecretsDetectionCheck {
	return &GitLabSecretsDetectionCheck{
		metadata: models.CheckMetadata{
			Provider: "gitlab", CheckID: "gitlab_secrets_detection",
			CheckTitle: "Ensure GitLab secrets detection is enabled",
			Description: "GitLab should have secrets detection enabled",
			ServiceName: "gitlab", Severity: "high", ResourceType: "Project",
			Categories: []string{"gitlab", "secrets"},
		},
	}
}

func (c *GitLabSecretsDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GitLabSecretsDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitLabProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitLabProvider")
	}
	findings := []models.Finding{}
	projects, err := p.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	for _, proj := range projects {
		if !proj.SecretsDetectionEnabled {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Project %s does not have secrets detection", proj.Name),
				ResourceID: proj.Name, Provider: "gitlab", Service: "gitlab",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Project %s has secrets detection", proj.Name),
				ResourceID: proj.Name, Provider: "gitlab", Service: "gitlab",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DatadogMonitoringCheck ensures Datadog monitoring.
type DatadogMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewDatadogMonitoringCheck() *DatadogMonitoringCheck {
	return &DatadogMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider: "datadog", CheckID: "datadog_monitoring",
			CheckTitle: "Ensure Datadog monitoring is enabled",
			Description: "Datadog should have monitoring enabled for all resources",
			ServiceName: "datadog", Severity: "medium", ResourceType: "Organization",
			Categories: []string{"datadog", "monitoring"},
		},
	}
}

func (c *DatadogMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatadogMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(DatadogProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement DatadogProvider")
	}
	findings := []models.Finding{}
	org, err := p.GetOrganization(ctx)
	if err != nil {
		return nil, err
	}
	if !org.MonitoringEnabled {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Datadog monitoring is not enabled",
			Provider: "datadog", Service: "datadog",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Datadog monitoring is enabled",
			Provider: "datadog", Service: "datadog",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// DatadogLoggingCheck ensures Datadog logging.
type DatadogLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewDatadogLoggingCheck() *DatadogLoggingCheck {
	return &DatadogLoggingCheck{
		metadata: models.CheckMetadata{
			Provider: "datadog", CheckID: "datadog_logging",
			CheckTitle: "Ensure Datadog logging is enabled",
			Description: "Datadog should have logging enabled for all resources",
			ServiceName: "datadog", Severity: "medium", ResourceType: "Organization",
			Categories: []string{"datadog", "logging"},
		},
	}
}

func (c *DatadogLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatadogLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(DatadogProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement DatadogProvider")
	}
	findings := []models.Finding{}
	org, err := p.GetOrganization(ctx)
	if err != nil {
		return nil, err
	}
	if !org.LoggingEnabled {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Datadog logging is not enabled",
			Provider: "datadog", Service: "datadog",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Datadog logging is enabled",
			Provider: "datadog", Service: "datadog",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// OktaMFACheck ensures Okta MFA.
type OktaMFACheck struct {
	metadata models.CheckMetadata
}

func NewOktaMFACheck() *OktaMFACheck {
	return &OktaMFACheck{
		metadata: models.CheckMetadata{
			Provider: "okta", CheckID: "okta_mfa",
			CheckTitle: "Ensure Okta MFA is enabled",
			Description: "Okta should require MFA for all users",
			ServiceName: "okta", Severity: "critical", ResourceType: "Organization",
			Categories: []string{"okta", "2fa"},
		},
	}
}

func (c *OktaMFACheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OktaMFACheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(OktaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement OktaProvider")
	}
	findings := []models.Finding{}
	org, err := p.GetOrganization(ctx)
	if err != nil {
		return nil, err
	}
	if !org.MFAEnabled {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Okta MFA is not enabled",
			Provider: "okta", Service: "okta",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Okta MFA is enabled",
			Provider: "okta", Service: "okta",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// OktaPasswordPolicyCheck ensures Okta password policy.
type OktaPasswordPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewOktaPasswordPolicyCheck() *OktaPasswordPolicyCheck {
	return &OktaPasswordPolicyCheck{
		metadata: models.CheckMetadata{
			Provider: "okta", CheckID: "okta_password_policy",
			CheckTitle: "Ensure Okta password policy is strong",
			Description: "Okta should have a strong password policy",
			ServiceName: "okta", Severity: "high", ResourceType: "Organization",
			Categories: []string{"okta", "password"},
		},
	}
}

func (c *OktaPasswordPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OktaPasswordPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(OktaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement OktaProvider")
	}
	findings := []models.Finding{}
	org, err := p.GetOrganization(ctx)
	if err != nil {
		return nil, err
	}
	if !org.StrongPasswordPolicy {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Okta password policy is not strong enough",
			Provider: "okta", Service: "okta",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Okta password policy is strong",
			Provider: "okta", Service: "okta",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Slack2FACheck ensures Slack 2FA.
type Slack2FACheck struct {
	metadata models.CheckMetadata
}

func NewSlack2FACheck() *Slack2FACheck {
	return &Slack2FACheck{
		metadata: models.CheckMetadata{
			Provider: "slack", CheckID: "slack_2fa",
			CheckTitle: "Ensure Slack 2FA is enabled",
			Description: "Slack workspace should require 2FA for all members",
			ServiceName: "slack", Severity: "critical", ResourceType: "Workspace",
			Categories: []string{"slack", "2fa"},
		},
	}
}

func (c *Slack2FACheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Slack2FACheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(SlackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement SlackProvider")
	}
	findings := []models.Finding{}
	workspace, err := p.GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	if !workspace.Require2FA {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Slack workspace does not require 2FA",
			Provider: "slack", Service: "slack",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Slack workspace requires 2FA",
			Provider: "slack", Service: "slack",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// SlackAppManagementCheck ensures Slack app management.
type SlackAppManagementCheck struct {
	metadata models.CheckMetadata
}

func NewSlackAppManagementCheck() *SlackAppManagementCheck {
	return &SlackAppManagementCheck{
		metadata: models.CheckMetadata{
			Provider: "slack", CheckID: "slack_app_management",
			CheckTitle: "Ensure Slack app management is secure",
			Description: "Slack workspace should have app management restricted",
			ServiceName: "slack", Severity: "medium", ResourceType: "Workspace",
			Categories: []string{"slack", "apps"},
		},
	}
}

func (c *SlackAppManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SlackAppManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(SlackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement SlackProvider")
	}
	findings := []models.Finding{}
	workspace, err := p.GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	if !workspace.AppManagementRestricted {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Slack app management is not restricted",
			Provider: "slack", Service: "slack",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Slack app management is restricted",
			Provider: "slack", Service: "slack",
			Categories: c.metadata.Categories, FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Provider interfaces for SaaS platforms

// GitHubProvider is the interface for GitHub access.
type GitHubProvider interface {
	ListRepositories(ctx context.Context) ([]GitHubRepository, error)
	ListOrganizations(ctx context.Context) ([]GitHubOrganization, error)
}

// GitHubRepository represents a GitHub repository.
type GitHubRepository struct {
	Name                     string
	BranchProtectionEnabled  bool
	SecretsScanningEnabled   bool
	DependabotEnabled        bool
	ActionsSecure            bool
}

// GitHubOrganization represents a GitHub organization.
type GitHubOrganization struct {
	Name      string
	Require2FA bool
}

// GitLabProvider is the interface for GitLab access.
type GitLabProvider interface {
	ListProjects(ctx context.Context) ([]GitLabProject, error)
	GetInstance(ctx context.Context) (*GitLabInstance, error)
}

// GitLabProject represents a GitLab project.
type GitLabProject struct {
	Name                     string
	BranchProtectionEnabled  bool
	SecretsDetectionEnabled  bool
}

// GitLabInstance represents a GitLab instance.
type GitLabInstance struct {
	Require2FA bool
}

// DatadogProvider is the interface for Datadog access.
type DatadogProvider interface {
	GetOrganization(ctx context.Context) (*DatadogOrganization, error)
}

// DatadogOrganization represents a Datadog organization.
type DatadogOrganization struct {
	Name             string
	MonitoringEnabled bool
	LoggingEnabled   bool
}

// OktaProvider is the interface for Okta access.
type OktaProvider interface {
	GetOrganization(ctx context.Context) (*OktaOrganization, error)
}

// OktaOrganization represents an Okta organization.
type OktaOrganization struct {
	Name               string
	MFAEnabled         bool
	StrongPasswordPolicy bool
}

// SlackProvider is the interface for Slack access.
type SlackProvider interface {
	GetWorkspace(ctx context.Context) (*SlackWorkspace, error)
}

// SlackWorkspace represents a Slack workspace.
type SlackWorkspace struct {
	Name                   string
	Require2FA             bool
	AppManagementRestricted bool
}
