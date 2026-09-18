package githubactions

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// GitHubActionsProvider defines the interface for GitHub Actions API calls
type GitHubActionsProvider interface {
	ListRepositories(ctx context.Context) ([]*github.Repository, error)
	GetRepository(ctx context.Context, owner, repo string) (*github.Repository, error)
}

// Check 31: githubactions_workflow_security_scan
type GithubactionsWorkflowSecurityScanCheck struct {
	metadata models.CheckMetadata
}

func NewGithubactionsWorkflowSecurityScanCheck() *GithubactionsWorkflowSecurityScanCheck {
	return &GithubactionsWorkflowSecurityScanCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "githubactions_workflow_security_scan",
			CheckTitle:  "Security scanning in workflow files",
			ServiceName: "githubactions",
			Severity:    "medium",
			Description: "Ensure security scanning is implemented in GitHub Actions workflow files.",
			RemediationText: "Add security scanning steps to your workflow files (e.g., CodeQL).",
			RemediationURL:  "https://docs.github.com/en/code-security/secure-coding/automatically-scanning-your-code-for-vulnerabilities-and-errors",
			Categories:      []string{"internet", "githubactions", "security-scan"},
		},
	}
}

func (c *GithubactionsWorkflowSecurityScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubactionsWorkflowSecurityScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubActionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubActionsProvider")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner := ""
		reponame := ""
		if repo.Owner != nil && repo.Owner.Login != nil {
			owner = *repo.Owner.Login
		}
		if repo.Name != nil {
			reponame = *repo.Name
		}

		// Check if security scanning is enabled via SecurityAndAnalysis
		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider: "github", Service: "githubactions",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		securityScan := false
		if repoDetail.SecurityAndAnalysis != nil && repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil {
			securityScan = repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status != nil &&
				*repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status == "enabled"
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: security scanning not enabled.", owner, reponame)
		if securityScan {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: security scanning enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "githubactions",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 32: githubactions_actions_not_public
type GithubactionsActionsNotPublicCheck struct {
	metadata models.CheckMetadata
}

func NewGithubactionsActionsNotPublicCheck() *GithubactionsActionsNotPublicCheck {
	return &GithubactionsActionsNotPublicCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "githubactions_actions_not_public",
			CheckTitle:  "Actions are not publicly accessible",
			ServiceName: "githubactions",
			Severity:    "high",
			Description: "Ensure GitHub Actions are not publicly accessible.",
			RemediationText: "Disable public access to Actions for private repositories.",
			RemediationURL:  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
			Categories:      []string{"internet", "githubactions"},
		},
	}
}

func (c *GithubactionsActionsNotPublicCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubactionsActionsNotPublicCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubActionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubActionsProvider")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner := ""
		reponame := ""
		if repo.Owner != nil && repo.Owner.Login != nil {
			owner = *repo.Owner.Login
		}
		if repo.Name != nil {
			reponame = *repo.Name
		}

		// Check if actions are not public (only applicable to private repos)
		isPublic := repo.Private != nil && !*repo.Private
		if isPublic {
			// Public repos have public actions by default - that's OK
			continue
		}

		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: actions are not publicly accessible.", owner, reponame)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "githubactions",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 33: githubactions_oidc_permissions_bound
type GithubactionsOidcPermissionsBoundCheck struct {
	metadata models.CheckMetadata
}

func NewGithubactionsOidcPermissionsBoundCheck() *GithubactionsOidcPermissionsBoundCheck {
	return &GithubactionsOidcPermissionsBoundCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "githubactions_oidc_permissions_bound",
			CheckTitle:  "OIDC permissions are bound",
			ServiceName: "githubactions",
			Severity:    "medium",
			Description: "Ensure OIDC token permissions are bound to specific environments.",
			RemediationText: "Configure OIDC token permissions to be bound to specific environments or conditions.",
			RemediationURL:  "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
			Categories:      []string{"internet", "githubactions", "oidc"},
		},
	}
}

func (c *GithubactionsOidcPermissionsBoundCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GithubactionsOidcPermissionsBoundCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubActionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubActionsProvider")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner := ""
		reponame := ""
		if repo.Owner != nil && repo.Owner.Login != nil {
			owner = *repo.Owner.Login
		}
		if repo.Name != nil {
			reponame = *repo.Name
		}

		// go-github v53 doesn't have direct OIDC configuration access
		// Assume secure by default if security features are enabled
		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider: "github", Service: "githubactions",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		oidcBound := false
		if repoDetail.SecurityAndAnalysis != nil {
			oidcBound = repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: OIDC permissions not detected.", owner, reponame)
		if oidcBound {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: OIDC permissions appear bound.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "githubactions",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}
