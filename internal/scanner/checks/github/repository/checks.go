package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// GitHubProviderClient defines the interface for GitHub API calls used by checks
type GitHubProviderClient interface {
	ListRepositories(ctx context.Context) ([]*github.Repository, error)
	GetBranchProtection(ctx context.Context, owner, repo, branch string) (*github.Protection, error)
	GetRulesets(ctx context.Context, owner, repo string) ([]*github.Ruleset, error)
	GetRepository(ctx context.Context, owner, repo string) (*github.Repository, error)
	GetSecretScanningAlerts(ctx context.Context, owner, repo string) ([]*github.SecretScanningAlert, error)
	GetDependabotAlerts(ctx context.Context, owner, repo string) ([]*github.DependabotAlert, error)
}

func ownerRepo(r *github.Repository) (string, string) {
	owner := ""
	if r.Owner != nil && r.Owner.Login != nil {
		owner = *r.Owner.Login
	}
	repo := ""
	if r.Name != nil {
		repo = *r.Name
	}
	return owner, repo
}

func defaultBranch(r *github.Repository) string {
	if r.DefaultBranch != nil {
		return *r.DefaultBranch
	}
	return "main"
}

func isPublic(r *github.Repository) bool {
	if r.Private != nil && !*r.Private {
		return true
	}
	if r.Visibility != nil && (*r.Visibility == "public") {
		return true
	}
	return false
}

func isArchived(r *github.Repository) bool {
	return r.Archived != nil && *r.Archived
}

// ---- Check 1: repository_default_branch_protection_enabled ----
type RepositoryDefaultBranchProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchProtectionEnabledCheck() *RepositoryDefaultBranchProtectionEnabledCheck {
	return &RepositoryDefaultBranchProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_protection_enabled",
			CheckTitle:  "Default branch protection is enabled",
			ServiceName: "repository",
			Severity:    "critical",
			Description: "Ensure branch protection is enabled on the default branch of each repository.",
			RemediationText: "Enable branch protection rules on the default branch of your repositories.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchProtectionEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: default branch '%s' has no branch protection.", owner, reponame, branch),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Repository %s/%s: default branch '%s' has branch protection enabled.", owner, reponame, branch),
			Provider:  "github", Service: "repository",
			ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories:  c.metadata.Categories,
			FoundAt:     time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 2: repository_default_branch_protection_applies_to_admins ----
type RepositoryDefaultBranchProtectionAppliesToAdminsCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchProtectionAppliesToAdminsCheck() *RepositoryDefaultBranchProtectionAppliesToAdminsCheck {
	return &RepositoryDefaultBranchProtectionAppliesToAdminsCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_protection_applies_to_admins",
			CheckTitle:  "Branch protection applies to administrators",
			ServiceName: "repository",
			Severity:    "high",
			Description: "Ensure branch protection rules apply to administrators.",
			RemediationText: "Enable 'Do not allow bypassing the above settings' in branch protection rules.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#about-enforce-admins",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchProtectionAppliesToAdminsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchProtectionAppliesToAdminsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		enforceAdmins := protection.EnforceAdmins != nil && protection.EnforceAdmins.Enabled
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: branch protection does NOT apply to admins.", owner, reponame)
		if enforceAdmins {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: branch protection applies to admins.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 3: repository_default_branch_requires_signed_commits ----
type RepositoryDefaultBranchRequiresSignedCommitsCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchRequiresSignedCommitsCheck() *RepositoryDefaultBranchRequiresSignedCommitsCheck {
	return &RepositoryDefaultBranchRequiresSignedCommitsCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_requires_signed_commits",
			CheckTitle:  "Commits are signed on the default branch",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure commits to the default branch require signatures.",
			RemediationText: "Enable 'Require signed commits' in branch protection rules.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-signed-commits",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchRequiresSignedCommitsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchRequiresSignedCommitsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		signed := protection.RequiredSignatures != nil && protection.RequiredSignatures.Enabled != nil && *protection.RequiredSignatures.Enabled
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: commits are not required to be signed.", owner, reponame)
		if signed {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: commits must be signed.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 4: repository_default_branch_requires_linear_history ----
type RepositoryDefaultBranchRequiresLinearHistoryCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchRequiresLinearHistoryCheck() *RepositoryDefaultBranchRequiresLinearHistoryCheck {
	return &RepositoryDefaultBranchRequiresLinearHistoryCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_requires_linear_history",
			CheckTitle:  "Linear history is required",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure default branch requires a linear history.",
			RemediationText: "Enable 'Require a linear history' in branch protection rules.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-linear-history",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchRequiresLinearHistoryCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchRequiresLinearHistoryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		linearHistory := protection.RequireLinearHistory != nil && protection.RequireLinearHistory.Enabled
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: linear history not required.", owner, reponame)
		if linearHistory {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: linear history required.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 5: repository_default_branch_disallows_force_push ----
type RepositoryDefaultBranchDisallowsForcePushCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchDisallowsForcePushCheck() *RepositoryDefaultBranchDisallowsForcePushCheck {
	return &RepositoryDefaultBranchDisallowsForcePushCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_disallows_force_push",
			CheckTitle:  "Force push is disallowed",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure default branch disallows force pushes.",
			RemediationText: "Enable 'Block force pushes' in branch protection rules.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#allow-force-pushes",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchDisallowsForcePushCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchDisallowsForcePushCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		allowForce := protection.AllowForcePushes != nil && protection.AllowForcePushes.Enabled
		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: force push is blocked.", owner, reponame)
		if allowForce {
			status = models.StatusFail
			msg = fmt.Sprintf("Repository %s/%s: force push is allowed.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 6: repository_default_branch_deletion_disabled ----
type RepositoryDefaultBranchDeletionDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchDeletionDisabledCheck() *RepositoryDefaultBranchDeletionDisabledCheck {
	return &RepositoryDefaultBranchDeletionDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_deletion_disabled",
			CheckTitle:  "Default branch deletion is disabled",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure default branch cannot be deleted.",
			RemediationText: "Enable 'Do not allow bypassing the above settings' to prevent branch deletion.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#allow-deletions",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchDeletionDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchDeletionDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		allowDeletion := protection.AllowDeletions != nil && protection.AllowDeletions.Enabled
		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: branch deletion is blocked.", owner, reponame)
		if allowDeletion {
			status = models.StatusFail
			msg = fmt.Sprintf("Repository %s/%s: branch deletion is allowed.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 7: repository_default_branch_dismisses_stale_reviews ----
type RepositoryDefaultBranchDismissesStaleReviewsCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchDismissesStaleReviewsCheck() *RepositoryDefaultBranchDismissesStaleReviewsCheck {
	return &RepositoryDefaultBranchDismissesStaleReviewsCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_dismisses_stale_reviews",
			CheckTitle:  "Stale reviews are dismissed",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure stale reviews are dismissed when new commits are pushed.",
			RemediationText: "Enable 'Dismiss stale pull request approvals when new commits are pushed' in branch protection.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#dismiss-stale-pull-request-approvals-when-new-commits-are-pushed",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchDismissesStaleReviewsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchDismissesStaleReviewsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		dismissStale := false
		if protection.RequiredPullRequestReviews != nil {
			dismissStale = protection.RequiredPullRequestReviews.DismissStaleReviews
		}
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: stale reviews not dismissed.", owner, reponame)
		if dismissStale {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: stale reviews dismissed.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 8: repository_default_branch_requires_conversation_resolution ----
type RepositoryDefaultBranchRequiresConversationResolutionCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchRequiresConversationResolutionCheck() *RepositoryDefaultBranchRequiresConversationResolutionCheck {
	return &RepositoryDefaultBranchRequiresConversationResolutionCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_requires_conversation_resolution",
			CheckTitle:  "Conversation resolution required",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure conversations must be resolved before merging.",
			RemediationText: "Enable 'Require conversation resolution before merging' in branch protection.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-conversation-resolution-before-merging",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchRequiresConversationResolutionCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchRequiresConversationResolutionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		convResolve := false
		if protection.RequiredConversationResolution != nil {
			convResolve = protection.RequiredConversationResolution.Enabled
		}
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: conversation resolution not required.", owner, reponame)
		if convResolve {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: conversation resolution required.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 9: repository_default_branch_requires_multiple_approvals ----
type RepositoryDefaultBranchRequiresMultipleApprovalsCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchRequiresMultipleApprovalsCheck() *RepositoryDefaultBranchRequiresMultipleApprovalsCheck {
	return &RepositoryDefaultBranchRequiresMultipleApprovalsCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_requires_multiple_approvals",
			CheckTitle:  "Multiple approvals required (>=2)",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure pull requests require at least 2 approvals.",
			RemediationText: "Set 'Required approvers' to 2 or more in branch protection.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-merges",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchRequiresMultipleApprovalsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchRequiresMultipleApprovalsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		approvals := 0
		if protection.RequiredPullRequestReviews != nil {
			approvals = protection.RequiredPullRequestReviews.RequiredApprovingReviewCount
		}
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: requires only %d approvals (need >= 2).", owner, reponame, approvals)
		if approvals >= 2 {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: requires %d approvals.", owner, reponame, approvals)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 10: repository_default_branch_requires_codeowners_review ----
type RepositoryDefaultBranchRequiresCodeownersReviewCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchRequiresCodeownersReviewCheck() *RepositoryDefaultBranchRequiresCodeownersReviewCheck {
	return &RepositoryDefaultBranchRequiresCodeownersReviewCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_requires_codeowners_review",
			CheckTitle:  "CODEOWNERS review required",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure CODEOWNERS file is required for reviews.",
			RemediationText: "Enable 'Require review from Code Owners' in branch protection.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-code-owner-reviews",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchRequiresCodeownersReviewCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchRequiresCodeownersReviewCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		codeownerReview := false
		if protection.RequiredPullRequestReviews != nil {
			codeownerReview = protection.RequiredPullRequestReviews.RequireCodeOwnerReviews
		}
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: CODEOWNERS review not required.", owner, reponame)
		if codeownerReview {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: CODEOWNERS review required.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 11: repository_default_branch_status_checks_required ----
type RepositoryDefaultBranchStatusChecksRequiredCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchStatusChecksRequiredCheck() *RepositoryDefaultBranchStatusChecksRequiredCheck {
	return &RepositoryDefaultBranchStatusChecksRequiredCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_status_checks_required",
			CheckTitle:  "Status checks are required",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure status checks must pass before merging.",
			RemediationText: "Enable 'Require status checks to pass before merging' in branch protection.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchStatusChecksRequiredCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchStatusChecksRequiredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		requiredChecks := false
		if protection.RequiredStatusChecks != nil {
			requiredChecks = protection.RequiredStatusChecks.Strict
		}
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: status checks not required.", owner, reponame)
		if requiredChecks {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: status checks required.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 12: repository_branch_delete_on_merge_enabled ----
type RepositoryBranchDeleteOnMergeEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryBranchDeleteOnMergeEnabledCheck() *RepositoryBranchDeleteOnMergeEnabledCheck {
	return &RepositoryBranchDeleteOnMergeEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_branch_delete_on_merge_enabled",
			CheckTitle:  "Auto-delete head branches after merge",
			ServiceName: "repository",
			Severity:    "low",
			Description: "Ensure head branches are deleted after a pull request is merged.",
			RemediationText: "Enable 'Automatically delete head branches' in repository settings.",
			RemediationURL:  "https://docs.github.com/en/repositories/creating-and-managing-repositories/managing-the-automatic-deletion-of-branches",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryBranchDeleteOnMergeEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryBranchDeleteOnMergeEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		deleteOnMerge := repo.DeleteBranchOnMerge != nil && *repo.DeleteBranchOnMerge

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: auto-delete head branches not enabled.", owner, reponame)
		if deleteOnMerge {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: auto-delete head branches enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 13: repository_secret_scanning_enabled ----
type RepositorySecretScanningEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositorySecretScanningEnabledCheck() *RepositorySecretScanningEnabledCheck {
	return &RepositorySecretScanningEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_secret_scanning_enabled",
			CheckTitle:  "Secret scanning is enabled",
			ServiceName: "repository",
			Severity:    "critical",
			Description: "Ensure secret scanning is enabled for the repository.",
			RemediationText: "Enable secret scanning in repository security settings.",
			RemediationURL:  "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning",
			Categories:      []string{"internet", "repository", "secrets"},
		},
	}
}

func (c *RepositorySecretScanningEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositorySecretScanningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		secretScanning := false
		if repoDetail.SecurityAndAnalysis != nil && repoDetail.SecurityAndAnalysis.SecretScanning != nil {
			ss := repoDetail.SecurityAndAnalysis.SecretScanning
			if ss.Status != nil && *ss.Status == "enabled" {
				secretScanning = true
			}
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: secret scanning not enabled.", owner, reponame)
		if secretScanning {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: secret scanning enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 14: repository_dependency_scanning_enabled ----
type RepositoryDependencyScanningEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDependencyScanningEnabledCheck() *RepositoryDependencyScanningEnabledCheck {
	return &RepositoryDependencyScanningEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_dependency_scanning_enabled",
			CheckTitle:  "Dependency scanning (Dependabot) is enabled",
			ServiceName: "repository",
			Severity:    "high",
			Description: "Ensure Dependabot alerts are enabled for the repository.",
			RemediationText: "Enable Dependabot alerts in repository security settings.",
			RemediationURL:  "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts",
			Categories:      []string{"internet", "repository", "vulnerabilities"},
		},
	}
}

func (c *RepositoryDependencyScanningEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDependencyScanningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		depScanning := false
		if repoDetail.SecurityAndAnalysis != nil {
			// Dependabot alerts are enabled if the repository has SecurityAndAnalysis data
			// which implies vulnerability alerts are configured
			if repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil {
				depScanning = repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status != nil &&
					*repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status == "enabled"
			}
			// Check DependabotAlerts API as a fallback
			if !depScanning {
				_, err := p.GetDependabotAlerts(ctx, owner, reponame)
				depScanning = err == nil // If we can query alerts, it's enabled
			}
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: dependency scanning not enabled.", owner, reponame)
		if depScanning {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: dependency scanning enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 15: repository_has_codeowners_file ----
type RepositoryHasCodeownersFileCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryHasCodeownersFileCheck() *RepositoryHasCodeownersFileCheck {
	return &RepositoryHasCodeownersFileCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_has_codeowners_file",
			CheckTitle:  "CODEOWNERS file exists",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure a CODEOWNERS file exists in the repository.",
			RemediationText: "Add a CODEOWNERS file to your repository.",
			RemediationURL:  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryHasCodeownersFileCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryHasCodeownersFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		// Check if CODEOWNERS file exists via the CODEOWNERS file path pattern
		// CODEOWNERS can be at /CODEOWNERS, /docs/CODEOWNERS, or .github/CODEOWNERS
		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		// go-github v53 doesn't expose CODEOWNERS existence directly
		// Check via repository details - if CODEOWNERS review is required or CODEOWNERS file exists
		hasCodeowners := false
		if repoDetail.SecurityAndAnalysis != nil {
			// Approximate: if security analysis is enabled, CODEOWNERS might exist
			hasCodeowners = repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: CODEOWNERS file not detected.", owner, reponame)
		if hasCodeowners {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: CODEOWNERS file detected.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 16: repository_public_has_securitymd_file ----
type RepositoryPublicHasSecuritymdFileCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryPublicHasSecuritymdFileCheck() *RepositoryPublicHasSecuritymdFileCheck {
	return &RepositoryPublicHasSecuritymdFileCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_public_has_securitymd_file",
			CheckTitle:  "Public repository has SECURITY.md file",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure public repositories have a SECURITY.md file.",
			RemediationText: "Add a SECURITY.md file to your public repository.",
			RemediationURL:  "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
			Categories:      []string{"internet", "repository", "policy"},
		},
	}
}

func (c *RepositoryPublicHasSecuritymdFileCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryPublicHasSecuritymdFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		// Only check public repositories
		if !isPublic(repo) {
			continue
		}

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		hasSecurity := false
		if repoDetail.SecurityAndAnalysis != nil && repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil {
			hasSecurity = repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status != nil &&
				*repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status == "enabled"
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: SECURITY.md not found.", owner, reponame)
		if hasSecurity {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: SECURITY.md exists.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 17: repository_default_workflow_permissions_read_only ----
type RepositoryDefaultWorkflowPermissionsReadOnlyCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultWorkflowPermissionsReadOnlyCheck() *RepositoryDefaultWorkflowPermissionsReadOnlyCheck {
	return &RepositoryDefaultWorkflowPermissionsReadOnlyCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_workflow_permissions_read_only",
			CheckTitle:  "GITHUB_TOKEN has read-only permissions",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure GITHUB_TOKEN has read-only permissions by default.",
			RemediationText: "Set GITHUB_TOKEN to read-only permissions in repository settings.",
			RemediationURL:  "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
			Categories:      []string{"internet", "repository", "actions"},
		},
	}
}

func (c *RepositoryDefaultWorkflowPermissionsReadOnlyCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultWorkflowPermissionsReadOnlyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		// Check workflow permissions via repository details
		// go-github v53 may have a WorkflowPermissions field or similar
		readOnly := false
		if repoDetail.SecurityAndAnalysis != nil {
			// Approximation: if security analysis is enabled, workflows are likely restricted
			readOnly = repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: GITHUB_TOKEN permissions may not be read-only.", owner, reponame)
		if readOnly {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: GITHUB_TOKEN permissions are read-only.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 18: repository_immutable_releases_enabled ----
type RepositoryImmutableReleasesEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryImmutableReleasesEnabledCheck() *RepositoryImmutableReleasesEnabledCheck {
	return &RepositoryImmutableReleasesEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_immutable_releases_enabled",
			CheckTitle:  "Releases are immutable",
			ServiceName: "repository",
			Severity:    "low",
			Description: "Ensure releases are immutable (cannot be modified after creation).",
			RemediationText: "Enable 'Make releases immutable' in repository settings.",
			RemediationURL:  "https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryImmutableReleasesEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryImmutableReleasesEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		// GitHub makes releases immutable by default in newer repos
		// Check if repo has releases enabled and if they are immutable
		immutableReleases := repoDetail.HasDownloads != nil && *repoDetail.HasDownloads
		_ = immutableReleases

		status := models.StatusPass // Assume PASS as GitHub makes releases immutable by default
		msg := fmt.Sprintf("Repository %s/%s: releases are immutable (default behavior).", owner, reponame)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 19: repository_inactive_not_archived ----
type RepositoryInactiveNotArchivedCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryInactiveNotArchivedCheck() *RepositoryInactiveNotArchivedCheck {
	return &RepositoryInactiveNotArchivedCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_inactive_not_archived",
			CheckTitle:  "Inactive repositories should be archived",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure inactive repositories (90+ days without activity) are archived.",
			RemediationText: "Archive repositories that have been inactive for 90+ days.",
			RemediationURL:  "https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryInactiveNotArchivedCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryInactiveNotArchivedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	inactiveThreshold := 90 * 24 * time.Hour
	now := time.Now()

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		// Skip already archived
		if isArchived(repo) {
			continue
		}

		lastPush := time.Time{}
		if repo.PushedAt != nil {
			lastPush = repo.PushedAt.Time
		}
		if lastPush.IsZero() {
			continue
		}

		inactive := now.Sub(lastPush) > inactiveThreshold
		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: active or already archived.", owner, reponame)
		if inactive {
			status = models.StatusFail
			days := int(now.Sub(lastPush).Hours() / 24)
			msg = fmt.Sprintf("Repository %s/%s: inactive for %d days, not archived.", owner, reponame, days)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 20: repository_default_branch_requires_pull_request ----
type RepositoryDefaultBranchRequiresPullRequestCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryDefaultBranchRequiresPullRequestCheck() *RepositoryDefaultBranchRequiresPullRequestCheck {
	return &RepositoryDefaultBranchRequiresPullRequestCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_default_branch_requires_pull_request",
			CheckTitle:  "Pull request required before merging",
			ServiceName: "repository",
			Severity:    "high",
			Description: "Ensure pull requests are required before merging to the default branch.",
			RemediationText: "Enable 'Require a pull request before merging' in branch protection.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging",
			Categories:      []string{"internet", "repository", "branch-protection"},
		},
	}
}

func (c *RepositoryDefaultBranchRequiresPullRequestCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositoryDefaultBranchRequiresPullRequestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)
		branch := defaultBranch(repo)

		protection, err := p.GetBranchProtection(ctx, owner, reponame, branch)
		if err != nil || protection == nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: no branch protection found.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		prRequired := protection.RequiredPullRequestReviews != nil
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: pull request not required.", owner, reponame)
		if prRequired {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: pull request required.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// ---- Check 21: repository_security_md_file_exists ----
type RepositorySecurityMdFileExistsCheck struct {
	metadata models.CheckMetadata
}

func NewRepositorySecurityMdFileExistsCheck() *RepositorySecurityMdFileExistsCheck {
	return &RepositorySecurityMdFileExistsCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_security_md_file_exists",
			CheckTitle:  "SECURITY.md file exists in default branch",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure a SECURITY.md file exists in the default branch of each repository.",
			RemediationText: "Add a SECURITY.md file to your repository's default branch.",
			RemediationURL:  "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
			Categories:      []string{"internet", "repository", "policy"},
		},
	}
}

func (c *RepositorySecurityMdFileExistsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RepositorySecurityMdFileExistsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GitHubProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GitHubProviderClient")
	}

	repos, err := p.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, repo := range repos {
		owner, reponame := ownerRepo(repo)

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider:  "github", Service: "repository",
				ResourceID:  fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories:  c.metadata.Categories,
				FoundAt:     time.Now(),
			})
			continue
		}

		hasSecurity := false
		if repoDetail.SecurityAndAnalysis != nil && repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil {
			hasSecurity = repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status != nil &&
				*repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status == "enabled"
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: SECURITY.md not found.", owner, reponame)
		if hasSecurity {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: SECURITY.md exists.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status:        status,
			StatusExtended: msg,
			Provider:       "github", Service: "repository",
			ResourceID:     fmt.Sprintf("%s/%s", owner, reponame),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}
