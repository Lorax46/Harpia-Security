package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Check 34: repository_public_repository_has_no_secrets_in_environment
type RepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck() *RepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck {
	return &RepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_public_repository_has_no_secrets_in_environment",
			CheckTitle:  "No secrets in public repository environments",
			ServiceName: "repository",
			Severity:    "high",
			Description: "Ensure public repositories do not have secrets in environments.",
			RemediationText: "Remove secrets from public repository environments.",
			RemediationURL:  "https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions",
			Categories:      []string{"internet", "repository", "secrets"},
		},
	}
}

func (c *RepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: no secrets detected in environments.", owner, reponame)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 35: repository_tags_immutable
type RepositoryTagsImmutableCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryTagsImmutableCheck() *RepositoryTagsImmutableCheck {
	return &RepositoryTagsImmutableCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_tags_immutable",
			CheckTitle:  "Immutable tags enabled",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure repository tags are immutable.",
			RemediationText: "Enable tag immutability in repository settings.",
			RemediationURL:  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-repository-tags",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryTagsImmutableCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryTagsImmutableCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: tags are immutable (default).", owner, reponame)

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 36: repository_signing_required
type RepositorySigningRequiredCheck struct {
	metadata models.CheckMetadata
}

func NewRepositorySigningRequiredCheck() *RepositorySigningRequiredCheck {
	return &RepositorySigningRequiredCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_signing_required",
			CheckTitle:  "Commit signing required",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure commits must be signed.",
			RemediationText: "Require signed commits in branch protection settings.",
			RemediationURL:  "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-signed-commits",
			Categories:      []string{"internet", "repository", "signing"},
		},
	}
}

func (c *RepositorySigningRequiredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositorySigningRequiredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
				Provider: "github", Service: "repository",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		signed := protection.RequiredSignatures != nil && protection.RequiredSignatures.Enabled != nil && *protection.RequiredSignatures.Enabled
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: commit signing not required.", owner, reponame)
		if signed {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: commit signing required.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 37: repository_push_protection_enabled
type RepositoryPushProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryPushProtectionEnabledCheck() *RepositoryPushProtectionEnabledCheck {
	return &RepositoryPushProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_push_protection_enabled",
			CheckTitle:  "Push protection enabled",
			ServiceName: "repository",
			Severity:    "critical",
			Description: "Ensure secret scanning push protection is enabled.",
			RemediationText: "Enable secret scanning push protection for the repository.",
			RemediationURL:  "https://docs.github.com/en/code-security/secret-scanning/protecting-pushes-with-secret-scanning",
			Categories:      []string{"internet", "repository", "secrets"},
		},
	}
}

func (c *RepositoryPushProtectionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryPushProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
				Provider: "github", Service: "repository",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		pushProtection := false
		if repoDetail.SecurityAndAnalysis != nil && repoDetail.SecurityAndAnalysis.SecretScanningPushProtection != nil {
			pushProtection = repoDetail.SecurityAndAnalysis.SecretScanningPushProtection.Status != nil &&
				*repoDetail.SecurityAndAnalysis.SecretScanningPushProtection.Status == "enabled"
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: push protection not enabled.", owner, reponame)
		if pushProtection {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: push protection enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 38: repository_code_scanning_default_config
type RepositoryCodeScanningDefaultConfigCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryCodeScanningDefaultConfigCheck() *RepositoryCodeScanningDefaultConfigCheck {
	return &RepositoryCodeScanningDefaultConfigCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_code_scanning_default_config",
			CheckTitle:  "Code scanning with CodeQL configured",
			ServiceName: "repository",
			Severity:    "high",
			Description: "Ensure code scanning is configured with CodeQL.",
			RemediationText: "Configure CodeQL code scanning for the repository.",
			RemediationURL:  "https://docs.github.com/en/code-security/secure-coding/automatically-scanning-your-code-for-vulnerabilities-and-errors/setting-up-code-scanning-for-a-repository",
			Categories:      []string{"internet", "repository", "code-scanning"},
		},
	}
}

func (c *RepositoryCodeScanningDefaultConfigCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryCodeScanningDefaultConfigCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
				Provider: "github", Service: "repository",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		codeScanning := false
		if repoDetail.SecurityAndAnalysis != nil && repoDetail.SecurityAndAnalysis.AdvancedSecurity != nil {
			codeScanning = repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status != nil &&
				*repoDetail.SecurityAndAnalysis.AdvancedSecurity.Status == "enabled"
		}

		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: code scanning not configured.", owner, reponame)
		if codeScanning {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: code scanning configured.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 39: repository_security_and_analysis_enabled
type RepositorySecurityAndAnalysisEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositorySecurityAndAnalysisEnabledCheck() *RepositorySecurityAndAnalysisEnabledCheck {
	return &RepositorySecurityAndAnalysisEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_security_and_analysis_enabled",
			CheckTitle:  "Security and analysis enabled",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure security and analysis features are enabled for the repository.",
			RemediationText: "Enable security and analysis features in repository settings.",
			RemediationURL:  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-security-and-analysis-settings-for-your-repository",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositorySecurityAndAnalysisEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositorySecurityAndAnalysisEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
				Provider: "github", Service: "repository",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		securityEnabled := repoDetail.SecurityAndAnalysis != nil
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: security and analysis not configured.", owner, reponame)
		if securityEnabled {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: security and analysis configured.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 40: repository_forking_disabled
type RepositoryForkingDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryForkingDisabledCheck() *RepositoryForkingDisabledCheck {
	return &RepositoryForkingDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_forking_disabled",
			CheckTitle:  "Forking disabled for private repos",
			ServiceName: "repository",
			Severity:    "medium",
			Description: "Ensure forking is disabled for private repositories.",
			RemediationText: "Disable forking for private repositories.",
			RemediationURL:  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryForkingDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryForkingDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

		// Only check private repositories
		if repo.Private == nil || !*repo.Private {
			continue
		}

		repoDetail, err := p.GetRepository(ctx, owner, reponame)
		if err != nil {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Repository %s/%s: could not retrieve repository details.", owner, reponame),
				Provider: "github", Service: "repository",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		forkingAllowed := repoDetail.AllowForking != nil && *repoDetail.AllowForking
		status := models.StatusPass
		msg := fmt.Sprintf("Repository %s/%s: forking disabled.", owner, reponame)
		if forkingAllowed {
			status = models.StatusFail
			msg = fmt.Sprintf("Repository %s/%s: forking enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}

// Check 41: repository_issues_enabled
type RepositoryIssuesEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryIssuesEnabledCheck() *RepositoryIssuesEnabledCheck {
	return &RepositoryIssuesEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:    "github",
			CheckID:     "repository_issues_enabled",
			CheckTitle:  "Issues enabled",
			ServiceName: "repository",
			Severity:    "low",
			Description: "Ensure issues are enabled for the repository.",
			RemediationText: "Enable issues in repository settings.",
			RemediationURL:  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-repository-settings",
			Categories:      []string{"internet", "repository"},
		},
	}
}

func (c *RepositoryIssuesEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryIssuesEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
				Provider: "github", Service: "repository",
				ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
				Remediation: c.metadata.RemediationText,
				Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
			continue
		}

		hasIssues := repoDetail.HasIssues != nil && *repoDetail.HasIssues
		status := models.StatusFail
		msg := fmt.Sprintf("Repository %s/%s: issues not enabled.", owner, reponame)
		if hasIssues {
			status = models.StatusPass
			msg = fmt.Sprintf("Repository %s/%s: issues enabled.", owner, reponame)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			Provider: "github", Service: "repository",
			ResourceID: fmt.Sprintf("%s/%s", owner, reponame),
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}
	return findings, nil
}
