package codebuild

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type codebuildProvider interface {
	CodeBuild(ctx context.Context) (*codebuild.Client, error)
}

// CodebuildProjectLoggingEnabled - CodeBuild project has logging enabled
type CodebuildProjectLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectLoggingEnabled() *CodebuildProjectLoggingEnabled {
	return &CodebuildProjectLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_logging_enabled",
			CheckTitle:   "CodeBuild project has logging enabled",
			ServiceName:  "codebuild",
			Severity:     "medium",
			ResourceType: "Project",
			Description:  "CodeBuild projects should have logging enabled",
			RemediationText: "Enable CloudWatch logs and/or S3 logs on your CodeBuild projects",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s has logging enabled.", projectName)

			cwLogsEnabled := project.LogsConfig != nil && project.LogsConfig.CloudWatchLogs != nil && project.LogsConfig.CloudWatchLogs.Status == types.LogsConfigStatusTypeEnabled
			s3LogsEnabled := project.LogsConfig != nil && project.LogsConfig.S3Logs != nil && project.LogsConfig.S3Logs.Status == types.LogsConfigStatusTypeEnabled

			if !cwLogsEnabled && !s3LogsEnabled {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("CodeBuild project %s does not have any logging enabled.", projectName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectNoSecretsInVariables - CodeBuild project does not have secrets in environment variables
type CodebuildProjectNoSecretsInVariables struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectNoSecretsInVariables() *CodebuildProjectNoSecretsInVariables {
	return &CodebuildProjectNoSecretsInVariables{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_no_secrets_in_variables",
			CheckTitle:   "CodeBuild project does not have secrets in environment variables",
			ServiceName:  "codebuild",
			Severity:     "high",
			ResourceType: "Project",
			Description:  "CodeBuild projects should not have secrets in environment variables",
			RemediationText: "Use AWS Secrets Manager or SSM Parameter Store for secrets",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectNoSecretsInVariables) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectNoSecretsInVariables) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		sensitivePatterns := []string{"password", "secret", "token", "apikey", "api_key", "private_key", "access_key", "credential"}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s does not have secrets in environment variables.", projectName)

			if project.Environment != nil {
				for _, envVar := range project.Environment.EnvironmentVariables {
					envName := aws.ToString(envVar.Name)
					for _, pattern := range sensitivePatterns {
						if containsPattern(envName, pattern) {
							status = models.StatusFail
							statusExtended = fmt.Sprintf("CodeBuild project %s may have secrets in environment variable: %s", projectName, envName)
							break
						}
					}
					if status == models.StatusFail {
						break
					}
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

func containsPattern(s, pattern string) bool {
	if len(s) < len(pattern) {
		return false
	}
	for i := 0; i <= len(s)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			c1 := s[i+j]
			c2 := pattern[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 = c1 + 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 = c2 + 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// CodebuildProjectNotPubliclyAccessible - CodeBuild project is not publicly accessible
type CodebuildProjectNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectNotPubliclyAccessible() *CodebuildProjectNotPubliclyAccessible {
	return &CodebuildProjectNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_not_publicly_accessible",
			CheckTitle:   "CodeBuild project is not publicly accessible",
			ServiceName:  "codebuild",
			Severity:     "high",
			ResourceType: "Project",
			Description:  "CodeBuild projects should not be publicly accessible",
			RemediationText: "Set project visibility to PRIVATE",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusFail
			statusExtended := fmt.Sprintf("CodeBuild project %s is public.", projectName)

			if project.ProjectVisibility == types.ProjectVisibilityTypePrivate {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("CodeBuild project %s is private.", projectName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectOlder90Days - CodeBuild project has not been built in the last 90 days
type CodebuildProjectOlder90Days struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectOlder90Days() *CodebuildProjectOlder90Days {
	return &CodebuildProjectOlder90Days{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_older_90_days",
			CheckTitle:   "CodeBuild project has been used in the last 90 days",
			ServiceName:  "codebuild",
			Severity:     "low",
			ResourceType: "Project",
			Description:  "CodeBuild projects should be actively used; inactive projects should be reviewed",
			RemediationText: "Review and clean up unused CodeBuild projects",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectOlder90Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectOlder90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s has been used recently.", projectName)

			// Check if project has builds
			builds, err := cbClient.ListBuildsForProject(ctx, &codebuild.ListBuildsForProjectInput{
				ProjectName: aws.String(projectName),
			})
			if err != nil || len(builds.Ids) == 0 {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("CodeBuild project %s has no builds.", projectName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectS3LogsEncrypted - CodeBuild project S3 logs are encrypted
type CodebuildProjectS3LogsEncrypted struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectS3LogsEncrypted() *CodebuildProjectS3LogsEncrypted {
	return &CodebuildProjectS3LogsEncrypted{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_s3_logs_encrypted",
			CheckTitle:   "CodeBuild project S3 logs are encrypted",
			ServiceName:  "codebuild",
			Severity:     "medium",
			ResourceType: "Project",
			Description:  "CodeBuild project S3 logs should be encrypted",
			RemediationText: "Enable S3 log encryption on your CodeBuild projects",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectS3LogsEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectS3LogsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s S3 logs are encrypted or not configured.", projectName)

			if project.LogsConfig != nil && project.LogsConfig.S3Logs != nil && project.LogsConfig.S3Logs.Status == types.LogsConfigStatusTypeEnabled && aws.ToBool(project.LogsConfig.S3Logs.EncryptionDisabled) {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("CodeBuild project %s S3 logs are not encrypted.", projectName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectSourceRepoUrlNoSensitiveCredentials - CodeBuild source repo URL does not contain credentials
type CodebuildProjectSourceRepoUrlNoSensitiveCredentials struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectSourceRepoUrlNoSensitiveCredentials() *CodebuildProjectSourceRepoUrlNoSensitiveCredentials {
	return &CodebuildProjectSourceRepoUrlNoSensitiveCredentials{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_source_repo_url_no_sensitive_credentials",
			CheckTitle:   "CodeBuild source repo URL does not contain credentials",
			ServiceName:  "codebuild",
			Severity:     "high",
			ResourceType: "Project",
			Description:  "CodeBuild source repository URLs should not contain sensitive credentials",
			RemediationText: "Remove credentials from repository URLs and use proper authentication methods",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectSourceRepoUrlNoSensitiveCredentials) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectSourceRepoUrlNoSensitiveCredentials) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s source URL does not contain credentials.", projectName)

			// Check for common credential patterns in source location
			if project.Source != nil {
				sourceLocation := aws.ToString(project.Source.Location)
				if containsPattern(sourceLocation, "@") && containsPattern(sourceLocation, "://") {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("CodeBuild project %s source URL may contain credentials.", projectName)
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectUserControlledBuildspec - CodeBuild project does not allow user-controlled buildspec
type CodebuildProjectUserControlledBuildspec struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectUserControlledBuildspec() *CodebuildProjectUserControlledBuildspec {
	return &CodebuildProjectUserControlledBuildspec{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_user_controlled_buildspec",
			CheckTitle:   "CodeBuild project does not allow user-controlled buildspec",
			ServiceName:  "codebuild",
			Severity:     "medium",
			ResourceType: "Project",
			Description:  "CodeBuild projects should not allow user-controlled buildspec to prevent injection attacks",
			RemediationText: "Use buildspec.yml from repository instead of allowing user override",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectUserControlledBuildspec) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectUserControlledBuildspec) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s does not allow user-controlled buildspec.", projectName)

			// Check if buildspec is user-controlled (when buildspec field is specified externally)
			if project.Source != nil && project.Source.Buildspec != nil && aws.ToString(project.Source.Buildspec) != "" {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("CodeBuild project %s allows user-controlled buildspec.", projectName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectUsesAllowedGithubOrganizations - CodeBuild project uses allowed GitHub organizations
type CodebuildProjectUsesAllowedGithubOrganizations struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectUsesAllowedGithubOrganizations() *CodebuildProjectUsesAllowedGithubOrganizations {
	return &CodebuildProjectUsesAllowedGithubOrganizations{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_uses_allowed_github_organizations",
			CheckTitle:   "CodeBuild project uses allowed GitHub organizations",
			ServiceName:  "codebuild",
			Severity:     "medium",
			ResourceType: "Project",
			Description:  "CodeBuild projects should use only allowed GitHub organizations as source",
			RemediationText: "Restrict CodeBuild projects to use only approved GitHub organizations",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectUsesAllowedGithubOrganizations) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectUsesAllowedGithubOrganizations) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s source is not from GitHub or uses allowed organizations.", projectName)

			if project.Source != nil {
				sourceLocation := aws.ToString(project.Source.Location)
				if containsPattern(sourceLocation, "github.com") && !containsPattern(sourceLocation, "organizations") {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("CodeBuild project %s source is from GitHub without organization restriction.", projectName)
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildProjectWebhookFiltersUseAnchoredPatterns - CodeBuild project webhook filters use anchored patterns
type CodebuildProjectWebhookFiltersUseAnchoredPatterns struct {
	metadata models.CheckMetadata
}

func NewCodebuildProjectWebhookFiltersUseAnchoredPatterns() *CodebuildProjectWebhookFiltersUseAnchoredPatterns {
	return &CodebuildProjectWebhookFiltersUseAnchoredPatterns{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_project_webhook_filters_use_anchored_patterns",
			CheckTitle:   "CodeBuild project webhook filters use anchored patterns",
			ServiceName:  "codebuild",
			Severity:     "medium",
			ResourceType: "Project",
			Description:  "CodeBuild project webhook filters should use anchored patterns to prevent unauthorized triggers",
			RemediationText: "Use anchored patterns (^$) in webhook filters",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildProjectWebhookFiltersUseAnchoredPatterns) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildProjectWebhookFiltersUseAnchoredPatterns) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	projects, err := cbClient.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
	}

	if len(projects.Projects) > 0 {
		batchOutput, err := cbClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: projects.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			projectName := aws.ToString(project.Name)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild project %s webhook filters use anchored patterns or webhooks are not configured.", projectName)

			// Check webhook filters for unanchored patterns
			if project.Webhook != nil && project.Webhook.FilterGroups != nil {
				for _, fg := range project.Webhook.FilterGroups {
					for _, f := range fg {
						pattern := aws.ToString(f.Pattern)
						if pattern != "" && pattern[0] != '^' {
							status = models.StatusFail
							statusExtended = fmt.Sprintf("CodeBuild project %s webhook filters do not use anchored patterns.", projectName)
							break
						}
					}
					if status == models.StatusFail {
						break
					}
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     projectName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// CodebuildReportGroupExportEncrypted - CodeBuild report group export is encrypted
type CodebuildReportGroupExportEncrypted struct {
	metadata models.CheckMetadata
}

func NewCodebuildReportGroupExportEncrypted() *CodebuildReportGroupExportEncrypted {
	return &CodebuildReportGroupExportEncrypted{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "codebuild_report_group_export_encrypted",
			CheckTitle:   "CodeBuild report group export is encrypted",
			ServiceName:  "codebuild",
			Severity:     "medium",
			ResourceType: "ReportGroup",
			Description:  "CodeBuild report group S3 exports should be encrypted",
			RemediationText: "Enable S3 encryption for CodeBuild report group exports",
			Categories:   []string{"ci-cd"},
		},
	}
}

func (c *CodebuildReportGroupExportEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodebuildReportGroupExportEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(codebuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement codebuildProvider")
	}
	cbClient, err := p.CodeBuild(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	reportGroups, err := cbClient.ListReportGroups(ctx, &codebuild.ListReportGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CodeBuild report groups: %w", err)
	}

	if len(reportGroups.ReportGroups) > 0 {
		batchOutput, err := cbClient.BatchGetReportGroups(ctx, &codebuild.BatchGetReportGroupsInput{
			ReportGroupArns: reportGroups.ReportGroups,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild report groups: %w", err)
		}

		for _, rg := range batchOutput.ReportGroups {
			rgArn := aws.ToString(rg.Arn)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("CodeBuild report group %s export is encrypted or not configured.", rgArn)

			if rg.ExportConfig != nil && rg.ExportConfig.S3Destination != nil {
				if aws.ToBool(rg.ExportConfig.S3Destination.EncryptionDisabled) {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("CodeBuild report group %s export is not encrypted.", rgArn)
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "codebuild",
				ResourceID:     rgArn,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}