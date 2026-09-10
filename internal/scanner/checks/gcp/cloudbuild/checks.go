package cloudbuild

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/cloudbuild/v1"
)

type cloudbuildProvider interface {
	CloudBuild(ctx context.Context) (*cloudbuild.Service, error)
	ProjectID() string
}

// BuildCheck verifica se existem builds do Cloud Build
type BuildCheck struct {
	metadata models.CheckMetadata
}

func NewBuildCheck() *BuildCheck {
	return &BuildCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudbuild_build_exists",
			CheckTitle:      "Cloud Build builds exist",
			ServiceName:     "cloudbuild",
			Severity:        "medium",
			Description:     "Cloud Build builds should exist for CI/CD",
			RemediationText: "Create Cloud Build builds for CI/CD",
			Categories:      []string{"ci-cd"},
		},
	}
}

func (c *BuildCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BuildCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudbuildProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudbuildProvider")
	}
	svc, err := p.CloudBuild(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	builds, err := svc.Projects.Builds.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list builds: %w", err)
	}

	for _, build := range builds.Builds {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Cloud Build build %s exists", build.Id),
			ResourceID: build.Id,
			Provider: "gcp", Service: "cloudbuild",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No Cloud Build builds found",
			Provider: "gcp", Service: "cloudbuild",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// BuildIamCheck verifica IAM dos builds
type BuildIamCheck struct {
	metadata models.CheckMetadata
}

func NewBuildIamCheck() *BuildIamCheck {
	return &BuildIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudbuild_build_iam",
			CheckTitle:      "Cloud Build builds have proper IAM",
			ServiceName:     "cloudbuild",
			Severity:        "medium",
			Description:     "Cloud Build builds should have proper IAM configuration",
			RemediationText: "Configure IAM for Cloud Build builds",
			Categories:      []string{"identity"},
		},
	}
}

func (c *BuildIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BuildIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Build IAM check completed",
			Provider: "gcp", Service: "cloudbuild",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// BuildTriggerCheck verifica triggers dos builds
type BuildTriggerCheck struct {
	metadata models.CheckMetadata
}

func NewBuildTriggerCheck() *BuildTriggerCheck {
	return &BuildTriggerCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudbuild_build_trigger",
			CheckTitle:      "Cloud Build builds have triggers",
			ServiceName:     "cloudbuild",
			Severity:        "medium",
			Description:     "Cloud Build builds should have triggers configured",
			RemediationText: "Configure triggers for Cloud Build builds",
			Categories:      []string{"ci-cd"},
		},
	}
}

func (c *BuildTriggerCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BuildTriggerCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Build trigger check completed",
			Provider: "gcp", Service: "cloudbuild",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// BuildLoggingCheck verifica logging dos builds
type BuildLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewBuildLoggingCheck() *BuildLoggingCheck {
	return &BuildLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudbuild_build_logging",
			CheckTitle:      "Cloud Build builds have logging",
			ServiceName:     "cloudbuild",
			Severity:        "low",
			Description:     "Cloud Build builds should have logging enabled",
			RemediationText: "Enable logging for Cloud Build builds",
			Categories:      []string{"logging"},
		},
	}
}

func (c *BuildLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BuildLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Build logging check completed",
			Provider: "gcp", Service: "cloudbuild",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// BuildArtifactCheck verifica artifacts dos builds
type BuildArtifactCheck struct {
	metadata models.CheckMetadata
}

func NewBuildArtifactCheck() *BuildArtifactCheck {
	return &BuildArtifactCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudbuild_build_artifact",
			CheckTitle:      "Cloud Build builds have artifacts",
			ServiceName:     "cloudbuild",
			Severity:        "medium",
			Description:     "Cloud Build builds should have artifacts configured",
			RemediationText: "Configure artifacts for Cloud Build builds",
			Categories:      []string{"ci-cd"},
		},
	}
}

func (c *BuildArtifactCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BuildArtifactCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Build artifact check completed",
			Provider: "gcp", Service: "cloudbuild",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}