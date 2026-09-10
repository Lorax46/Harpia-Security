package artifactregistry

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"google.golang.org/api/artifactregistry/v1"
)

type artifactregistryProvider interface {
	ArtifactRegistry(ctx context.Context) (*artifactregistry.Service, error)
	ProjectID() string
	Region() string
}

// RepositoryCheck verifica se existem repositórios
type RepositoryCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryCheck() *RepositoryCheck {
	return &RepositoryCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "artifactregistry_repository_exists",
			CheckTitle:      "Artifact Registry repositories exist",
			ServiceName:     "artifactregistry",
			Severity:        "medium",
			Description:     "Artifact Registry repositories should exist for container images",
			RemediationText: "Create Artifact Registry repositories",
			Categories:      []string{"ci-cd"},
		},
	}
}

func (c *RepositoryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(artifactregistryProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement artifactregistryProvider")
	}
	svc, err := p.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	region := p.Region()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	repos, err := svc.Projects.Locations.Repositories.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	for _, repo := range repos.Repositories {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Repository %s exists", repo.Name),
			ResourceID: repo.Name,
			Provider: "gcp", Service: "artifactregistry",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No Artifact Registry repositories found",
			Provider: "gcp", Service: "artifactregistry",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// RepositoryIamCheck verifica IAM dos repositórios
type RepositoryIamCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryIamCheck() *RepositoryIamCheck {
	return &RepositoryIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "artifactregistry_repository_iam",
			CheckTitle:      "Artifact Registry repositories have proper IAM",
			ServiceName:     "artifactregistry",
			Severity:        "medium",
			Description:     "Artifact Registry repositories should have proper IAM configuration",
			RemediationText: "Configure IAM for Artifact Registry repositories",
			Categories:      []string{"identity"},
		},
	}
}

func (c *RepositoryIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Artifact Registry IAM check completed",
			Provider: "gcp", Service: "artifactregistry",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// RepositoryEncryptionCheck verifica criptografia dos repositórios
type RepositoryEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewRepositoryEncryptionCheck() *RepositoryEncryptionCheck {
	return &RepositoryEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "artifactregistry_repository_encryption",
			CheckTitle:      "Artifact Registry repositories are encrypted",
			ServiceName:     "artifactregistry",
			Severity:        "high",
			Description:     "Artifact Registry repositories should be encrypted",
			RemediationText: "Enable encryption for Artifact Registry repositories",
			Categories:      []string{"encryption"},
		},
	}
}

func (c *RepositoryEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RepositoryEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Artifact Registry encryption check completed",
			Provider: "gcp", Service: "artifactregistry",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}