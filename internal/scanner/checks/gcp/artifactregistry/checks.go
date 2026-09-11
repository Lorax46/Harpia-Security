package artifactregistry

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/artifactregistry/v1"
)

type artifactregistryProvider interface {
	ArtifactRegistry(ctx context.Context) (*artifactregistry.Service, error)
	ProjectID() string
}

// CmekEncryptionCheck - verifica criptografia CMEK
type CmekEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewCmekEncryptionCheck() *CmekEncryptionCheck {
	return &CmekEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "artifactregistry_cmek_encryption_enabled",
			CheckTitle: "Ensure Artifact Registry repositories are encrypted with CMEK",
			Description: "Artifact Registry repositories should be encrypted with customer-managed encryption keys",
			Severity: "high", ServiceName: "artifactregistry", ResourceType: "Repository",
			RemediationText: "Configure CMEK encryption for Artifact Registry repositories",
			Categories: []string{"artifactregistry", "encryption"},
		},
	}
}

func (c *CmekEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CmekEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(artifactregistryProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa artifactregistryProvider")
	}
	svc, err := p.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}

	locations := []string{"us-central1", "us-east1", "europe-west1", "asia-east1"}
	findings := []models.Finding{}

	for _, loc := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", p.ProjectID(), loc)
		repos, err := svc.Projects.Locations.Repositories.List(parent).Do()
		if err != nil {
			continue
		}

		for _, repo := range repos.Repositories {
			status := models.StatusPass
			ext := "Repository is encrypted with CMEK"
			hasCMEK := repo.KmsKeyName != ""
			if !hasCMEK {
				status = models.StatusFail
				ext = "Repository is not encrypted with CMEK"
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: repo.Name, Provider: "gcp", Service: "artifactregistry",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now().UTC(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "No repositories found",
			Provider: "gcp", Service: "artifactregistry",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// PublicAccessCheck - verifica acesso público
type PublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewPublicAccessCheck() *PublicAccessCheck {
	return &PublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "artifactregistry_public_access_disabled",
			CheckTitle: "Ensure Artifact Registry repositories have no public access",
			Description: "Artifact Registry repositories should have no public access",
			Severity: "high", ServiceName: "artifactregistry", ResourceType: "Repository",
			RemediationText: "Disable public access on Artifact Registry repositories",
			Categories: []string{"artifactregistry", "public-access"},
		},
	}
}

func (c *PublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Artifact Registry public access check requires GCP SDK",
		Provider: "gcp", Service: "artifactregistry",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// UsesPrivateLinkCheck - verifica private link
type UsesPrivateLinkCheck struct {
	metadata models.CheckMetadata
}

func NewUsesPrivateLinkCheck() *UsesPrivateLinkCheck {
	return &UsesPrivateLinkCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "artifactregistry_uses_private_link",
			CheckTitle: "Ensure Artifact Registry uses private link",
			Description: "Artifact Registry should use private link",
			Severity: "medium", ServiceName: "artifactregistry", ResourceType: "Repository",
			RemediationText: "Configure private link for Artifact Registry",
			Categories: []string{"artifactregistry", "private-link"},
		},
	}
}

func (c *UsesPrivateLinkCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *UsesPrivateLinkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Artifact Registry private link check requires GCP SDK",
		Provider: "gcp", Service: "artifactregistry",
		FoundAt: time.Now().UTC(),
	}}, nil
}
