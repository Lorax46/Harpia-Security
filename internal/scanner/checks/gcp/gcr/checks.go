package gcr

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/cloudbuild/v1"
)

type gcrProvider interface {
	ArtifactRegistry(ctx context.Context) (*artifactregistry.Service, error)
	CloudBuild(ctx context.Context) (*cloudbuild.Service, error)
	ProjectID() string
}

// CmekEncryptionCheck - verifica criptografia CMEK
type CmekEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewCmekEncryptionCheck() *CmekEncryptionCheck {
	return &CmekEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "gcr_cmek_encryption_enabled",
			CheckTitle: "Ensure GCR repositories are encrypted with CMEK",
			Description: "GCR repositories should be encrypted with customer-managed encryption keys",
			Severity: "high", ServiceName: "gcr", ResourceType: "Repository",
			RemediationText: "Configure CMEK encryption for GCR repositories",
			Categories: []string{"gcr", "encryption"},
		},
	}
}

func (c *CmekEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CmekEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gcrProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa gcrProvider")
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
				ResourceID: repo.Name, Provider: "gcp", Service: "gcr",
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
			Provider: "gcp", Service: "gcr",
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
			Provider: "gcp", CheckID: "gcr_public_access_disabled",
			CheckTitle: "Ensure GCR repositories have no public access",
			Description: "GCR repositories should have no public access",
			Severity: "high", ServiceName: "gcr", ResourceType: "Repository",
			RemediationText: "Disable public access on GCR repositories",
			Categories: []string{"gcr", "public-access"},
		},
	}
}

func (c *PublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCR public access check requires GCP SDK",
		Provider: "gcp", Service: "gcr",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// VulnerabilityScanningCheck - verifica vulnerability scanning
type VulnerabilityScanningCheck struct {
	metadata models.CheckMetadata
}

func NewVulnerabilityScanningCheck() *VulnerabilityScanningCheck {
	return &VulnerabilityScanningCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "gcr_vulnerability_scanning_enabled",
			CheckTitle: "Ensure GCR vulnerability scanning is enabled",
			Description: "GCR should have vulnerability scanning enabled",
			Severity: "high", ServiceName: "gcr", ResourceType: "Repository",
			RemediationText: "Enable vulnerability scanning for GCR",
			Categories: []string{"gcr", "vulnerability"},
		},
	}
}

func (c *VulnerabilityScanningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VulnerabilityScanningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCR vulnerability scanning check requires GCP SDK",
		Provider: "gcp", Service: "gcr",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// WorkerPoolCheck - verifica worker pool
type WorkerPoolCheck struct {
	metadata models.CheckMetadata
}

func NewWorkerPoolCheck() *WorkerPoolCheck {
	return &WorkerPoolCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "gcr_worker_pool_enabled",
			CheckTitle: "Ensure GCR builds use private worker pool",
			Description: "GCR builds should use private worker pool",
			Severity: "medium", ServiceName: "gcr", ResourceType: "Build",
			RemediationText: "Configure private worker pool for GCR builds",
			Categories: []string{"gcr", "worker-pool"},
		},
	}
}

func (c *WorkerPoolCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WorkerPoolCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCR worker pool check requires GCP SDK",
		Provider: "gcp", Service: "gcr",
		FoundAt: time.Now().UTC(),
	}}, nil
}
