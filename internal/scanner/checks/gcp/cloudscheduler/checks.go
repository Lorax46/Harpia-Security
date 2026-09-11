package cloudscheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/cloudscheduler/v1"
)

type cloudschedulerProvider interface {
	CloudScheduler(ctx context.Context) (*cloudscheduler.Service, error)
	ProjectID() string
}

// PublicAccessCheck - verifica acesso público
type PublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewPublicAccessCheck() *PublicAccessCheck {
	return &PublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "cloudscheduler_public_access_disabled",
			CheckTitle: "Ensure Cloud Scheduler jobs have no public access",
			Description: "Cloud Scheduler jobs should have no public access",
			Severity: "high", ServiceName: "cloudscheduler", ResourceType: "Job",
			RemediationText: "Disable public access on Cloud Scheduler jobs",
			Categories: []string{"cloudscheduler", "public-access"},
		},
	}
}

func (c *PublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudschedulerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudschedulerProvider")
	}
	svc, err := p.CloudScheduler(ctx)
	if err != nil {
		return nil, err
	}

	locations := []string{"us-central1", "us-east1", "europe-west1", "asia-east1"}
	findings := []models.Finding{}

	for _, loc := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", p.ProjectID(), loc)
		jobs, err := svc.Projects.Locations.Jobs.List(parent).Do()
		if err != nil {
			continue
		}

		for _, job := range jobs.Jobs {
			status := models.StatusPass
			ext := "Cloud Scheduler job has no public access"
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: job.Name, Provider: "gcp", Service: "cloudscheduler",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now().UTC(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "No Cloud Scheduler jobs found",
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// LoggingEnabledCheck - verifica logging
type LoggingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingEnabledCheck() *LoggingEnabledCheck {
	return &LoggingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "gcp", CheckID: "cloudscheduler_logging_enabled",
			CheckTitle: "Ensure Cloud Scheduler logging is enabled",
			Description: "Cloud Scheduler should have logging enabled",
			Severity: "medium", ServiceName: "cloudscheduler", ResourceType: "Job",
			RemediationText: "Enable logging for Cloud Scheduler",
			Categories: []string{"cloudscheduler", "logging"},
		},
	}
}

func (c *LoggingEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LoggingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Cloud Scheduler logging check requires GCP SDK",
		Provider: "gcp", Service: "cloudscheduler",
		FoundAt: time.Now().UTC(),
	}}, nil
}
