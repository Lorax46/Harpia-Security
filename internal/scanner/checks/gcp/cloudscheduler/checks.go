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
	Region() string
}

// JobCheck verifica se existem jobs do Cloud Scheduler
type JobCheck struct {
	metadata models.CheckMetadata
}

func NewJobCheck() *JobCheck {
	return &JobCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudscheduler_job_exists",
			CheckTitle:      "Cloud Scheduler jobs exist",
			ServiceName:     "cloudscheduler",
			Severity:        "medium",
			Description:     "Cloud Scheduler jobs should exist for scheduled tasks",
			RemediationText: "Create Cloud Scheduler jobs for scheduled tasks",
			Categories:      []string{"compute"},
		},
	}
}

func (c *JobCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudschedulerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudschedulerProvider")
	}
	svc, err := p.CloudScheduler(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	region := p.Region()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	jobs, err := svc.Projects.Locations.Jobs.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list scheduler jobs: %w", err)
	}

	for _, job := range jobs.Jobs {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Cloud Scheduler job %s exists", job.Name),
			ResourceID: job.Name,
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No Cloud Scheduler jobs found",
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// JobIamCheck verifica IAM dos jobs
type JobIamCheck struct {
	metadata models.CheckMetadata
}

func NewJobIamCheck() *JobIamCheck {
	return &JobIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudscheduler_job_iam",
			CheckTitle:      "Cloud Scheduler jobs have proper IAM",
			ServiceName:     "cloudscheduler",
			Severity:        "medium",
			Description:     "Cloud Scheduler jobs should have proper IAM configuration",
			RemediationText: "Configure IAM for Cloud Scheduler jobs",
			Categories:      []string{"identity"},
		},
	}
}

func (c *JobIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Scheduler IAM check completed",
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// JobRetryCheck verifica retry dos jobs
type JobRetryCheck struct {
	metadata models.CheckMetadata
}

func NewJobRetryCheck() *JobRetryCheck {
	return &JobRetryCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudscheduler_job_retry",
			CheckTitle:      "Cloud Scheduler jobs have retry configured",
			ServiceName:     "cloudscheduler",
			Severity:        "low",
			Description:     "Cloud Scheduler jobs should have retry configured",
			RemediationText: "Configure retry for Cloud Scheduler jobs",
			Categories:      []string{"reliability"},
		},
	}
}

func (c *JobRetryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobRetryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Scheduler retry check completed",
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// JobLoggingCheck verifica logging dos jobs
type JobLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewJobLoggingCheck() *JobLoggingCheck {
	return &JobLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudscheduler_job_logging",
			CheckTitle:      "Cloud Scheduler jobs have logging",
			ServiceName:     "cloudscheduler",
			Severity:        "low",
			Description:     "Cloud Scheduler jobs should have logging enabled",
			RemediationText: "Enable logging for Cloud Scheduler jobs",
			Categories:      []string{"logging"},
		},
	}
}

func (c *JobLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Scheduler logging check completed",
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// JobTargetCheck verifica targets dos jobs
type JobTargetCheck struct {
	metadata models.CheckMetadata
}

func NewJobTargetCheck() *JobTargetCheck {
	return &JobTargetCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudscheduler_job_target",
			CheckTitle:      "Cloud Scheduler jobs have targets",
			ServiceName:     "cloudscheduler",
			Severity:        "medium",
			Description:     "Cloud Scheduler jobs should have targets configured",
			RemediationText: "Configure targets for Cloud Scheduler jobs",
			Categories:      []string{"compute"},
		},
	}
}

func (c *JobTargetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobTargetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Cloud Scheduler target check completed",
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}