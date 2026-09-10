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

// JobIamCheck verifica IAM dos jobs - verifica acesso público
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
			Description:     "Cloud Scheduler jobs should not have public IAM access",
			RemediationText: "Remove allUsers from Cloud Scheduler job IAM",
			Categories:      []string{"identity"},
		},
	}
}

func (c *JobIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		iamPolicy, err := svc.Projects.Locations.Jobs.GetIamPolicy(job.Name, &cloudscheduler.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			continue
		}

		hasPublicAccess := false
		for _, binding := range iamPolicy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					hasPublicAccess = true
					break
				}
			}
		}

		status := models.StatusPass
		ext := "Job has proper IAM configuration"
		if hasPublicAccess {
			status = models.StatusFail
			ext = "Job has public IAM access"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: job.Name,
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
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
			Description:     "Cloud Scheduler jobs should have retry configured for reliability",
			RemediationText: "Configure retry for Cloud Scheduler jobs",
			Categories:      []string{"reliability"},
		},
	}
}

func (c *JobRetryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobRetryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		hasRetryConfig := job.RetryConfig != nil && job.RetryConfig.RetryCount > 0
		status := models.StatusPass
		ext := fmt.Sprintf("Job %s has retry configured", job.Name)
		if !hasRetryConfig {
			status = models.StatusFail
			ext = fmt.Sprintf("Job %s does not have retry configured", job.Name)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: job.Name,
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
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
			Description:     "Cloud Scheduler jobs should have logging enabled for monitoring",
			RemediationText: "Enable logging for Cloud Scheduler jobs",
			Categories:      []string{"logging"},
		},
	}
}

func (c *JobLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *JobLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		hasLogging := job.LogConfig != nil && job.LogConfig.Enable
		status := models.StatusPass
		ext := fmt.Sprintf("Job %s has logging enabled", job.Name)
		if !hasLogging {
			status = models.StatusFail
			ext = fmt.Sprintf("Job %s does not have logging enabled", job.Name)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: job.Name,
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
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
		// Check if job has a valid target configured
		hasTarget := job.PubsubTarget != nil || job.HttpTarget != nil || job.AppEngineHttpTarget != nil
		status := models.StatusPass
		ext := fmt.Sprintf("Job %s has target configured", job.Name)
		if !hasTarget {
			status = models.StatusFail
			ext = fmt.Sprintf("Job %s does not have target configured", job.Name)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: job.Name,
			Provider: "gcp", Service: "cloudscheduler",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}
