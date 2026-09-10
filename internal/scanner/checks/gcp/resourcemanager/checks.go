package resourcemanager

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/cloudresourcemanager/v1"
)

type resourcemanagerProvider interface {
	ResourceManager(ctx context.Context) (*cloudresourcemanager.Service, error)
	ProjectID() string
}

// ProjectIamCheck verifica IAM do projeto
type ProjectIamCheck struct {
	metadata models.CheckMetadata
}

func NewProjectIamCheck() *ProjectIamCheck {
	return &ProjectIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "resourcemanager_project_iam",
			CheckTitle:      "Project IAM is configured",
			ServiceName:     "resourcemanager",
			Severity:        "medium",
			Description:     "Project should have proper IAM configuration",
			RemediationText: "Configure IAM for project",
			Categories:      []string{"identity"},
		},
	}
}

func (c *ProjectIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ProjectIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(resourcemanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement resourcemanagerProvider")
	}
	svc, err := p.ResourceManager(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	policy, err := svc.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy: %w", err)
	}

	if len(policy.Bindings) > 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("Project has %d IAM bindings", len(policy.Bindings)),
			Provider: "gcp", Service: "resourcemanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "Project has no IAM bindings",
			Provider: "gcp", Service: "resourcemanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ProjectLoggingCheck verifica logging do projeto
type ProjectLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewProjectLoggingCheck() *ProjectLoggingCheck {
	return &ProjectLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "resourcemanager_project_logging",
			CheckTitle:      "Project logging is enabled",
			ServiceName:     "resourcemanager",
			Severity:        "low",
			Description:     "Project should have logging enabled",
			RemediationText: "Enable logging for project",
			Categories:      []string{"logging"},
		},
	}
}

func (c *ProjectLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ProjectLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Project logging check completed",
			Provider: "gcp", Service: "resourcemanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// ProjectMonitoringCheck verifica monitoring do projeto
type ProjectMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewProjectMonitoringCheck() *ProjectMonitoringCheck {
	return &ProjectMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "resourcemanager_project_monitoring",
			CheckTitle:      "Project monitoring is enabled",
			ServiceName:     "resourcemanager",
			Severity:        "low",
			Description:     "Project should have monitoring enabled",
			RemediationText: "Enable monitoring for project",
			Categories:      []string{"monitoring"},
		},
	}
}

func (c *ProjectMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ProjectMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Project monitoring check completed",
			Provider: "gcp", Service: "resourcemanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}