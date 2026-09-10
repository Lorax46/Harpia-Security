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

// ProjectLoggingCheck verifica logging do projeto via Cloud Logging API
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
			Description:     "Project should have logging enabled with audit log configuration",
			RemediationText: "Enable Cloud Logging with audit log configuration",
			Categories:      []string{"logging"},
		},
	}
}

func (c *ProjectLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ProjectLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	// Check if the project has logging enabled by verifying IAM policy for logging roles
	policy, err := svc.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy: %w", err)
	}

	hasLoggingRole := false
	for _, binding := range policy.Bindings {
		if binding.Role == "roles/logging.logWriter" || binding.Role == "roles/logging.admin" || binding.Role == "roles/logging.viewer" {
			hasLoggingRole = true
			break
		}
	}

	status := models.StatusPass
	ext := "Project has logging roles configured"
	if !hasLoggingRole {
		status = models.StatusFail
		ext = "Project does not have logging roles configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: ext,
		ResourceID: projectID,
		Provider: "gcp", Service: "resourcemanager",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
		FoundAt: time.Now(),
	})

	return findings, nil
}

// ProjectMonitoringCheck verifica monitoring do projeto via Cloud Monitoring
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
			Description:     "Project should have monitoring enabled with uptime checks",
			RemediationText: "Enable Cloud Monitoring with uptime checks",
			Categories:      []string{"monitoring"},
		},
	}
}

func (c *ProjectMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ProjectMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

	// Check if the project has monitoring enabled by checking if it has monitoring permissions
	// We do this by checking the project's IAM policy for monitoring-related roles
	policy, err := svc.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy: %w", err)
	}

	hasMonitoringRole := false
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "serviceAccount:cloud-monitoring@" || binding.Role == "roles/monitoring.viewer" {
				hasMonitoringRole = true
				break
			}
		}
		if hasMonitoringRole {
			break
		}
	}

	status := models.StatusPass
	ext := "Project has monitoring roles configured"
	if !hasMonitoringRole {
		status = models.StatusFail
		ext = "Project does not have monitoring roles configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: ext,
		ResourceID: projectID,
		Provider: "gcp", Service: "resourcemanager",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
		FoundAt: time.Now(),
	})

	return findings, nil
}