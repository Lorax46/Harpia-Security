package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/iam/v1"
)

type iamProvider interface {
	IAM(ctx context.Context) (*iam.Service, error)
	ProjectID() string
}

// ServiceAccountKeyRotationCheck verifica rotação de chaves de service account
type ServiceAccountKeyRotationCheck struct {
	metadata models.CheckMetadata
}

func NewServiceAccountKeyRotationCheck() *ServiceAccountKeyRotationCheck {
	return &ServiceAccountKeyRotationCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "iam_service_account_key_rotation",
			CheckTitle:      "Service account keys are rotated",
			ServiceName:     "iam",
			Severity:        "medium",
			Description:     "Service account keys should be rotated regularly",
			RemediationText: "Rotate service account keys",
			Categories:      []string{"identity"},
		},
	}
}

func (c *ServiceAccountKeyRotationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceAccountKeyRotationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	svc, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	saList, err := svc.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", projectID)).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}

	for _, sa := range saList.Accounts {
		keys, err := svc.Projects.ServiceAccounts.Keys.List(sa.Name).Do()
		if err != nil {
			continue
		}
		for _, key := range keys.Keys {
			validAfter, parseErr := time.Parse(time.RFC3339, key.ValidAfterTime)
			if parseErr != nil {
				continue
			}
			age := time.Since(validAfter)
			if age > 90*24*time.Hour {
				findings = append(findings, models.Finding{
					ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
					Description: c.metadata.Description, Severity: c.metadata.Severity,
					Status: models.StatusFail,
					StatusExtended: fmt.Sprintf("Service account key %s is older than 90 days", key.Name),
					ResourceID: key.Name,
					Provider: "gcp", Service: "iam",
					Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
					FoundAt: time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "All service account keys are within 90 days rotation policy",
			Provider: "gcp", Service: "iam",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ServiceAccountManagedKeyCheck verifica se há chaves gerenciadas pelo usuário (user-managed keys)
type ServiceAccountManagedKeyCheck struct {
	metadata models.CheckMetadata
}

func NewServiceAccountManagedKeyCheck() *ServiceAccountManagedKeyCheck {
	return &ServiceAccountManagedKeyCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "iam_service_account_managed_key",
			CheckTitle:      "Service account keys are managed by user",
			ServiceName:     "iam",
			Severity:        "medium",
			Description:     "Service account keys should be managed by user (not Google-managed) for better control",
			RemediationText: "Use user-managed service account keys and rotate them regularly",
			Categories:      []string{"identity"},
		},
	}
}

func (c *ServiceAccountManagedKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceAccountManagedKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	svc, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	saList, err := svc.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", projectID)).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}

	for _, sa := range saList.Accounts {
		keys, err := svc.Projects.ServiceAccounts.Keys.List(sa.Name).Do()
		if err != nil {
			continue
		}

		hasUserManagedKey := false
		for _, key := range keys.Keys {
			// User-managed keys have keyType = USER_MANAGED
			if key.KeyType == "USER_MANAGED" {
				hasUserManagedKey = true
				break
			}
		}

		status := models.StatusPass
		ext := "Service account uses Google-managed keys (recommended)"
		if hasUserManagedKey {
			status = models.StatusFail
			ext = "Service account uses user-managed keys (consider using workload identity instead)"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: sa.Name,
			Provider: "gcp", Service: "iam",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// WorkloadIdentityCheck verifica se Workload Identity está configurado no projeto
type WorkloadIdentityCheck struct {
	metadata models.CheckMetadata
}

func NewWorkloadIdentityCheck() *WorkloadIdentityCheck {
	return &WorkloadIdentityCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "iam_workload_identity",
			CheckTitle:      "Workload Identity is configured",
			ServiceName:     "iam",
			Severity:        "medium",
			Description:     "Workload Identity should be configured to allow Kubernetes service accounts to impersonate GCP service accounts",
			RemediationText: "Configure Workload Identity for GKE clusters",
			Categories:      []string{"identity"},
		},
	}
}

func (c *WorkloadIdentityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WorkloadIdentityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	svc, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// Check if there are any workload identity pools configured
	pools, err := svc.Projects.Locations.WorkloadIdentityPools.List(fmt.Sprintf("projects/%s/locations/global", projectID)).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list workload identity pools: %w", err)
	}

	if len(pools.WorkloadIdentityPools) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No workload identity pools found in project",
			ResourceID: projectID,
			Provider: "gcp", Service: "iam",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	} else {
		for _, pool := range pools.WorkloadIdentityPools {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Workload identity pool %s is configured", pool.Name),
				ResourceID: pool.Name,
				Provider: "gcp", Service: "iam",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	return findings, nil
}
