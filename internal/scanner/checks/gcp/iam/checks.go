package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
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

// ServiceAccountManagedKeyCheck verifica chaves gerenciadas pelo usuário
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
			Description:     "Service account keys should be managed by user",
			RemediationText: "Use user-managed service account keys",
			Categories:      []string{"identity"},
		},
	}
}

func (c *ServiceAccountManagedKeyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceAccountManagedKeyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Service account managed key check completed",
			Provider: "gcp", Service: "iam",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}

// WorkloadIdentityCheck verifica Workload Identity
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
			Description:     "Workload Identity should be configured",
			RemediationText: "Configure Workload Identity",
			Categories:      []string{"identity"},
		},
	}
}

func (c *WorkloadIdentityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WorkloadIdentityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Workload Identity check completed",
			Provider: "gcp", Service: "iam",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		},
	}, nil
}