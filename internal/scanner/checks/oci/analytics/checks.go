package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/analytics"
)

// InstanceAccessRestrictedCheck verifica se instâncias analytics têm acesso restrito
type InstanceAccessRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceAccessRestrictedCheck() *InstanceAccessRestrictedCheck {
	return &InstanceAccessRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "analytics_instance_access_restricted",
			CheckTitle:      "Ensure Analytics Cloud instances are not publicly accessible",
			ServiceName:     "analytics",
			Severity:        "high",
			Description:     "Oracle Analytics Cloud instances should not be publicly accessible",
			RemediationText: "Restrict access to Oracle Analytics Cloud instances",
			Categories:      []string{"analytics"},
		},
	}
}

func (c *InstanceAccessRestrictedCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceAccessRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Analytics() (analytics.AnalyticsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Analytics()")
	}

	client, err := p.Analytics()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := analytics.ListAnalyticsInstancesRequest{
		CompartmentId: &tenancyId,
	}
	instances, err := client.ListAnalyticsInstances(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	for _, instance := range instances.Items {
		isPublic := false
		if instance.NetworkEndpointDetails != nil {
			// Verifica se é endpoint público
			if _, ok := instance.NetworkEndpointDetails.(analytics.PublicEndpointDetails); ok {
				isPublic = true
			}
		}

		if isPublic {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Analytics instance %s is publicly accessible", *instance.Name),
				ResourceID:     *instance.Id,
				Provider:       "oci",
				Service:        "analytics",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Analytics instance %s is private", *instance.Name),
				ResourceID:     *instance.Id,
				Provider:       "oci",
				Service:        "analytics",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No Analytics instances found",
			Provider:       "oci",
			Service:        "analytics",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
