package compute

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// InstanceInTransitEncryptionCheck verifica criptografia em trânsito
type InstanceInTransitEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceInTransitEncryptionCheck() *InstanceInTransitEncryptionCheck {
	return &InstanceInTransitEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "compute_instance_in_transit_encryption_enabled",
			CheckTitle:      "Ensure instances have in-transit encryption enabled",
			ServiceName:     "compute",
			Severity:        "high",
			Description:     "Compute instances should have in-transit encryption enabled",
			RemediationText: "Enable in-transit encryption for compute instances",
			Categories:      []string{"compute"},
		},
	}
}

func (c *InstanceInTransitEncryptionCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceInTransitEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Compute() (core.ComputeClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Compute()")
	}

	computeClient, err := p.Compute()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	listReq := core.ListInstancesRequest{
		CompartmentId: &tenancyId,
	}

	instances, err := computeClient.ListInstances(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	for _, instance := range instances.Items {
		if instance.LaunchOptions != nil && instance.LaunchOptions.IsPvEncryptionInTransitEnabled != nil && *instance.LaunchOptions.IsPvEncryptionInTransitEnabled {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Instance %s has in-transit encryption enabled", safeString(instance.DisplayName)),
				ResourceID:     safeString(instance.Id),
				Provider:       "oci",
				Service:        "compute",
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
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Instance %s does not have in-transit encryption enabled", safeString(instance.DisplayName)),
				ResourceID:     safeString(instance.Id),
				Provider:       "oci",
				Service:        "compute",
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
			StatusExtended: "No instances found",
			Provider:       "oci",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// safeString retorna string vazia se ponteiro for nil
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
