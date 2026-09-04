package cloudguard

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/cloudguard"
)

// CloudguardEnabledCheck verifica se Cloudguard está habilitado
type CloudguardEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudguardEnabledCheck() *CloudguardEnabledCheck {
	return &CloudguardEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "cloudguard_enabled",
			CheckTitle:      "Ensure Cloud Guard is enabled",
			ServiceName:     "cloudguard",
			Severity:        "high",
			Description:     "Cloud Guard should be enabled for threat detection",
			RemediationText: "Enable Cloud Guard at the tenancy level",
			Categories:      []string{"security"},
		},
	}
}

func (c *CloudguardEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudguardEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		CloudGuard() (cloudguard.CloudGuardClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa CloudGuard()")
	}

	client, err := p.CloudGuard()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := cloudguard.GetConfigurationRequest{
		CompartmentId: &tenancyId,
	}
	config, err := client.GetConfiguration(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter configuração do Cloud Guard: %w", err)
	}

	if config.Status == "ENABLED" {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Cloud Guard is enabled",
			Provider:       "oci",
			Service:        "cloudguard",
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
			StatusExtended: fmt.Sprintf("Cloud Guard status: %s", string(config.Status)),
			Provider:       "oci",
			Service:        "cloudguard",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
