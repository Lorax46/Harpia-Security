package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/audit"
)

// LogRetentionCheck verifica retenção de logs
type LogRetentionCheck struct {
	metadata models.CheckMetadata
}

func NewLogRetentionCheck() *LogRetentionCheck {
	return &LogRetentionCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "audit_log_retention_period_365_days",
			CheckTitle:      "Tenancy audit log retention period is 365 days or greater",
			ServiceName:     "audit",
			Severity:        "medium",
			Description:     "OCI Audit configuration defines tenancy-wide log retention",
			RemediationText: "Set audit retention to >= 365 days",
			Categories:      []string{"audit"},
		},
	}
}

func (c *LogRetentionCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LogRetentionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Audit() (audit.AuditClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Audit()")
	}

	auditClient, err := p.Audit()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	request := audit.GetConfigurationRequest{
		CompartmentId: &tenancyId,
	}

	response, err := auditClient.GetConfiguration(ctx, request)
	if err != nil {
		// Se não tem permissão, retorna INFO ao invés de erro
		if err.Error() != "" && (contains(err.Error(), "NotAuthorized") || contains(err.Error(), "404")) {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusInfo,
				StatusExtended: "Unable to verify audit retention (insufficient permissions)",
				Provider:       "oci",
				Service:        "audit",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
			return findings, nil
		}
		return nil, fmt.Errorf("falha ao obter configuração de audit: %w", err)
	}

	retentionPeriod := response.Configuration.RetentionPeriodDays
	if retentionPeriod != nil && *retentionPeriod >= 365 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("Audit log retention is %d days", *retentionPeriod),
			Provider:       "oci",
			Service:        "audit",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		msg := "Audit log retention is less than 365 days"
		if retentionPeriod != nil {
			msg = fmt.Sprintf("Audit log retention is %d days (should be >= 365)", *retentionPeriod)
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: msg,
			Provider:       "oci",
			Service:        "audit",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
