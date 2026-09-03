package audit

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// AuditLogRetentionPeriod365Days - medium
type AuditLogRetentionPeriod365Days struct {
	metadata models.CheckMetadata
}

// NewAuditLogRetentionPeriod365Days cria nova instância
func NewAuditLogRetentionPeriod365Days() *AuditLogRetentionPeriod365Days {
	return &AuditLogRetentionPeriod365Days{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "audit_log_retention_period_365_days",
			CheckTitle:     "Tenancy audit log retention period is 365 days or greater",
			ServiceName:    "audit",
			Severity:       "medium",
			Description:    "**OCI Audit configuration** defines tenancy-wide log retention for audit events. The finding evaluates whether the retention period (days) is `>= 365`",
			RemediationText: "Set audit retention to `>= 365` days at the tenancy level and protect the setting with **least privi",
			Categories:     []string{"audit"},
		},
	}
}

// Metadata retorna os metadados
func (c *AuditLogRetentionPeriod365Days) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *AuditLogRetentionPeriod365Days) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "audit",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

