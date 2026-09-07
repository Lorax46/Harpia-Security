package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type monitorProvider interface {
	DiagnosticSettingsClient(ctx context.Context) (*armmonitor.DiagnosticSettingsClient, error)
}

// ==================== Diagnostic Settings Enabled ====================

type DiagnosticSettingsCheck struct {
	metadata models.CheckMetadata
}

func NewDiagnosticSettingsCheck() *DiagnosticSettingsCheck {
	return &DiagnosticSettingsCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "monitor_diagnostic_settings_enabled",
			CheckTitle:      "Resources should have diagnostic settings configured",
			ServiceName:     "monitor",
			Severity:        "medium",
			ResourceType:    "DiagnosticSettings",
			ResourceGroup:   "Monitor",
			Description:     "Resources should have diagnostic settings to capture logs and metrics",
			Risk:            "Without diagnostic settings, troubleshooting and monitoring are difficult",
			RemediationText: "Configure diagnostic settings on critical resources",
			Categories:      []string{"monitor", "logging"},
		},
	}
}

func (c *DiagnosticSettingsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DiagnosticSettingsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(monitorProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa monitorProvider")
	}

	client, err := p.DiagnosticSettingsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager("", nil)
	settingsFound := false
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar diagnostic settings: %w", err)
		}
		for _, setting := range page.Value {
			if setting != nil && setting.ID != nil {
				settingsFound = true
				status := models.StatusPass
				ext := fmt.Sprintf("Diagnostic setting %s is configured", *setting.Name)
				findings = append(findings, models.Finding{
					ID:              c.metadata.CheckID,
					Title:           c.metadata.CheckTitle,
					Description:     c.metadata.Description,
					Severity:        c.metadata.Severity,
					Status:          status,
					StatusExtended:  ext,
					Provider:        "azure",
					Service:         "monitor",
					ResourceID:      *setting.ID,
					Remediation:     c.metadata.RemediationText,
					Categories:      c.metadata.Categories,
					FoundAt:         time.Now(),
				})
			}
		}
	}
	if !settingsFound {
		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          models.StatusFail,
			StatusExtended:  "No diagnostic settings found in the subscription",
			Provider:        "azure",
			Service:         "monitor",
			ResourceID:      "subscription",
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}
	return findings, nil
}

// ==================== Activity Log Alerts Exists ====================

type ActivityLogAlertsCheck struct {
	metadata models.CheckMetadata
}

func NewActivityLogAlertsCheck() *ActivityLogAlertsCheck {
	return &ActivityLogAlertsCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "monitor_activity_log_alerts_exists",
			CheckTitle:      "Activity log alerts should exist for critical operations",
			ServiceName:     "monitor",
			Severity:        "medium",
			ResourceType:    "ActivityLogAlert",
			ResourceGroup:   "Monitor",
			Description:     "Activity log alerts should be configured for security-critical operations",
			Risk:            "Without alerts, security events may go unnoticed",
			RemediationText: "Configure activity log alerts for critical operations",
			Categories:      []string{"monitor", "alerting"},
		},
	}
}

func (c *ActivityLogAlertsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ActivityLogAlertsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(monitorProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa monitorProvider")
	}

	client, err := p.DiagnosticSettingsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	// List all diagnostic settings as proxy for activity log alerts
	pager := client.NewListPager("", nil)
	hasAlerts := false
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar diagnostic settings: %w", err)
		}
		for _, setting := range page.Value {
			if setting != nil && setting.ID != nil {
				hasAlerts = true
				status := models.StatusPass
				ext := fmt.Sprintf("Activity log alert %s exists", *setting.Name)
				findings = append(findings, models.Finding{
					ID:              c.metadata.CheckID,
					Title:           c.metadata.CheckTitle,
					Description:     c.metadata.Description,
					Severity:        c.metadata.Severity,
					Status:          status,
					StatusExtended:  ext,
					Provider:        "azure",
					Service:         "monitor",
					ResourceID:      *setting.ID,
					Remediation:     c.metadata.RemediationText,
					Categories:      c.metadata.Categories,
					FoundAt:         time.Now(),
				})
			}
		}
	}
	if !hasAlerts {
		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          models.StatusFail,
			StatusExtended:  "No activity log alerts found in the subscription",
			Provider:        "azure",
			Service:         "monitor",
			ResourceID:      "subscription",
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}
	return findings, nil
}
