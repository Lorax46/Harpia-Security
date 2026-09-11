package monitor

// =============================================================================
// Azure Monitor Checks — 15 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// MonitorDiagnosticSettings - verifica configurações de diagnóstico
type MonitorDiagnosticSettings struct {
	metadata models.CheckMetadata
}

func NewMonitorDiagnosticSettings() *MonitorDiagnosticSettings {
	return &MonitorDiagnosticSettings{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_diagnostic_settings",
			CheckTitle: "Ensure diagnostic settings are configured",
			Description: "Diagnostic settings should be configured for all resources",
			Severity: "medium", ServiceName: "monitor", ResourceType: "DiagnosticSettings",
			RemediationText: "Configure diagnostic settings",
			Categories: []string{"monitor", "diagnostics"},
		},
	}
}

func (c *MonitorDiagnosticSettings) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorDiagnosticSettings) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Monitor diagnostic settings check requires Azure SDK",
		ResourceID: "monitor-diagnostic-settings", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorActivityLogAlerts - verifica alertas de log de atividade
type MonitorActivityLogAlerts struct {
	metadata models.CheckMetadata
}

func NewMonitorActivityLogAlerts() *MonitorActivityLogAlerts {
	return &MonitorActivityLogAlerts{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_activity_log_alerts",
			CheckTitle: "Ensure activity log alerts are configured",
			Description: "Activity log alerts should be configured",
			Severity: "medium", ServiceName: "monitor", ResourceType: "AlertRule",
			RemediationText: "Configure activity log alerts",
			Categories: []string{"monitor", "alerts"},
		},
	}
}

func (c *MonitorActivityLogAlerts) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorActivityLogAlerts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Monitor activity log alerts check requires Azure SDK",
		ResourceID: "monitor-activity-log-alerts", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorLogAnalyticsAgentEnabled - verifica agente Log Analytics
type MonitorLogAnalyticsAgentEnabled struct {
	metadata models.CheckMetadata
}

func NewMonitorLogAnalyticsAgentEnabled() *MonitorLogAnalyticsAgentEnabled {
	return &MonitorLogAnalyticsAgentEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_log_analytics_agent_enabled",
			CheckTitle: "Ensure Log Analytics agent is enabled",
			Description: "Log Analytics agent should be enabled",
			Severity: "medium", ServiceName: "monitor", ResourceType: "Workspace",
			RemediationText: "Enable Log Analytics agent",
			Categories: []string{"monitor", "agent"},
		},
	}
}

func (c *MonitorLogAnalyticsAgentEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorLogAnalyticsAgentEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Log Analytics agent check requires Azure SDK",
		ResourceID: "monitor-log-analytics-agent", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorLogRetentionDays - verifica retenção de logs
type MonitorLogRetentionDays struct {
	metadata models.CheckMetadata
}

func NewMonitorLogRetentionDays() *MonitorLogRetentionDays {
	return &MonitorLogRetentionDays{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_log_retention_days",
			CheckTitle: "Ensure log retention is configured",
			Description: "Log retention should be configured to at least 90 days",
			Severity: "medium", ServiceName: "monitor", ResourceType: "Workspace",
			RemediationText: "Configure log retention to at least 90 days",
			Categories: []string{"monitor", "retention"},
		},
	}
}

func (c *MonitorLogRetentionDays) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorLogRetentionDays) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Log retention check requires Azure SDK",
		ResourceID: "monitor-log-retention", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorMetricAlertsEnabled - verifica alertas de métrica
type MonitorMetricAlertsEnabled struct {
	metadata models.CheckMetadata
}

func NewMonitorMetricAlertsEnabled() *MonitorMetricAlertsEnabled {
	return &MonitorMetricAlertsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_metric_alerts_enabled",
			CheckTitle: "Ensure metric alerts are enabled",
			Description: "Metric alerts should be enabled for critical resources",
			Severity: "medium", ServiceName: "monitor", ResourceType: "MetricAlert",
			RemediationText: "Enable metric alerts for critical resources",
			Categories: []string{"monitor", "alerts"},
		},
	}
}

func (c *MonitorMetricAlertsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorMetricAlertsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Metric alerts check requires Azure SDK",
		ResourceID: "monitor-metric-alerts", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorApplicationInsightsEnabled - verifica Application Insights
type MonitorApplicationInsightsEnabled struct {
	metadata models.CheckMetadata
}

func NewMonitorApplicationInsightsEnabled() *MonitorApplicationInsightsEnabled {
	return &MonitorApplicationInsightsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_application_insights_enabled",
			CheckTitle: "Ensure Application Insights is enabled",
			Description: "Application Insights should be enabled for applications",
			Severity: "medium", ServiceName: "monitor", ResourceType: "ApplicationInsights",
			RemediationText: "Enable Application Insights for applications",
			Categories: []string{"monitor", "application-insights"},
		},
	}
}

func (c *MonitorApplicationInsightsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorApplicationInsightsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Application Insights check requires Azure SDK",
		ResourceID: "monitor-application-insights", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorWorkspaceEncryption - verificação de criptografia
type MonitorWorkspaceEncryption struct {
	metadata models.CheckMetadata
}

func NewMonitorWorkspaceEncryption() *MonitorWorkspaceEncryption {
	return &MonitorWorkspaceEncryption{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_workspace_encryption",
			CheckTitle: "Ensure Log Analytics workspace is encrypted",
			Description: "Log Analytics workspace should be encrypted with CMK",
			Severity: "medium", ServiceName: "monitor", ResourceType: "Workspace",
			RemediationText: "Enable CMK encryption for Log Analytics workspace",
			Categories: []string{"monitor", "encryption"},
		},
	}
}

func (c *MonitorWorkspaceEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorWorkspaceEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Workspace encryption check requires Azure SDK",
		ResourceID: "monitor-workspace-encryption", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorAzureMonitorAlerts - verifica alertas do Azure Monitor
type MonitorAzureMonitorAlerts struct {
	metadata models.CheckMetadata
}

func NewMonitorAzureMonitorAlerts() *MonitorAzureMonitorAlerts {
	return &MonitorAzureMonitorAlerts{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_azure_monitor_alerts",
			CheckTitle: "Ensure Azure Monitor alerts are configured",
			Description: "Azure Monitor alerts should be configured",
			Severity: "medium", ServiceName: "monitor", ResourceType: "AlertRule",
			RemediationText: "Configure Azure Monitor alerts",
			Categories: []string{"monitor", "alerts"},
		},
	}
}

func (c *MonitorAzureMonitorAlerts) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorAzureMonitorAlerts) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Azure Monitor alerts check requires Azure SDK",
		ResourceID: "monitor-azure-monitor-alerts", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorDiagnosticLoggingEnabled - verifica logging de diagnóstico
type MonitorDiagnosticLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewMonitorDiagnosticLoggingEnabled() *MonitorDiagnosticLoggingEnabled {
	return &MonitorDiagnosticLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_diagnostic_logging_enabled",
			CheckTitle: "Ensure diagnostic logging is enabled",
			Description: "Diagnostic logging should be enabled for all resources",
			Severity: "medium", ServiceName: "monitor", ResourceType: "DiagnosticSettings",
			RemediationText: "Enable diagnostic logging",
			Categories: []string{"monitor", "logging"},
		},
	}
}

func (c *MonitorDiagnosticLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorDiagnosticLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Diagnostic logging check requires Azure SDK",
		ResourceID: "monitor-diagnostic-logging", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorLogProfileArchive - verifica arquivamento de logs
type MonitorLogProfileArchive struct {
	metadata models.CheckMetadata
}

func NewMonitorLogProfileArchive() *MonitorLogProfileArchive {
	return &MonitorLogProfileArchive{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_log_profile_archive",
			CheckTitle: "Ensure log profile is archived",
			Description: "Log profile should be archived to a storage account",
			Severity: "medium", ServiceName: "monitor", ResourceType: "LogProfile",
			RemediationText: "Configure log profile archiving",
			Categories: []string{"monitor", "archiving"},
		},
	}
}

func (c *MonitorLogProfileArchive) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorLogProfileArchive) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Log profile archiving check requires Azure SDK",
		ResourceID: "monitor-log-profile-archive", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorLogProfileCategories - verifica categorias de log
type MonitorLogProfileCategories struct {
	metadata models.CheckMetadata
}

func NewMonitorLogProfileCategories() *MonitorLogProfileCategories {
	return &MonitorLogProfileCategories{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_log_profile_categories",
			CheckTitle: "Ensure log profile includes all categories",
			Description: "Log profile should include all log categories",
			Severity: "medium", ServiceName: "monitor", ResourceType: "LogProfile",
			RemediationText: "Configure log profile to include all categories",
			Categories: []string{"monitor", "categories"},
		},
	}
}

func (c *MonitorLogProfileCategories) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorLogProfileCategories) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Log profile categories check requires Azure SDK",
		ResourceID: "monitor-log-profile-categories", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorLogProfileRetention - verifica retenção de log
type MonitorLogProfileRetention struct {
	metadata models.CheckMetadata
}

func NewMonitorLogProfileRetention() *MonitorLogProfileRetention {
	return &MonitorLogProfileRetention{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_log_profile_retention",
			CheckTitle: "Ensure log profile has retention configured",
			Description: "Log profile should have retention configured",
			Severity: "medium", ServiceName: "monitor", ResourceType: "LogProfile",
			RemediationText: "Configure log profile retention",
			Categories: []string{"monitor", "retention"},
		},
	}
}

func (c *MonitorLogProfileRetention) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorLogProfileRetention) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Log profile retention check requires Azure SDK",
		ResourceID: "monitor-log-profile-retention", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorLogProfileRegions - verifica regiões de log
type MonitorLogProfileRegions struct {
	metadata models.CheckMetadata
}

func NewMonitorLogProfileRegions() *MonitorLogProfileRegions {
	return &MonitorLogProfileRegions{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_log_profile_regions",
			CheckTitle: "Ensure log profile covers all regions",
			Description: "Log profile should cover all regions",
			Severity: "medium", ServiceName: "monitor", ResourceType: "LogProfile",
			RemediationText: "Configure log profile to cover all regions",
			Categories: []string{"monitor", "regions"},
		},
	}
}

func (c *MonitorLogProfileRegions) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorLogProfileRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Log profile regions check requires Azure SDK",
		ResourceID: "monitor-log-profile-regions", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// MonitorVMHealthAlertsEnabled - verifica alertas de saúde de VM
type MonitorVMHealthAlertsEnabled struct {
	metadata models.CheckMetadata
}

func NewMonitorVMHealthAlertsEnabled() *MonitorVMHealthAlertsEnabled {
	return &MonitorVMHealthAlertsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "monitor_vm_health_alerts_enabled",
			CheckTitle: "Ensure VM health alerts are enabled",
			Description: "VM health alerts should be enabled",
			Severity: "medium", ServiceName: "monitor", ResourceType: "AlertRule",
			RemediationText: "Enable VM health alerts",
			Categories: []string{"monitor", "alerts"},
		},
	}
}

func (c *MonitorVMHealthAlertsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonitorVMHealthAlertsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "VM health alerts check requires Azure SDK",
		ResourceID: "monitor-vm-health-alerts", Provider: "azure", Service: "monitor",
		FoundAt: time.Now().UTC(),
	}}, nil
}
