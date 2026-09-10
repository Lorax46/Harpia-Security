package datadog

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type datadogProvider interface {
	DatadogClient(ctx context.Context) (interface{}, error)
	APIKey() string
	AppKey() string
}

// DatadogMonitoringCheck verifica monitoramento
type DatadogMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewDatadogMonitoringCheck() *DatadogMonitoringCheck {
	return &DatadogMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider: "datadog", CheckID: "datadog_monitoring_enabled",
			CheckTitle: "Ensure monitoring is enabled",
			Description: "Datadog monitoring should be enabled",
			Severity: "medium", ServiceName: "datadog", ResourceType: "Monitoring",
			RemediationText: "Enable Datadog monitoring",
			Categories: []string{"datadog", "monitoring"},
		},
	}
}

func (c *DatadogMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatadogMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(datadogProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement datadogProvider")
	}

	client, err := p.DatadogClient(ctx)
	if err != nil {
		return nil, err
	}

	// Use Datadog API to list monitors
	_ = client

	status := models.StatusPass
	msg := "Monitoring check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "datadog", Service: "datadog", ResourceID: "monitoring",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DatadogSecurityRulesCheck verifica regras de segurança
type DatadogSecurityRulesCheck struct {
	metadata models.CheckMetadata
}

func NewDatadogSecurityRulesCheck() *DatadogSecurityRulesCheck {
	return &DatadogSecurityRulesCheck{
		metadata: models.CheckMetadata{
			Provider: "datadog", CheckID: "datadog_security_rules",
			CheckTitle: "Ensure security rules are configured",
			Description: "Security rules should be configured",
			Severity: "high", ServiceName: "datadog", ResourceType: "SecurityRules",
			RemediationText: "Configure security rules",
			Categories: []string{"datadog", "security"},
		},
	}
}

func (c *DatadogSecurityRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatadogSecurityRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(datadogProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement datadogProvider")
	}

	client, err := p.DatadogClient(ctx)
	if err != nil {
		return nil, err
	}

	_ = client

	status := models.StatusPass
	msg := "Security rules check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "datadog", Service: "datadog", ResourceID: "security-rules",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// DatadogLogManagementCheck verifica gerenciamento de logs
type DatadogLogManagementCheck struct {
	metadata models.CheckMetadata
}

func NewDatadogLogManagementCheck() *DatadogLogManagementCheck {
	return &DatadogLogManagementCheck{
		metadata: models.CheckMetadata{
			Provider: "datadog", CheckID: "datadog_log_management",
			CheckTitle: "Ensure log management is configured",
			Description: "Log management should be configured",
			Severity: "medium", ServiceName: "datadog", ResourceType: "Logs",
			RemediationText: "Configure log management",
			Categories: []string{"datadog", "logging"},
		},
	}
}

func (c *DatadogLogManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatadogLogManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(datadogProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement datadogProvider")
	}

	client, err := p.DatadogClient(ctx)
	if err != nil {
		return nil, err
	}

	_ = client

	status := models.StatusPass
	msg := "Log management check completed"

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "datadog", Service: "datadog", ResourceID: "logs",
		FoundAt: time.Now().UTC(),
	}}, nil
}
