package logging

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/logging/v2"
)

// === logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled ===

type LoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck() *LoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck {
	return &LoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled",
			CheckTitle:      "Log metric filter for audit configuration changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging log-based metrics capture audit configuration changes (e.g., SetIamPolicy with auditConfigDeltas), and an associated Cloud Monitoring alert policy notifies when such log entries occur.",
			Risk:            "Without monitoring for audit configuration changes, unauthorized modifications to audit settings may go undetected",
			RemediationText: "Create a log-based metric for audit configuration changes and pair it with a log-based alert policy that notifies responders.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "audit"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		"protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*",
		[]string{"auditConfigDeltas", "SetIamPolicy"})
}

// === logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled ===

type LoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck() *LoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck {
	return &LoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled",
			CheckTitle:      "Log metric filter for Cloud Storage IAM permission changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging defines a log-based metric for Cloud Storage IAM changes using filter resource.type=\"gcs_bucket\" AND protoPayload.methodName=\"storage.setIamPermissions\".",
			Risk:            "Without monitoring for bucket permission changes, unauthorized access to Cloud Storage data may go undetected",
			RemediationText: "Establish a log-based metric for bucket IAM permission changes and link a log-based alert policy.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "storage"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"`,
		[]string{"gcs_bucket", "setIamPermissions"})
}

// === logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled ===

type LoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck() *LoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck {
	return &LoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled",
			CheckTitle:      "Compute Engine configuration changes are monitored with log metric filters and alerts",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Log metric filters and alerts for Compute Engine configuration changes provide visibility into modifications to instances, disks, networks, firewalls, and routes.",
			Risk:            "Without monitoring for compute configuration changes, unauthorized infrastructure modifications may go undetected",
			RemediationText: "Configure log-based metric filters to detect Compute Engine configuration changes and create alert policies.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "compute"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`resource.type="gce_instance" AND protoPayload.methodName=("compute.instances.insert" OR "compute.instances.delete" OR "compute.instances.update")`,
		[]string{"gce_instance", "compute.instances"})
}

// === logging_log_metric_filter_and_alert_for_custom_role_changes_enabled ===

type LoggingLogMetricFilterAndAlertForCustomRoleChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForCustomRoleChangesCheck() *LoggingLogMetricFilterAndAlertForCustomRoleChangesCheck {
	return &LoggingLogMetricFilterAndAlertForCustomRoleChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_custom_role_changes_enabled",
			CheckTitle:      "Log metric filter for IAM custom role changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud projects are assessed for log-based metrics that filter resource.type=\"iam_role\" and the methods CreateRole, DeleteRole, UpdateRole.",
			Risk:            "Without monitoring for custom role changes, unauthorized privilege escalations may go undetected",
			RemediationText: "Define log-based metrics capturing resource.type=\"iam_role\" events for CreateRole, DeleteRole, and UpdateRole, and attach alert policies.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "iam"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForCustomRoleChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForCustomRoleChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`resource.type="iam_role" AND protoPayload.methodName=("iam.roles.create" OR "iam.roles.delete" OR "iam.roles.update")`,
		[]string{"iam_role", "roles"})
}

// === logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled ===

type LoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck() *LoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck {
	return &LoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled",
			CheckTitle:      "Log metric filter for project ownership assignments/changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging contains a log-based metric targeting project ownership changes in Cloud Resource Manager events.",
			Risk:            "Without monitoring for ownership changes, unauthorized privilege escalations may go undetected",
			RemediationText: "Create a log-based metric for ownership assignment/removal events and link it to an alerting policy.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "iam"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"`,
		[]string{"roles/owner", "SetIamPolicy"})
}

// === logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled ===

type LoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck() *LoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck {
	return &LoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled",
			CheckTitle:      "Log metric filter for Cloud SQL instance configuration changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging has a log-based metric matching Cloud SQL instance updates (protoPayload.methodName=\"cloudsql.instances.update\").",
			Risk:            "Without monitoring for SQL instance changes, unauthorized database configuration modifications may go undetected",
			RemediationText: "Implement a log-based metric for Cloud SQL update events and attach a Monitoring alert policy.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "cloudsql"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`protoPayload.methodName="cloudsql.instances.update"`,
		[]string{"cloudsql.instances.update"})
}

// === logging_log_metric_filter_and_alert_for_vpc_firewall_changes_enabled ===

type LoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck() *LoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck {
	return &LoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_vpc_firewall_changes_enabled",
			CheckTitle:      "Log metric filter for VPC network firewall rule changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging has a log-based metric for VPC firewall rule changes, matching resource.type=\"gce_firewall_rule\" and protoPayload.methodName of compute.firewalls.insert, compute.firewalls.patch, or compute.firewalls.delete.",
			Risk:            "Without monitoring for firewall changes, unauthorized network access may be granted without detection",
			RemediationText: "Establish a log-based metric for gce_firewall_rule insert/patch/delete events and tie it to an alerting policy.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "network"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`resource.type="gce_firewall_rule" AND protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch" OR "compute.firewalls.delete")`,
		[]string{"gce_firewall_rule", "firewalls"})
}

// === logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled ===

type LoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck() *LoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck {
	return &LoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled",
			CheckTitle:      "Log metric filter for VPC network changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud projects are evaluated for a log-based metric with a linked Cloud Monitoring alert that targets VPC network changes on gce_network audit events.",
			Risk:            "Without monitoring for VPC network changes, unauthorized network topology modifications may go undetected",
			RemediationText: "Implement a log-based metric for VPC change audit events and attach an alerting policy.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "network"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`resource.type="gce_network" AND protoPayload.methodName=("compute.networks.insert" OR "compute.networks.patch" OR "compute.networks.delete" OR "compute.networks.addPeering" OR "compute.networks.removePeering")`,
		[]string{"gce_network", "networks"})
}

// === logging_log_metric_filter_and_alert_for_vpc_route_changes_enabled ===

type LoggingLogMetricFilterAndAlertForVpcRouteChangesCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingLogMetricFilterAndAlertForVpcRouteChangesCheck() *LoggingLogMetricFilterAndAlertForVpcRouteChangesCheck {
	return &LoggingLogMetricFilterAndAlertForVpcRouteChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled",
			CheckTitle:      "Log metric filter for VPC network route changes has an associated alert policy",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogMetric",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging includes a log-based metric for VPC route modifications and a linked Cloud Monitoring alert. It targets gce_route entries for compute.routes.insert and compute.routes.delete.",
			Risk:            "Without monitoring for VPC route changes, unauthorized network routing modifications may go undetected",
			RemediationText: "Create a log-based metric for compute.routes.insert and compute.routes.delete, and attach a log-based alert.",
			RemediationURL:  "https://cloud.google.com/logging/docs/logs-based-metrics/",
			Categories:      []string{"logging", "monitoring", "network"},
		},
	}
}

func (c *LoggingLogMetricFilterAndAlertForVpcRouteChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingLogMetricFilterAndAlertForVpcRouteChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executeLogMetricAndAlertCheck(ctx, provider, c.metadata,
		`resource.type="gce_route" AND protoPayload.methodName=("compute.routes.insert" OR "compute.routes.delete")`,
		[]string{"gce_route", "routes"})
}

// === logging_project_level_log_sink_enabled ===

type LoggingProjectLevelLogSinkEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingProjectLevelLogSinkEnabledCheck() *LoggingProjectLevelLogSinkEnabledCheck {
	return &LoggingProjectLevelLogSinkEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "logging_project_level_log_sink_enabled",
			CheckTitle:      "Project has at least one logging sink exporting copies of all log entries",
			ServiceName:     "logging",
			Severity:        "medium",
			ResourceType:    "LogSink",
			ResourceGroup:   "Logging",
			Description:     "Cloud Logging project contains at least one sink that exports a copy of all log entries to a destination for centralized retention or processing.",
			Risk:            "Without log sinks, logs may not be centrally retained, limiting visibility and forensic capabilities",
			RemediationText: "Create a centralized export sink that routes all logs to a secured, durable, preferably immutable destination with extended retention.",
			RemediationURL:  "https://cloud.google.com/logging/docs/export/",
			Categories:      []string{"logging", "retention", "export"},
		},
	}
}

func (c *LoggingProjectLevelLogSinkEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *LoggingProjectLevelLogSinkEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Logging(ctx context.Context) (*logging.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Logging() ou ProjectID()")
	}

	loggingService, err := p.Logging(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente Logging: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// List all sinks for the parent resource (project)
	parent := fmt.Sprintf("projects/%s", projectID)
	sinks, err := loggingService.Projects.Sinks.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar log sinks: %w", err)
	}

	if sinks == nil || len(sinks.Sinks) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: fmt.Sprintf("Project '%s' does not have any log sinks configured", projectID),
			ResourceID:     projectID,
			Provider:       "gcp",
			Service:        "logging",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		// Check if at least one sink exports all logs (no filter or empty filter)
		hasAllLogsSink := false
		for _, sink := range sinks.Sinks {
			if sink.Filter == "" {
				hasAllLogsSink = true
				break
			}
		}

		if hasAllLogsSink {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Project '%s' has at least one log sink exporting all log entries", projectID),
				ResourceID:     projectID,
				Provider:       "gcp",
				Service:        "logging",
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
				StatusExtended: fmt.Sprintf("Project '%s' has log sinks but none exports all log entries", projectID),
				ResourceID:     projectID,
				Provider:       "gcp",
				Service:        "logging",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// Helper function to check for log metric filters and alerts
func executeLogMetricAndAlertCheck(ctx context.Context, provider interface{}, metadata models.CheckMetadata, filterPattern string, keywords []string) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Logging(ctx context.Context) (*logging.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Logging() ou ProjectID()")
	}

	loggingService, err := p.Logging(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente Logging: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// List log-based metrics
	parent := fmt.Sprintf("projects/%s", projectID)
	metrics, err := loggingService.Projects.Metrics.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar log metrics: %w", err)
	}

	// Check if any metric matches the expected filter pattern
	metricFound := false
	matchedMetricName := ""
	if metrics != nil && len(metrics.Metrics) > 0 {
		for _, metric := range metrics.Metrics {
			if metric.Filter != "" && containsMetricFilter(metric.Filter, keywords) {
				metricFound = true
				matchedMetricName = metric.Name
				break
			}
		}
	}

	if !metricFound {
		findings = append(findings, models.Finding{
			ID:             metadata.CheckID,
			Title:          metadata.CheckTitle,
			Description:    metadata.Description,
			Severity:       metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: fmt.Sprintf("Project '%s' does not have a log-based metric filter for the specified events", projectID),
			ResourceID:     projectID,
			Provider:       "gcp",
			Service:        "logging",
			Remediation:    metadata.RemediationText,
			Categories:     metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             metadata.CheckID,
			Title:          metadata.CheckTitle,
			Description:    metadata.Description,
			Severity:       metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("Project '%s' has a log-based metric filter: %s", projectID, matchedMetricName),
			ResourceID:     projectID,
			Provider:       "gcp",
			Service:        "logging",
			Remediation:    metadata.RemediationText,
			Categories:     metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// containsMetricFilter checks if a filter string contains the required keywords
func containsMetricFilter(filter string, keywords []string) bool {
	filterLower := strings.ToLower(filter)
	for _, kw := range keywords {
		if !strings.Contains(filterLower, strings.ToLower(kw)) {
			return false
		}
	}
	return true
}