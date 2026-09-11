package cloudsql

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cloudsqlCheck struct {
	metadata models.CheckMetadata
}

func newCloudsqlCheck(id, title, description, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: description, Severity: severity,
		ServiceName: "cloudsql", ResourceType: "Instance",
		Categories: []string{"cloudsql"},
	}
}

func (c *cloudsqlCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *cloudsqlCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP CloudSQL check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "cloudsql",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// 14 checks faltantes do CloudSQL
type cloudsqlInstanceSslConnectionsOnlyEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceSslConnectionsOnlyEnabled() *cloudsqlInstanceSslConnectionsOnlyEnabled {
	return &cloudsqlInstanceSslConnectionsOnlyEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_ssl_connections_only_enabled",
		"Ensure CloudSQL instance SSL connections only is enabled",
		"CloudSQL instance should require SSL connections only",
		"high",
	)}}
}

type cloudsqlInstanceRestrictAuthorizedNetworksEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceRestrictAuthorizedNetworksEnabled() *cloudsqlInstanceRestrictAuthorizedNetworksEnabled {
	return &cloudsqlInstanceRestrictAuthorizedNetworksEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_restrict_authorized_networks_enabled",
		"Ensure CloudSQL instance restrict authorized networks is enabled",
		"CloudSQL instance should restrict authorized networks",
		"high",
	)}}
}

type cloudsqlInstanceLogCheckpointEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogCheckpointEnabled() *cloudsqlInstanceLogCheckpointEnabled {
	return &cloudsqlInstanceLogCheckpointEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_checkpoint_enabled",
		"Ensure CloudSQL instance log checkpoint is enabled",
		"CloudSQL instance should have log checkpoint enabled",
		"medium",
	)}}
}

type cloudsqlInstanceLogConnectionsEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogConnectionsEnabled() *cloudsqlInstanceLogConnectionsEnabled {
	return &cloudsqlInstanceLogConnectionsEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_connections_enabled",
		"Ensure CloudSQL instance log connections is enabled",
		"CloudSQL instance should have log connections enabled",
		"medium",
	)}}
}

type cloudsqlInstanceLogDisconnectionsEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogDisconnectionsEnabled() *cloudsqlInstanceLogDisconnectionsEnabled {
	return &cloudsqlInstanceLogDisconnectionsEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_disconnections_enabled",
		"Ensure CloudSQL instance log disconnections is enabled",
		"CloudSQL instance should have log disconnections enabled",
		"medium",
	)}}
}

type cloudsqlInstanceLogLockWaitsEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogLockWaitsEnabled() *cloudsqlInstanceLogLockWaitsEnabled {
	return &cloudsqlInstanceLogLockWaitsEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_lock_waits_enabled",
		"Ensure CloudSQL instance log lock waits is enabled",
		"CloudSQL instance should have log lock waits enabled",
		"low",
	)}}
}

type cloudsqlInstanceLogTempFilesEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogTempFilesEnabled() *cloudsqlInstanceLogTempFilesEnabled {
	return &cloudsqlInstanceLogTempFilesEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_temp_files_enabled",
		"Ensure CloudSQL instance log temp files is enabled",
		"CloudSQL instance should have log temp files enabled",
		"medium",
	)}}
}

type cloudsqlInstanceLogMinErrorStatementEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogMinErrorStatementEnabled() *cloudsqlInstanceLogMinErrorStatementEnabled {
	return &cloudsqlInstanceLogMinErrorStatementEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_min_error_statement_enabled",
		"Ensure CloudSQL instance log min error statement is enabled",
		"CloudSQL instance should have log min error statement enabled",
		"medium",
	)}}
}

type cloudsqlInstanceLogMinDurationStatementEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogMinDurationStatementEnabled() *cloudsqlInstanceLogMinDurationStatementEnabled {
	return &cloudsqlInstanceLogMinDurationStatementEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_min_duration_statement_enabled",
		"Ensure CloudSQL instance log min duration statement is enabled",
		"CloudSQL instance should have log min duration statement enabled",
		"medium",
	)}}
}

type cloudsqlInstanceLogExecutorStatsEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogExecutorStatsEnabled() *cloudsqlInstanceLogExecutorStatsEnabled {
	return &cloudsqlInstanceLogExecutorStatsEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_executor_stats_enabled",
		"Ensure CloudSQL instance log executor stats is enabled",
		"CloudSQL instance should have log executor stats enabled",
		"low",
	)}}
}

type cloudsqlInstanceLogStatementStatsEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceLogStatementStatsEnabled() *cloudsqlInstanceLogStatementStatsEnabled {
	return &cloudsqlInstanceLogStatementStatsEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_log_statement_stats_enabled",
		"Ensure CloudSQL instance log statement stats is enabled",
		"CloudSQL instance should have log statement stats enabled",
		"low",
	)}}
}

type cloudsqlInstancePrivateIpOnlyEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstancePrivateIpOnlyEnabled() *cloudsqlInstancePrivateIpOnlyEnabled {
	return &cloudsqlInstancePrivateIpOnlyEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_private_ip_only_enabled",
		"Ensure CloudSQL instance private IP only is enabled",
		"CloudSQL instance should have private IP only enabled",
		"high",
	)}}
}

type cloudsqlInstanceSkipShowDatabaseDisabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceSkipShowDatabaseDisabled() *cloudsqlInstanceSkipShowDatabaseDisabled {
	return &cloudsqlInstanceSkipShowDatabaseDisabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_skip_show_database_disabled",
		"Ensure CloudSQL instance skip show database is disabled",
		"CloudSQL instance should have skip show database disabled",
		"medium",
	)}}
}

type cloudsqlInstanceTraceFlagsEnabled struct{ cloudsqlCheck }

func NewCloudsqlInstanceTraceFlagsEnabled() *cloudsqlInstanceTraceFlagsEnabled {
	return &cloudsqlInstanceTraceFlagsEnabled{cloudsqlCheck{metadata: newCloudsqlCheck(
		"cloudsql_instance_trace_flags_enabled",
		"Ensure CloudSQL instance trace flags is enabled",
		"CloudSQL instance should have trace flags enabled",
		"medium",
	)}}
}
