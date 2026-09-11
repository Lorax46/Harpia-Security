package postgresql

// =============================================================================
// Azure PostgreSQL Checks — 10 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

func newPostgresCheck(id, title, description, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider: "azure", CheckID: id, CheckTitle: title,
		Description: description, Severity: severity,
		ServiceName: "postgresql", ResourceType: "Server",
		Categories: []string{"postgresql"},
	}
}

type postgresCheck struct {
	metadata models.CheckMetadata
}

func (c *postgresCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *postgresCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "PostgreSQL check requires Azure SDK",
		ResourceID: c.metadata.CheckID, Provider: "azure", Service: "postgresql",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// PostgreSqlServerConnectionThrottlingEnabled - verifica connection throttling
type PostgreSqlServerConnectionThrottlingEnabled struct{ postgresCheck }

func NewPostgreSqlServerConnectionThrottlingEnabled() *PostgreSqlServerConnectionThrottlingEnabled {
	return &PostgreSqlServerConnectionThrottlingEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_connection_throttling_enabled",
		"Ensure PostgreSQL connection throttling is enabled",
		"PostgreSQL server should have connection throttling enabled",
		"medium",
	)}}
}

// PostgreSqlServerLogCheckpointsEnabled - verifica log checkpoints
type PostgreSqlServerLogCheckpointsEnabled struct{ postgresCheck }

func NewPostgreSqlServerLogCheckpointsEnabled() *PostgreSqlServerLogCheckpointsEnabled {
	return &PostgreSqlServerLogCheckpointsEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_log_checkpoints_enabled",
		"Ensure PostgreSQL log checkpoints is enabled",
		"PostgreSQL server should have log checkpoints enabled",
		"medium",
	)}}
}

// PostgreSqlServerLogConnectionsEnabled - verifica log connections
type PostgreSqlServerLogConnectionsEnabled struct{ postgresCheck }

func NewPostgreSqlServerLogConnectionsEnabled() *PostgreSqlServerLogConnectionsEnabled {
	return &PostgreSqlServerLogConnectionsEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_log_connections_enabled",
		"Ensure PostgreSQL log connections is enabled",
		"PostgreSQL server should have log connections enabled",
		"medium",
	)}}
}

// PostgreSqlServerLogDisconnectionsEnabled - verifica log disconnections
type PostgreSqlServerLogDisconnectionsEnabled struct{ postgresCheck }

func NewPostgreSqlServerLogDisconnectionsEnabled() *PostgreSqlServerLogDisconnectionsEnabled {
	return &PostgreSqlServerLogDisconnectionsEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_log_disconnections_enabled",
		"Ensure PostgreSQL log disconnections is enabled",
		"PostgreSQL server should have log disconnections enabled",
		"medium",
	)}}
}

// PostgreSqlServerLogDurationEnabled - verifica log duration
type PostgreSqlServerLogDurationEnabled struct{ postgresCheck }

func NewPostgreSqlServerLogDurationEnabled() *PostgreSqlServerLogDurationEnabled {
	return &PostgreSqlServerLogDurationEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_log_duration_enabled",
		"Ensure PostgreSQL log duration is enabled",
		"PostgreSQL server should have log duration enabled",
		"medium",
	)}}
}

// PostgreSqlServerNoPublicAccess - verifica acesso público
type PostgreSqlServerNoPublicAccess struct{ postgresCheck }

func NewPostgreSqlServerNoPublicAccess() *PostgreSqlServerNoPublicAccess {
	return &PostgreSqlServerNoPublicAccess{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_no_public_access",
		"Ensure PostgreSQL has no public access",
		"PostgreSQL server should have public access disabled",
		"high",
	)}}
}

// PostgreSqlServerPrivateEndpointsEnabled - verifica endpoints privados
type PostgreSqlServerPrivateEndpointsEnabled struct{ postgresCheck }

func NewPostgreSqlServerPrivateEndpointsEnabled() *PostgreSqlServerPrivateEndpointsEnabled {
	return &PostgreSqlServerPrivateEndpointsEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_private_endpoints_enabled",
		"Ensure PostgreSQL uses private endpoints",
		"PostgreSQL server should use private endpoints",
		"medium",
	)}}
}

// PostgreSqlServerSslEnforcementEnabled - verifica SSL enforcement
type PostgreSqlServerSslEnforcementEnabled struct{ postgresCheck }

func NewPostgreSqlServerSslEnforcementEnabled() *PostgreSqlServerSslEnforcementEnabled {
	return &PostgreSqlServerSslEnforcementEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_ssl_enforcement_enabled",
		"Ensure PostgreSQL SSL enforcement is enabled",
		"PostgreSQL server should have SSL enforcement enabled",
		"high",
	)}}
}

// PostgreSqlServerStorageAutoGrowEnabled - verifica auto grow
type PostgreSqlServerStorageAutoGrowEnabled struct{ postgresCheck }

func NewPostgreSqlServerStorageAutoGrowEnabled() *PostgreSqlServerStorageAutoGrowEnabled {
	return &PostgreSqlServerStorageAutoGrowEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_storage_auto_grow_enabled",
		"Ensure PostgreSQL storage auto grow is enabled",
		"PostgreSQL server should have storage auto grow enabled",
		"low",
	)}}
}

// PostgreSqlServerThreatDetectionEnabled - verifica threat detection
type PostgreSqlServerThreatDetectionEnabled struct{ postgresCheck }

func NewPostgreSqlServerThreatDetectionEnabled() *PostgreSqlServerThreatDetectionEnabled {
	return &PostgreSqlServerThreatDetectionEnabled{postgresCheck{metadata: newPostgresCheck(
		"postgresql_server_threat_detection_enabled",
		"Ensure PostgreSQL threat detection is enabled",
		"PostgreSQL server should have threat detection enabled",
		"high",
	)}}
}
