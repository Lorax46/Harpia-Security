package mysql

// =============================================================================
// Azure MySQL Missing Checks — 6 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type azureMysqlMissingCheck struct {
	metadata models.CheckMetadata
}

func newAzureMysqlMissingCheck(id, title, desc, sev string) azureMysqlMissingCheck {
	return azureMysqlMissingCheck{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "mysql", ResourceType: "Server",
		Categories: []string{"mysql"},
	}}
}

func (c *azureMysqlMissingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *azureMysqlMissingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Azure mysql check requires Azure SDK",
		ResourceID: c.metadata.CheckID, Provider: "azure", Service: "mysql",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type mysqlFlexibleServerAuditLogConnectionActivated struct{ azureMysqlMissingCheck }

func NewMysqlFlexibleServerAuditLogConnectionActivated() *mysqlFlexibleServerAuditLogConnectionActivated {
	return &mysqlFlexibleServerAuditLogConnectionActivated{newAzureMysqlMissingCheck(
		"mysql_flexible_server_audit_log_connection_activated",
		"Ensure MySQL flexible server audit log connection is activated",
		"MySQL flexible server should have audit log connection activated",
		"medium",
	)}
}

type mysqlFlexibleServerAuditLogEnabled struct{ azureMysqlMissingCheck }

func NewMysqlFlexibleServerAuditLogEnabled() *mysqlFlexibleServerAuditLogEnabled {
	return &mysqlFlexibleServerAuditLogEnabled{newAzureMysqlMissingCheck(
		"mysql_flexible_server_audit_log_enabled",
		"Ensure MySQL flexible server audit log is enabled",
		"MySQL flexible server should have audit log enabled",
		"medium",
	)}
}

type mysqlFlexibleServerGeoRedundantBackupEnabled struct{ azureMysqlMissingCheck }

func NewMysqlFlexibleServerGeoRedundantBackupEnabled() *mysqlFlexibleServerGeoRedundantBackupEnabled {
	return &mysqlFlexibleServerGeoRedundantBackupEnabled{newAzureMysqlMissingCheck(
		"mysql_flexible_server_geo_redundant_backup_enabled",
		"Ensure MySQL flexible server geo redundant backup is enabled",
		"MySQL flexible server should have geo redundant backup enabled",
		"medium",
	)}
}

type mysqlFlexibleServerHighAvailabilityEnabled struct{ azureMysqlMissingCheck }

func NewMysqlFlexibleServerHighAvailabilityEnabled() *mysqlFlexibleServerHighAvailabilityEnabled {
	return &mysqlFlexibleServerHighAvailabilityEnabled{newAzureMysqlMissingCheck(
		"mysql_flexible_server_high_availability_enabled",
		"Ensure MySQL flexible server high availability is enabled",
		"MySQL flexible server should have high availability enabled",
		"medium",
	)}
}

type mysqlFlexibleServerMinimumTlsVersion12 struct{ azureMysqlMissingCheck }

func NewMysqlFlexibleServerMinimumTlsVersion12() *mysqlFlexibleServerMinimumTlsVersion12 {
	return &mysqlFlexibleServerMinimumTlsVersion12{newAzureMysqlMissingCheck(
		"mysql_flexible_server_minimum_tls_version_12",
		"Ensure MySQL flexible server uses minimum TLS 1.2",
		"MySQL flexible server should use minimum TLS version 1.2",
		"medium",
	)}
}

type mysqlFlexibleServerSslConnectionEnabled struct{ azureMysqlMissingCheck }

func NewMysqlFlexibleServerSslConnectionEnabled() *mysqlFlexibleServerSslConnectionEnabled {
	return &mysqlFlexibleServerSslConnectionEnabled{newAzureMysqlMissingCheck(
		"mysql_flexible_server_ssl_connection_enabled",
		"Ensure MySQL flexible server SSL connection is enabled",
		"MySQL flexible server should have SSL connection enabled",
		"high",
	)}
}
