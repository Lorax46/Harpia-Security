package cloudsql

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"google.golang.org/api/sqladmin/v1"
)

// === cloudsql_instance_postgres_check_password_flag ===

type CloudSQLInstancePostgresCheckPasswordFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresCheckPasswordFlagCheck() *CloudSQLInstancePostgresCheckPasswordFlagCheck {
	return &CloudSQLInstancePostgresCheckPasswordFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_check_password_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has check_password flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "high",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the check_password flag being set to on.",
			Risk:            "Without check_password enabled, weak passwords may be set without validation against the password policy",
			RemediationText: "Enable check_password flag on all Cloud SQL PostgreSQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#cloudsql_check_password",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "authentication"},
		},
	}
}

func (c *CloudSQLInstancePostgresCheckPasswordFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresCheckPasswordFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "cloudsql.check_password", "on", "1")
}

// === cloudsql_instance_postgres_connections_limit_flag ===

type CloudSQLInstancePostgresConnectionsLimitFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresConnectionsLimitFlagCheck() *CloudSQLInstancePostgresConnectionsLimitFlagCheck {
	return &CloudSQLInstancePostgresConnectionsLimitFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_connections_limit_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has connections_limit flag configured",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the connections_limit flag being configured.",
			Risk:            "Unlimited connections may lead to resource exhaustion and denial of service",
			RemediationText: "Set connections_limit flag appropriately on all Cloud SQL PostgreSQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#connections_limit",
			Categories:      []string{"cloudsql", "database-flags", "postgres"},
		},
	}
}

func (c *CloudSQLInstancePostgresConnectionsLimitFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresConnectionsLimitFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagConfiguredCheck(ctx, provider, c.metadata, "cloudsql.connections_limit")
}

// === cloudsql_instance_postgres_db_role_flag ===

type CloudSQLInstancePostgresDbRoleFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresDbRoleFlagCheck() *CloudSQLInstancePostgresDbRoleFlagCheck {
	return &CloudSQLInstancePostgresDbRoleFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_db_role_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has db_role flag configured",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the db_role flag being configured to separate database and role management.",
			Risk:            "Without db_role separation, role management can be performed by any user with CREATEROLE privilege, increasing risk of privilege escalation",
			RemediationText: "Enable db_role flag on all Cloud SQL PostgreSQL instances to enforce separation of duties.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#cloudsql_db_role",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "rbac"},
		},
	}
}

func (c *CloudSQLInstancePostgresDbRoleFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresDbRoleFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "cloudsql.enable_db_role", "on", "1")
}

// === cloudsql_instance_postgres_encrypted_connections_flag ===

type CloudSQLInstancePostgresEncryptedConnectionsFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresEncryptedConnectionsFlagCheck() *CloudSQLInstancePostgresEncryptedConnectionsFlagCheck {
	return &CloudSQLInstancePostgresEncryptedConnectionsFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_encrypted_connections_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has encrypted_connections flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "high",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the encrypted_connections flag being set to on.",
			Risk:            "Without encrypted connections, database traffic could be intercepted, exposing credentials and sensitive data",
			RemediationText: "Enable encrypted_connections flag to require TLS for all connections.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#cloudsql_encrypted_connections",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "encryption"},
		},
	}
}

func (c *CloudSQLInstancePostgresEncryptedConnectionsFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresEncryptedConnectionsFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "cloudsql.encrypted_connections", "on", "1")
}

// === cloudsql_instance_postgres_log_checkpoints_flag ===

type CloudSQLInstancePostgresLogCheckpointsFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogCheckpointsFlagCheck() *CloudSQLInstancePostgresLogCheckpointsFlagCheck {
	return &CloudSQLInstancePostgresLogCheckpointsFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_checkpoints_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has log_checkpoints flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the log_checkpoints flag being set to on.",
			Risk:            "Without log_checkpoints enabled, checkpoint activity is not logged, reducing visibility into database performance and recovery operations",
			RemediationText: "Enable log_checkpoints flag on all Cloud SQL PostgreSQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_checkpoints",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogCheckpointsFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogCheckpointsFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_checkpoints", "on", "1")
}

// === cloudsql_instance_postgres_log_connections_flag ===

type CloudSQLInstancePostgresLogConnectionsFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogConnectionsFlagCheck() *CloudSQLInstancePostgresLogConnectionsFlagCheck {
	return &CloudSQLInstancePostgresLogConnectionsFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_connections_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has log_connections flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances have the log_connections flag set to on, causing the server to record every connection attempt.",
			Risk:            "Without logging connections, unauthorized access attempts may go undetected",
			RemediationText: "Enable log_connections=on for all PostgreSQL instances. Apply defense in depth: also capture disconnects and audit events.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_connections",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogConnectionsFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogConnectionsFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_connections", "on", "1")
}

// === cloudsql_instance_postgres_log_disconnections_flag ===

type CloudSQLInstancePostgresLogDisconnectionsFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogDisconnectionsFlagCheck() *CloudSQLInstancePostgresLogDisconnectionsFlagCheck {
	return &CloudSQLInstancePostgresLogDisconnectionsFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_disconnections_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has log_disconnections flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances have the log_disconnections flag set to on, creating a record each time a client session ends.",
			Risk:            "Without logging disconnections, session activity is incomplete and auditing gaps may hide unauthorized access patterns",
			RemediationText: "Enable log_disconnections=on to ensure complete session auditing. Pair with log_connections and a consistent log_line_prefix.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_disconnections",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogDisconnectionsFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogDisconnectionsFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_disconnections", "on", "1")
}

// === cloudsql_instance_postgres_log_duration_flag ===

type CloudSQLInstancePostgresLogDurationFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogDurationFlagCheck() *CloudSQLInstancePostgresLogDurationFlagCheck {
	return &CloudSQLInstancePostgresLogDurationFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_duration_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has log_duration flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the log_duration flag being set to on.",
			Risk:            "Without log_duration, slow queries may go undetected, impacting performance and security monitoring",
			RemediationText: "Enable log_duration flag on all Cloud SQL PostgreSQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_duration",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogDurationFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogDurationFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_duration", "on", "1")
}

// === cloudsql_instance_postgres_log_lock_waits_flag ===

type CloudSQLInstancePostgresLogLockWaitsFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogLockWaitsFlagCheck() *CloudSQLInstancePostgresLogLockWaitsFlagCheck {
	return &CloudSQLInstancePostgresLogLockWaitsFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_lock_waits_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has log_lock_waits flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the log_lock_waits flag being set to on.",
			Risk:            "Without log_lock_waits, database lock contention issues may go undetected, impacting performance and availability",
			RemediationText: "Enable log_lock_waits flag on all Cloud SQL PostgreSQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_lock_waits",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogLockWaitsFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogLockWaitsFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_lock_waits", "on", "1")
}

// === cloudsql_instance_postgres_log_min_duration_statement_flag ===

type CloudSQLInstancePostgresLogMinDurationStatementFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogMinDurationStatementFlagCheck() *CloudSQLInstancePostgresLogMinDurationStatementFlagCheck {
	return &CloudSQLInstancePostgresLogMinDurationStatementFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_min_duration_statement_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has the log_min_duration_statement flag set to -1",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL evaluates whether log_min_duration_statement is set to -1, disabling statement duration logging.",
			Risk:            "Without proper configuration, sensitive query text may be written to logs, exposing data to unauthorized personnel",
			RemediationText: "Keep log_min_duration_statement at -1 in production to avoid writing sensitive query text to logs.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_min_duration_statement",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogMinDurationStatementFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogMinDurationStatementFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_min_duration_statement", "-1", "")
}

// === cloudsql_instance_postgres_log_min_error_statement_flag ===

type CloudSQLInstancePostgresLogMinErrorStatementFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogMinErrorStatementFlagCheck() *CloudSQLInstancePostgresLogMinErrorStatementFlagCheck {
	return &CloudSQLInstancePostgresLogMinErrorStatementFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_min_error_statement_flag",
			CheckTitle:      "Cloud SQL for PostgreSQL instance has log_min_error_statement set to error",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL uses the log_min_error_statement flag and expects it set to error.",
			Risk:            "Without proper log_min_error_statement configuration, error severity may not be properly captured in logs",
			RemediationText: "Set log_min_error_statement to error to balance insight and exposure.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_min_error_statement",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogMinErrorStatementFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogMinErrorStatementFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagCheck(ctx, provider, c.metadata, "log_min_error_statement", "error", "")
}

// === cloudsql_instance_postgres_log_min_messages_flag ===

type CloudSQLInstancePostgresLogMinMessagesFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresLogMinMessagesFlagCheck() *CloudSQLInstancePostgresLogMinMessagesFlagCheck {
	return &CloudSQLInstancePostgresLogMinMessagesFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_log_min_messages_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has the log_min_messages flag set to WARNING or higher",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the log_min_messages flag being set to a sufficiently high severity.",
			Risk:            "Low log_min_messages values may expose sensitive information in logs or generate excessive noise",
			RemediationText: "Set log_min_messages to ERROR or stricter to ensure error statements are captured with context.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#log_min_messages",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "logging"},
		},
	}
}

func (c *CloudSQLInstancePostgresLogMinMessagesFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresLogMinMessagesFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// Valid values in ascending order of severity: DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, PANIC
	validValues := map[string]int{
		"DEBUG5": 0, "DEBUG4": 1, "DEBUG3": 2, "DEBUG2": 3, "DEBUG1": 4,
		"INFO": 5, "NOTICE": 6, "WARNING": 7, "ERROR": 8, "LOG": 9, "FATAL": 10, "PANIC": 11,
	}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			if !isPostgresInstance(instance) {
				continue
			}
			value := getDatabaseFlagValue(instance.Settings.DatabaseFlags, "log_min_messages")
			level, exists := validValues[value]
			if !exists || level < validValues["WARNING"] {
				statusExtended := fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has log_min_messages flag not set to WARNING or higher (value: %s)", instance.Name, value)
				if value == "" {
					statusExtended = fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has log_min_messages flag not configured", instance.Name)
				}
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: statusExtended,
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has log_min_messages flag set to WARNING or higher (value: %s)", instance.Name, value),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_postgres_statement_timeout_flag ===

type CloudSQLInstancePostgresStatementTimeoutFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePostgresStatementTimeoutFlagCheck() *CloudSQLInstancePostgresStatementTimeoutFlagCheck {
	return &CloudSQLInstancePostgresStatementTimeoutFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_postgres_statement_timeout_flag",
			CheckTitle:      "Cloud SQL PostgreSQL instance has statement_timeout flag configured",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "PostgreSQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for PostgreSQL instances are evaluated for the statement_timeout flag being configured.",
			Risk:            "Without statement_timeout, long-running queries may consume excessive resources and impact database performance",
			RemediationText: "Set statement_timeout flag on all Cloud SQL PostgreSQL instances to prevent long-running queries.",
			RemediationURL:  "https://cloud.google.com/sql/docs/postgres/flags#statement_timeout",
			Categories:      []string{"cloudsql", "database-flags", "postgres", "performance"},
		},
	}
}

func (c *CloudSQLInstancePostgresStatementTimeoutFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePostgresStatementTimeoutFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return executePostgresFlagConfiguredCheck(ctx, provider, c.metadata, "statement_timeout")
}

// Helper function for PostgreSQL flag checks that expect a specific value
func executePostgresFlagCheck(ctx context.Context, provider interface{}, metadata models.CheckMetadata, flagName string, expectedValue1, expectedValue2 string) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			if !isPostgresInstance(instance) {
				continue
			}
			value := getDatabaseFlagValue(instance.Settings.DatabaseFlags, flagName)
			isPass := value == expectedValue1 || (expectedValue2 != "" && value == expectedValue2)
			if !isPass {
				statusExtended := fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has %s flag not set to expected value (value: %s)", instance.Name, flagName, value)
				if value == "" {
					statusExtended = fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has %s flag not configured", instance.Name, flagName)
				}
				findings = append(findings, models.Finding{
					ID:             metadata.CheckID,
					Title:          metadata.CheckTitle,
					Description:    metadata.Description,
					Severity:       metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: statusExtended,
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					StatusExtended: fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has %s flag set correctly (value: %s)", instance.Name, flagName, value),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    metadata.RemediationText,
					Categories:     metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// Helper function for PostgreSQL flag checks that expect the flag to be configured (any value)
func executePostgresFlagConfiguredCheck(ctx context.Context, provider interface{}, metadata models.CheckMetadata, flagName string) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			if !isPostgresInstance(instance) {
				continue
			}
			value := getDatabaseFlagValue(instance.Settings.DatabaseFlags, flagName)
			if value == "" {
				findings = append(findings, models.Finding{
					ID:             metadata.CheckID,
					Title:          metadata.CheckTitle,
					Description:    metadata.Description,
					Severity:       metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has %s flag not configured", instance.Name, flagName),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					StatusExtended: fmt.Sprintf("Cloud SQL PostgreSQL instance '%s' has %s flag configured (value: %s)", instance.Name, flagName, value),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    metadata.RemediationText,
					Categories:     metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// Helper function to check if instance is PostgreSQL
func isPostgresInstance(instance *sqladmin.DatabaseInstance) bool {
	if instance.DatabaseVersion != "" {
		return len(instance.DatabaseVersion) >= 9 && instance.DatabaseVersion[:9] == "POSTGRES"
	}
	return false
}