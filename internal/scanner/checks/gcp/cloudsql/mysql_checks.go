package cloudsql

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/sqladmin/v1"
)

// === cloudsql_instance_mysql_local_infile_flag ===

type CloudSQLInstanceMysqlLocalInfileFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceMysqlLocalInfileFlagCheck() *CloudSQLInstanceMysqlLocalInfileFlagCheck {
	return &CloudSQLInstanceMysqlLocalInfileFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_mysql_local_infile_flag",
			CheckTitle:      "Cloud SQL MySQL instance has the local_infile database flag set to off",
			ServiceName:     "cloudsql",
			Severity:        "high",
			ResourceType:    "MySQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL for MySQL instances are evaluated for the local_infile database flag being explicitly set to off, disabling use of LOAD DATA LOCAL.",
			Risk:            "With local_infile enabled, a MySQL client could read arbitrary files from the server and potentially exfiltrate sensitive data",
			RemediationText: "Keep local_infile set to off. Use governed import channels (e.g., controlled object storage imports) and enforce least privilege for bulk-loading.",
			RemediationURL:  "https://cloud.google.com/sql/mysql/flags#mysql_local_infile",
			Categories:      []string{"cloudsql", "database-flags", "mysql", "hardening"},
		},
	}
}

func (c *CloudSQLInstanceMysqlLocalInfileFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceMysqlLocalInfileFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
			if !isMySQLInstance(instance) {
				continue
			}
			localInfileValue := getDatabaseFlagValue(instance.Settings.DatabaseFlags, "local_infile")
			if localInfileValue != "off" && localInfileValue != "0" {
				statusExtended := fmt.Sprintf("Cloud SQL MySQL instance '%s' has local_infile flag not set to off (value: %s)", instance.Name, localInfileValue)
				if localInfileValue == "" {
					statusExtended = fmt.Sprintf("Cloud SQL MySQL instance '%s' has local_infile flag not configured", instance.Name)
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
					StatusExtended: fmt.Sprintf("Cloud SQL MySQL instance '%s' has local_infile flag set to off", instance.Name),
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

// === cloudsql_instance_mysql_skip_show_database_flag ===

type CloudSQLInstanceMysqlSkipShowDatabaseFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceMysqlSkipShowDatabaseFlagCheck() *CloudSQLInstanceMysqlSkipShowDatabaseFlagCheck {
	return &CloudSQLInstanceMysqlSkipShowDatabaseFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_mysql_skip_show_database_flag",
			CheckTitle:      "Cloud SQL MySQL instance has skip_show_database flag set to on",
			ServiceName:     "cloudsql",
			Severity:        "low",
			ResourceType:    "MySQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL MySQL instances configure the skip_show_database database flag to on, limiting use of SHOW DATABASES to accounts with the SHOW DATABASES privilege.",
			Risk:            "Without skip_show_database, any user with SHOW DATABASES privilege can see all database names, aiding reconnaissance for attackers",
			RemediationText: "Set skip_show_database to on for all Cloud SQL MySQL instances. Enforce least privilege by granting SHOW DATABASES only when necessary.",
			RemediationURL:  "https://cloud.google.com/sql/mysql/flags#mysql_skip_show_database",
			Categories:      []string{"cloudsql", "database-flags", "mysql", "hardening"},
		},
	}
}

func (c *CloudSQLInstanceMysqlSkipShowDatabaseFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceMysqlSkipShowDatabaseFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
			if !isMySQLInstance(instance) {
				continue
			}
			skipShowDbValue := getDatabaseFlagValue(instance.Settings.DatabaseFlags, "skip_show_database")
			if skipShowDbValue != "on" && skipShowDbValue != "1" {
				statusExtended := fmt.Sprintf("Cloud SQL MySQL instance '%s' has skip_show_database flag not set to on (value: %s)", instance.Name, skipShowDbValue)
				if skipShowDbValue == "" {
					statusExtended = fmt.Sprintf("Cloud SQL MySQL instance '%s' has skip_show_database flag not configured", instance.Name)
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
					StatusExtended: fmt.Sprintf("Cloud SQL MySQL instance '%s' has skip_show_database flag set to on", instance.Name),
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

// === cloudsql_instance_password_min_length_flag ===

type CloudSQLInstancePasswordMinLengthFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePasswordMinLengthFlagCheck() *CloudSQLInstancePasswordMinLengthFlagCheck {
	return &CloudSQLInstancePasswordMinLengthFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_password_min_length_flag",
			CheckTitle:      "Cloud SQL instance has password_min_length flag configured",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances are evaluated for the password_min_length flag being configured to enforce minimum password length.",
			Risk:            "Without password_min_length enforcement, users may set weak passwords that are easily compromised",
			RemediationText: "Set password_min_length flag to an appropriate value (e.g., 14) on all Cloud SQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/flags",
			Categories:      []string{"cloudsql", "database-flags", "authentication"},
		},
	}
}

func (c *CloudSQLInstancePasswordMinLengthFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePasswordMinLengthFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
			minLengthValue := getDatabaseFlagValue(instance.Settings.DatabaseFlags, "password_min_length")
			if minLengthValue == "" {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' does not have password_min_length flag configured", instance.Name),
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
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has password_min_length flag configured (value: %s)", instance.Name, minLengthValue),
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

// === cloudsql_instance_password_require_complexity_flag ===

type CloudSQLInstancePasswordRequireComplexityFlagCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstancePasswordRequireComplexityFlagCheck() *CloudSQLInstancePasswordRequireComplexityFlagCheck {
	return &CloudSQLInstancePasswordRequireComplexityFlagCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_password_require_complexity_flag",
			CheckTitle:      "Cloud SQL instance has password_require_complexity flag configured",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances are evaluated for the password_require_complexity flag being configured to enforce strong password policies.",
			Risk:            "Without password complexity requirements, users may set simple passwords that are vulnerable to brute-force attacks",
			RemediationText: "Enable password_require_complexity flag on all Cloud SQL instances.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/flags",
			Categories:      []string{"cloudsql", "database-flags", "authentication"},
		},
	}
}

func (c *CloudSQLInstancePasswordRequireComplexityFlagCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstancePasswordRequireComplexityFlagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
			complexityValue := getDatabaseFlagValue(instance.Settings.DatabaseFlags, "password_require_complexity")
			if complexityValue != "on" && complexityValue != "1" {
				statusExtended := fmt.Sprintf("Cloud SQL instance '%s' has password_require_complexity flag not set to on (value: %s)", instance.Name, complexityValue)
				if complexityValue == "" {
					statusExtended = fmt.Sprintf("Cloud SQL instance '%s' has password_require_complexity flag not configured", instance.Name)
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
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has password_require_complexity flag set to on", instance.Name),
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

// Helper function to check if instance is MySQL
func isMySQLInstance(instance *sqladmin.DatabaseInstance) bool {
	if instance.DatabaseVersion != "" {
		return len(instance.DatabaseVersion) >= 5 && instance.DatabaseVersion[:5] == "MYSQL"
	}
	return false
}

// Helper function to get database flag value
func getDatabaseFlagValue(flags []*sqladmin.DatabaseFlags, flagName string) string {
	for _, flag := range flags {
		if flag.Name == flagName {
			return flag.Value
		}
	}
	return ""
}