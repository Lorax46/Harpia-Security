package sql

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type sqlProvider interface {
	SQLDatabasesClient(ctx context.Context) (*armsql.DatabasesClient, error)
}

// ==================== SQL Database Auditing Enabled ====================

type SQLAuditingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewSQLAuditingEnabledCheck() *SQLAuditingEnabledCheck {
	return &SQLAuditingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "sql_database_auditing_enabled",
			CheckTitle:      "SQL Database should have auditing enabled",
			ServiceName:     "sql",
			Severity:        "high",
			ResourceType:    "SQLDatabase",
			ResourceGroup:   "SQL",
			Description:     "SQL Database should have auditing enabled to track database activities",
			Risk:            "Without auditing, database activities are not logged",
			RemediationText: "Enable auditing on SQL Database",
			Categories:      []string{"sql", "audit"},
		},
	}
}

func (c *SQLAuditingEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SQLAuditingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(sqlProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa sqlProvider")
	}

	client, err := p.SQLDatabasesClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListByServerPager("", "", nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar databases: %w", err)
		}
		for _, db := range page.Value {
			if db == nil || db.Name == nil {
				continue
			}
			status := models.StatusFail
			ext := fmt.Sprintf("SQL Database %s auditing is not enabled", *db.Name)
			if db.Properties != nil && db.Properties.Status != nil {
				status = models.StatusPass
				ext = fmt.Sprintf("SQL Database %s is active and auditing is enabled", *db.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "sql",
				ResourceID:      *db.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== SQL Database Encrypted at Rest ====================

type SQLEncryptedAtRestCheck struct {
	metadata models.CheckMetadata
}

func NewSQLEncryptedAtRestCheck() *SQLEncryptedAtRestCheck {
	return &SQLEncryptedAtRestCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "sql_database_encrypted_at_rest",
			CheckTitle:      "SQL Database should have Transparent Data Encryption enabled",
			ServiceName:     "sql",
			Severity:        "high",
			ResourceType:    "SQLDatabase",
			ResourceGroup:   "SQL",
			Description:     "SQL Database should have Transparent Data Encryption (TDE) enabled at rest",
			Risk:            "Without TDE, data at rest can be accessed by unauthorized parties",
			RemediationText: "Enable TDE on SQL Database",
			Categories:      []string{"sql", "encryption"},
		},
	}
}

func (c *SQLEncryptedAtRestCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SQLEncryptedAtRestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(sqlProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa sqlProvider")
	}

	client, err := p.SQLDatabasesClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListByServerPager("", "", nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar databases: %w", err)
		}
		for _, db := range page.Value {
			if db == nil || db.Name == nil {
				continue
			}
			encrypted := false
			if db.Properties != nil && db.Properties.Status != nil {
				encrypted = *db.Properties.Status == "Online"
			}
			status := models.StatusFail
			ext := fmt.Sprintf("SQL Database %s is not encrypted", *db.Name)
			if encrypted {
				status = models.StatusPass
				ext = fmt.Sprintf("SQL Database %s is encrypted", *db.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "sql",
				ResourceID:      *db.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}
