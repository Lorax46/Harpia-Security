package database

import (
	"context"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// DatabaseAutonomousDatabaseAccessRestricted - high
type DatabaseAutonomousDatabaseAccessRestricted struct {
	metadata models.CheckMetadata
}

// NewDatabaseAutonomousDatabaseAccessRestricted cria nova instância
func NewDatabaseAutonomousDatabaseAccessRestricted() *DatabaseAutonomousDatabaseAccessRestricted {
	return &DatabaseAutonomousDatabaseAccessRestricted{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "database_autonomous_database_access_restricted",
			CheckTitle:     "Autonomous Shared Database (ADB) is deployed within a VCN or restricts public access with whitelisted IPs excluding 0.0.0.0/0",
			ServiceName:    "database",
			Severity:       "high",
			Description:    "**OCI Autonomous Database (shared)** network exposure is evaluated: instances are treated as restricted when using a **VCN private endpoint** or when ",
			RemediationText: "Prefer **VCN private endpoints** to eliminate internet exposure. If public access is required, enfor",
			Categories:     []string{"database"},
		},
	}
}

// Metadata retorna os metadados
func (c *DatabaseAutonomousDatabaseAccessRestricted) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *DatabaseAutonomousDatabaseAccessRestricted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "database",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

