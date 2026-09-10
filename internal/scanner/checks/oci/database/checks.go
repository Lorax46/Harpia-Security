package database

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/database"
)

type databaseProvider interface {
	Database() (database.DatabaseClient, error)
	TenancyId() string
}

// DatabaseAutonomousDatabaseAccessRestricted - high
type DatabaseAutonomousDatabaseAccessRestricted struct {
	metadata models.CheckMetadata
}

func NewDatabaseAutonomousDatabaseAccessRestricted() *DatabaseAutonomousDatabaseAccessRestricted {
	return &DatabaseAutonomousDatabaseAccessRestricted{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "database_autonomous_database_access_restricted",
			CheckTitle:     "Autonomous Shared Database (ADB) is deployed within a VCN or restricts public access with whitelisted IPs excluding 0.0.0.0/0",
			ServiceName:    "database",
			Severity:       "high",
			Description:    "**OCI Autonomous Database (shared)** network exposure is evaluated: instances are treated as restricted when using a **VCN private endpoint** or when public access uses IP allowlists.",
			RemediationText: "Prefer **VCN private endpoints** to eliminate internet exposure.",
			Categories:     []string{"database"},
		},
	}
}

func (c *DatabaseAutonomousDatabaseAccessRestricted) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *DatabaseAutonomousDatabaseAccessRestricted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(databaseProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa databaseProvider")
	}

	dbClient, err := p.Database()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := database.ListAutonomousDatabasesRequest{
		CompartmentId: &tenancyId,
	}

	dbs, err := dbClient.ListAutonomousDatabases(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list autonomous databases: %w", err)
	}

	for _, db := range dbs.Items {
		isRestricted := false
		if db.IsAccessControlEnabled != nil && *db.IsAccessControlEnabled {
			isRestricted = true
		}
		if db.WhitelistedIps != nil && len(db.WhitelistedIps) > 0 {
			// Check if only specific IPs are allowed (not 0.0.0.0/0)
			hasOpenAccess := false
			for _, ip := range db.WhitelistedIps {
				if ip == "0.0.0.0/0" {
					hasOpenAccess = true
					break
				}
			}
			isRestricted = !hasOpenAccess
		}

		if isRestricted {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Autonomous Database %s has restricted access", safeString(db.DisplayName)),
				ResourceID:     safeString(db.Id),
				Provider:       "oci",
				Service:        "database",
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
				StatusExtended: fmt.Sprintf("Autonomous Database %s has public access", safeString(db.DisplayName)),
				ResourceID:     safeString(db.Id),
				Provider:       "oci",
				Service:        "database",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}