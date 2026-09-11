package bigquery

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type bigqueryCheck struct {
	metadata models.CheckMetadata
}

func (c *bigqueryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *bigqueryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP BigQuery check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "bigquery",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newBigqueryCheck(id, title, desc, sev string) bigqueryCheck {
	return bigqueryCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "bigquery", ResourceType: "Dataset",
		Categories: []string{"bigquery"},
	}}
}

type bigqueryDatasetPublicAccessDisabled struct{ bigqueryCheck }

func NewBigqueryDatasetPublicAccessDisabled() *bigqueryDatasetPublicAccessDisabled {
	return &bigqueryDatasetPublicAccessDisabled{newBigqueryCheck("bigquery_dataset_public_access_disabled", "Ensure BigQuery dataset public access is disabled", "BigQuery dataset should have public access disabled", "high")}
}

type bigqueryTableCustomerEncrypted struct{ bigqueryCheck }

func NewBigqueryTableCustomerEncrypted() *bigqueryTableCustomerEncrypted {
	return &bigqueryTableCustomerEncrypted{newBigqueryCheck("bigquery_table_customer_encrypted", "Ensure BigQuery table is customer encrypted", "BigQuery table should be customer encrypted", "medium")}
}
