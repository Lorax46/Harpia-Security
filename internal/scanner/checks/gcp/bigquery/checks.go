package bigquery

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"google.golang.org/api/bigquery/v2"
)

type bigqueryProvider interface {
	BigQuery(ctx context.Context) (*bigquery.Service, error)
	ProjectID() string
}

// ========== 1. DatasetPublicAccessCheck ==========

type DatasetPublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewDatasetPublicAccessCheck() *DatasetPublicAccessCheck {
	return &DatasetPublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigquery_dataset_public_access",
			CheckTitle:      "BigQuery dataset should not be publicly accessible",
			ServiceName:     "bigquery",
			Severity:        "critical",
			ResourceType:    "Dataset",
			Description:     "BigQuery datasets should not be publicly accessible",
			Risk:            "Public datasets expose data to the internet",
			RemediationText: "Remove allUsers and allAuthenticatedUsers from dataset access",
			RemediationURL:  "https://cloud.google.com/bigquery/docs/dataset-access-controls",
			Categories:      []string{"bigquery", "data"},
		},
	}
}

func (c *DatasetPublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatasetPublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigqueryProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa bigqueryProvider")
	}
	bq, err := p.BigQuery(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := bq.Datasets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			// Get full dataset details to access the Access field
			fullDs, err := bq.Datasets.Get(p.ProjectID(), ds.DatasetReference.DatasetId).Context(ctx).Do()
			if err != nil {
				return err
			}
			isPublic := false
			for _, access := range fullDs.Access {
				if access.UserByEmail == "allUsers" || access.UserByEmail == "allAuthenticatedUsers" {
					isPublic = true
					break
				}
			}
			status := models.StatusPass
			ext := "Dataset is not publicly accessible"
			if isPublic {
				status = models.StatusFail
				ext = "Dataset is publicly accessible"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "bigquery",
				ResourceID:     fullDs.DatasetReference.DatasetId,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 2. DatasetCmekEncryptionCheck ==========

type DatasetCmekEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewDatasetCmekEncryptionCheck() *DatasetCmekEncryptionCheck {
	return &DatasetCmekEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigquery_dataset_cmek_encryption",
			CheckTitle:      "BigQuery dataset should use customer-managed encryption keys (CMEK)",
			ServiceName:     "bigquery",
			Severity:        "high",
			ResourceType:    "Dataset",
			Description:     "BigQuery datasets should use customer-managed encryption keys (CMEK) instead of Google-managed keys",
			Risk:            "Using Google-managed encryption keys reduces control over data encryption and key rotation",
			RemediationText: "Configure a Cloud KMS key for the dataset encryptionConfiguration.kmsKeyName",
			RemediationURL:  "https://cloud.google.com/bigquery/docs/customer-managed-encryption",
			Categories:      []string{"bigquery", "encryption"},
		},
	}
}

func (c *DatasetCmekEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatasetCmekEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigqueryProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa bigqueryProvider")
	}
	bq, err := p.BigQuery(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := bq.Datasets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			// Get full dataset details to access the EncryptionConfiguration field
			fullDs, err := bq.Datasets.Get(p.ProjectID(), ds.DatasetReference.DatasetId).Context(ctx).Do()
			if err != nil {
				return err
			}
			hasCmek := fullDs.DefaultEncryptionConfiguration != nil && fullDs.DefaultEncryptionConfiguration.KmsKeyName != ""
			status := models.StatusPass
			ext := "Dataset uses customer-managed encryption key (CMEK)"
			if !hasCmek {
				status = models.StatusFail
				ext = "Dataset does not use customer-managed encryption key (CMEK)"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "bigquery",
				ResourceID:     fullDs.DatasetReference.DatasetId,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 3. DatasetLabelsCheck ==========

type DatasetLabelsCheck struct {
	metadata models.CheckMetadata
}

func NewDatasetLabelsCheck() *DatasetLabelsCheck {
	return &DatasetLabelsCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigquery_dataset_labels",
			CheckTitle:      "BigQuery dataset should have labels for resource management",
			ServiceName:     "bigquery",
			Severity:        "medium",
			ResourceType:    "Dataset",
			Description:     "BigQuery datasets should have labels for cost allocation, organization, and resource management",
			Risk:            "Unlabeled datasets make it difficult to track costs, ownership, and compliance",
			RemediationText: "Add labels to the dataset for proper resource management and cost allocation",
			RemediationURL:  "https://cloud.google.com/bigquery/docs/adding-labels",
			Categories:      []string{"bigquery", "tagging"},
		},
	}
}

func (c *DatasetLabelsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatasetLabelsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigqueryProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa bigqueryProvider")
	}
	bq, err := p.BigQuery(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := bq.Datasets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			// Get full dataset details to access the Labels field
			fullDs, err := bq.Datasets.Get(p.ProjectID(), ds.DatasetReference.DatasetId).Context(ctx).Do()
			if err != nil {
				return err
			}
			hasLabels := fullDs.Labels != nil && len(fullDs.Labels) > 0
			status := models.StatusPass
			ext := "Dataset has labels configured"
			if !hasLabels {
				status = models.StatusFail
				ext = "Dataset does not have labels configured"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "bigquery",
				ResourceID:     fullDs.DatasetReference.DatasetId,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 4. TableCmekEncryptionCheck ==========

type TableCmekEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewTableCmekEncryptionCheck() *TableCmekEncryptionCheck {
	return &TableCmekEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigquery_table_cmek_encryption",
			CheckTitle:      "BigQuery table should use customer-managed encryption keys (CMEK)",
			ServiceName:     "bigquery",
			Severity:        "high",
			ResourceType:    "Table",
			Description:     "BigQuery tables should use customer-managed encryption keys (CMEK) instead of Google-managed keys",
			Risk:            "Using Google-managed encryption keys reduces control over data encryption and key rotation",
			RemediationText: "Configure a Cloud KMS key for the dataset encryptionConfiguration.kmsKeyName",
			RemediationURL:  "https://cloud.google.com/bigquery/docs/customer-managed-encryption",
			Categories:      []string{"bigquery", "encryption"},
		},
	}
}

func (c *TableCmekEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TableCmekEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigqueryProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa bigqueryProvider")
	}
	bq, err := p.BigQuery(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// List all datasets first
	datasetsReq := bq.Datasets.List(p.ProjectID())
	err = datasetsReq.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			datasetID := ds.DatasetReference.DatasetId

			// Get full dataset details to check encryption configuration
			fullDs, err := bq.Datasets.Get(p.ProjectID(), datasetID).Context(ctx).Do()
			if err != nil {
				return err
			}
			datasetHasCmek := fullDs.DefaultEncryptionConfiguration != nil && fullDs.DefaultEncryptionConfiguration.KmsKeyName != ""

			// List tables in each dataset
			tablesReq := bq.Tables.List(p.ProjectID(), datasetID)
			err = tablesReq.Pages(ctx, func(tablePage *bigquery.TableList) error {
				for _, table := range tablePage.Tables {
					status := models.StatusPass
					ext := "Table uses customer-managed encryption key (CMEK) via dataset"
					if !datasetHasCmek {
						status = models.StatusFail
						ext = "Table does not use customer-managed encryption key (CMEK)"
					}
					resourceID := fmt.Sprintf("%s.%s", datasetID, table.TableReference.TableId)
					findings = append(findings, models.Finding{
						ID:             c.metadata.CheckID,
						Title:          c.metadata.CheckTitle,
						Description:    c.metadata.Description,
						Severity:       c.metadata.Severity,
						Status:         status,
						StatusExtended: ext,
						Provider:       "gcp",
						Service:        "bigquery",
						ResourceID:     resourceID,
						Remediation:    c.metadata.RemediationText,
						Categories:     c.metadata.Categories,
						FoundAt:        time.Now(),
					})
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return findings, err
}

// ========== 5. DatasetIamPolicyCheck ==========

type DatasetIamPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewDatasetIamPolicyCheck() *DatasetIamPolicyCheck {
	return &DatasetIamPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigquery_dataset_iam_policy",
			CheckTitle:      "BigQuery dataset IAM policies should not grant overly permissive roles",
			ServiceName:     "bigquery",
			Severity:        "high",
			ResourceType:    "Dataset",
			Description:     "BigQuery dataset IAM policies should follow least privilege and avoid overly permissive roles like owner or editor",
			Risk:            "Overly permissive IAM roles can lead to unauthorized data access or modification",
			RemediationText: "Review and restrict IAM policies to follow the principle of least privilege",
			RemediationURL:  "https://cloud.google.com/bigquery/docs/dataset-access-controls#iam",
			Categories:      []string{"bigquery", "iam"},
		},
	}
}

func (c *DatasetIamPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DatasetIamPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigqueryProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa bigqueryProvider")
	}
	bq, err := p.BigQuery(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := bq.Datasets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			// Get full dataset details to access the Access field
			fullDs, err := bq.Datasets.Get(p.ProjectID(), ds.DatasetReference.DatasetId).Context(ctx).Do()
			if err != nil {
				return err
			}
			hasOverlyPermissive := false
			for _, access := range fullDs.Access {
				if access.Role == "OWNER" || access.Role == "WRITER" {
					if access.UserByEmail != "" || access.GroupByEmail != "" {
						hasOverlyPermissive = true
						break
					}
				}
			}
			status := models.StatusPass
			ext := "Dataset IAM policy does not have overly permissive roles"
			if hasOverlyPermissive {
				status = models.StatusFail
				ext = "Dataset IAM policy has overly permissive roles (OWNER or WRITER)"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "bigquery",
				ResourceID:     fullDs.DatasetReference.DatasetId,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}