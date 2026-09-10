package cloudstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/storage/v1"
)

type cloudstorageProvider interface {
	Storage(ctx context.Context) (*storage.Service, error)
	ProjectID() string
}

// BucketEncryptionCheck verifica se buckets usam criptografia CMEK
type BucketEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewBucketEncryptionCheck() *BucketEncryptionCheck {
	return &BucketEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudstorage_bucket_encryption",
			CheckTitle:      "Cloud Storage buckets use CMEK encryption",
			ServiceName:     "cloudstorage",
			Severity:        "high",
			Description:     "Cloud Storage buckets should use customer-managed encryption keys (CMEK)",
			RemediationText: "Enable CMEK encryption for Cloud Storage buckets",
			Categories:      []string{"storage", "encryption"},
		},
	}
}

func (c *BucketEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudstorageProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudstorageProvider")
	}
	svc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	buckets, err := svc.Buckets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		hasCMEK := bucket.Encryption != nil && bucket.Encryption.DefaultKmsKeyName != ""
		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s uses customer-managed encryption key (CMEK)", bucket.Name)
		if !hasCMEK {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s uses Google-managed encryption (no CMEK)", bucket.Name)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucket.Name,
			Provider: "gcp", Service: "cloudstorage",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// BucketIamCheck verifica IAM dos buckets - verifica acesso público
type BucketIamCheck struct {
	metadata models.CheckMetadata
}

func NewBucketIamCheck() *BucketIamCheck {
	return &BucketIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudstorage_bucket_iam",
			CheckTitle:      "Cloud Storage buckets have proper IAM",
			ServiceName:     "cloudstorage",
			Severity:        "medium",
			Description:     "Cloud Storage buckets should not have public IAM access (allUsers/allAuthenticatedUsers)",
			RemediationText: "Remove allUsers and allAuthenticatedUsers from bucket IAM policies",
			Categories:      []string{"identity"},
		},
	}
}

func (c *BucketIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudstorageProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudstorageProvider")
	}
	svc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	buckets, err := svc.Buckets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		policy, err := svc.Buckets.GetIamPolicy(bucket.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		hasPublicAccess := false
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					hasPublicAccess = true
					break
				}
			}
			if hasPublicAccess {
				break
			}
		}

		status := models.StatusPass
		ext := "Bucket has proper IAM configuration"
		if hasPublicAccess {
			status = models.StatusFail
			ext = "Bucket has public IAM access"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucket.Name,
			Provider: "gcp", Service: "cloudstorage",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// BucketLoggingCheck verifica logging dos buckets
type BucketLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewBucketLoggingCheck() *BucketLoggingCheck {
	return &BucketLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudstorage_bucket_logging",
			CheckTitle:      "Cloud Storage buckets have logging enabled",
			ServiceName:     "cloudstorage",
			Severity:        "low",
			Description:     "Cloud Storage buckets should have access logging enabled for audit",
			RemediationText: "Enable access logging for Cloud Storage buckets",
			Categories:      []string{"logging"},
		},
	}
}

func (c *BucketLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudstorageProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudstorageProvider")
	}
	svc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	buckets, err := svc.Buckets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		hasLogging := bucket.Logging != nil && bucket.Logging.LogBucket != ""
		status := models.StatusPass
		ext := "Bucket has access logging enabled"
		if !hasLogging {
			status = models.StatusFail
			ext = "Bucket does not have access logging enabled"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucket.Name,
			Provider: "gcp", Service: "cloudstorage",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// BucketVersioningCheck verifica versionamento dos buckets
type BucketVersioningCheck struct {
	metadata models.CheckMetadata
}

func NewBucketVersioningCheck() *BucketVersioningCheck {
	return &BucketVersioningCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudstorage_bucket_versioning",
			CheckTitle:      "Cloud Storage buckets have versioning enabled",
			ServiceName:     "cloudstorage",
			Severity:        "medium",
			Description:     "Cloud Storage buckets should have versioning enabled to protect against accidental deletion",
			RemediationText: "Enable versioning for Cloud Storage buckets",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketVersioningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketVersioningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudstorageProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudstorageProvider")
	}
	svc, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	buckets, err := svc.Buckets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		hasVersioning := bucket.Versioning != nil && bucket.Versioning.Enabled
		status := models.StatusPass
		ext := "Bucket has versioning enabled"
		if !hasVersioning {
			status = models.StatusFail
			ext = "Bucket does not have versioning enabled"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: bucket.Name,
			Provider: "gcp", Service: "cloudstorage",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}
