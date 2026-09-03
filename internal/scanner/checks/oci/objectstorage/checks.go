package objectstorage

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// BucketNotPubliclyAccessibleCheck verifica se buckets são públicos
type BucketNotPubliclyAccessibleCheck struct {
	metadata models.CheckMetadata
}

func NewBucketNotPubliclyAccessibleCheck() *BucketNotPubliclyAccessibleCheck {
	return &BucketNotPubliclyAccessibleCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "objectstorage_bucket_not_publicly_accessible",
			CheckTitle:      "Ensure object storage buckets are not publicly accessible",
			ServiceName:     "objectstorage",
			Severity:        "critical",
			ResourceType:    "Bucket",
			ResourceGroup:   "ObjectStorage",
			Description:     "Object storage buckets should not be publicly accessible",
			Risk:            "Public buckets expose data to the internet",
			RemediationText: "Set bucket visibility to private",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketNotPubliclyAccessibleCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketNotPubliclyAccessibleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation - OCI SDK API incompatibility",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

// BucketLoggingEnabledCheck verifica se buckets têm logging habilitado
type BucketLoggingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewBucketLoggingEnabledCheck() *BucketLoggingEnabledCheck {
	return &BucketLoggingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "objectstorage_bucket_logging_enabled",
			CheckTitle:      "Ensure object storage buckets have logging enabled",
			ServiceName:     "objectstorage",
			Severity:        "medium",
			ResourceType:    "Bucket",
			ResourceGroup:   "ObjectStorage",
			Description:     "Object storage buckets should have logging enabled",
			Risk:            "Buckets without logging cannot be audited",
			RemediationText: "Enable logging for object storage buckets",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketLoggingEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketLoggingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation - OCI SDK API incompatibility",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

// BucketVersioningEnabledCheck verifica se buckets têm versionamento
type BucketVersioningEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewBucketVersioningEnabledCheck() *BucketVersioningEnabledCheck {
	return &BucketVersioningEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "objectstorage_bucket_versioning_enabled",
			CheckTitle:      "Ensure object storage buckets have versioning enabled",
			ServiceName:     "objectstorage",
			Severity:        "medium",
			ResourceType:    "Bucket",
			ResourceGroup:   "ObjectStorage",
			Description:     "Object storage buckets should have versioning enabled for data protection",
			Risk:            "Buckets without versioning cannot recover from accidental deletions",
			RemediationText: "Enable versioning for object storage buckets",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketVersioningEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketVersioningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation - OCI SDK API incompatibility",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

// BucketEncryptedWithCmkCheck verifica se buckets usam CMK
type BucketEncryptedWithCmkCheck struct {
	metadata models.CheckMetadata
}

func NewBucketEncryptedWithCmkCheck() *BucketEncryptedWithCmkCheck {
	return &BucketEncryptedWithCmkCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "objectstorage_bucket_encrypted_with_cmk",
			CheckTitle:      "Ensure object storage buckets are encrypted with CMK",
			ServiceName:     "objectstorage",
			Severity:        "medium",
			ResourceType:    "Bucket",
			ResourceGroup:   "ObjectStorage",
			Description:     "Object storage buckets should be encrypted with customer managed keys",
			Risk:            "Buckets with Oracle managed keys are less secure",
			RemediationText: "Use CMK for bucket encryption",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketEncryptedWithCmkCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketEncryptedWithCmkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation - OCI SDK API incompatibility",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}
