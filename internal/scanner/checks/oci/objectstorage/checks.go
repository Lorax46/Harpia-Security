package objectstorage

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ObjectstorageBucketLoggingEnabled - medium
type ObjectstorageBucketLoggingEnabled struct {
	metadata models.CheckMetadata
}

// NewObjectstorageBucketLoggingEnabled cria nova instância
func NewObjectstorageBucketLoggingEnabled() *ObjectstorageBucketLoggingEnabled {
	return &ObjectstorageBucketLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "objectstorage_bucket_logging_enabled",
			CheckTitle:     "Object Storage bucket has write-level logging enabled",
			ServiceName:    "objectstorage",
			Severity:       "medium",
			Description:    "**OCI Object Storage buckets** have service logs for **write access events** enabled.  The evaluation identifies buckets with an active `write` loggin",
			RemediationText: "Enable `write` service logs on all buckets and route them to a centralized log group for monitoring.",
			Categories:     []string{"objectstorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *ObjectstorageBucketLoggingEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ObjectstorageBucketLoggingEnabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// ObjectstorageBucketEncryptedWithCmk - medium
type ObjectstorageBucketEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

// NewObjectstorageBucketEncryptedWithCmk cria nova instância
func NewObjectstorageBucketEncryptedWithCmk() *ObjectstorageBucketEncryptedWithCmk {
	return &ObjectstorageBucketEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "objectstorage_bucket_encrypted_with_cmk",
			CheckTitle:     "Object Storage bucket is encrypted with a Customer Managed Key (CMK)",
			ServiceName:    "objectstorage",
			Severity:       "medium",
			Description:    "**OCI Object Storage buckets** use **customer-managed encryption keys** (`CMEK`) for server-side encryption, with an associated KMS key configured on ",
			RemediationText: "Encrypt buckets with `CMEK`. Apply **least privilege** to key usage, enforce **separation of duties*",
			Categories:     []string{"objectstorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *ObjectstorageBucketEncryptedWithCmk) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ObjectstorageBucketEncryptedWithCmk) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// ObjectstorageBucketNotPubliclyAccessible - critical
type ObjectstorageBucketNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

// NewObjectstorageBucketNotPubliclyAccessible cria nova instância
func NewObjectstorageBucketNotPubliclyAccessible() *ObjectstorageBucketNotPubliclyAccessible {
	return &ObjectstorageBucketNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "objectstorage_bucket_not_publicly_accessible",
			CheckTitle:     "Object Storage bucket is not publicly accessible",
			ServiceName:    "objectstorage",
			Severity:       "critical",
			Description:    "**OCI Object Storage buckets** are assessed for **public accessibility**. Buckets configured as `NoPublicAccess` deny anonymous reads; any other publi",
			RemediationText: "Keep buckets **private** (`NoPublicAccess`) under the **least privilege** principle. For external sh",
			Categories:     []string{"objectstorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *ObjectstorageBucketNotPubliclyAccessible) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ObjectstorageBucketNotPubliclyAccessible) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// ObjectstorageBucketVersioningEnabled - medium
type ObjectstorageBucketVersioningEnabled struct {
	metadata models.CheckMetadata
}

// NewObjectstorageBucketVersioningEnabled cria nova instância
func NewObjectstorageBucketVersioningEnabled() *ObjectstorageBucketVersioningEnabled {
	return &ObjectstorageBucketVersioningEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "objectstorage_bucket_versioning_enabled",
			CheckTitle:     "Object Storage bucket has versioning enabled",
			ServiceName:    "objectstorage",
			Severity:       "medium",
			Description:    "**OCI Object Storage buckets** are assessed for **versioning** being set to `Enabled`, indicating prior object versions are retained when updates or d",
			RemediationText: "Enable **bucket versioning** (`Enabled`) for data that needs recovery. Apply **least privilege** to ",
			Categories:     []string{"objectstorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *ObjectstorageBucketVersioningEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ObjectstorageBucketVersioningEnabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

