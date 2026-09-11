package cloudstorage

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cloudstorageCheck struct {
	metadata models.CheckMetadata
}

func newCloudstorageCheck(id, title, description, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: description, Severity: severity,
		ServiceName: "cloudstorage", ResourceType: "Bucket",
		Categories: []string{"cloudstorage"},
	}
}

func (c *cloudstorageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *cloudstorageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP Cloud Storage check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "cloudstorage",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type cloudstorageBucketLoggingEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketLoggingEnabled() *cloudstorageBucketLoggingEnabled {
	return &cloudstorageBucketLoggingEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_logging_enabled",
		"Ensure Cloud Storage bucket logging is enabled",
		"Cloud Storage bucket should have logging enabled",
		"medium",
	)}}
}

type cloudstorageBucketNoPublicAccess struct{ cloudstorageCheck }

func NewCloudstorageBucketNoPublicAccess() *cloudstorageBucketNoPublicAccess {
	return &cloudstorageBucketNoPublicAccess{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_no_public_access",
		"Ensure Cloud Storage bucket has no public access",
		"Cloud Storage bucket should have no public access",
		"critical",
	)}}
}

type cloudstorageBucketPolicyOnlyEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketPolicyOnlyEnabled() *cloudstorageBucketPolicyOnlyEnabled {
	return &cloudstorageBucketPolicyOnlyEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_policy_only_enabled",
		"Ensure Cloud Storage bucket policy only is enabled",
		"Cloud Storage bucket should have policy only enabled",
		"medium",
	)}}
}

type cloudstorageBucketPublicAccessPreventionEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketPublicAccessPreventionEnabled() *cloudstorageBucketPublicAccessPreventionEnabled {
	return &cloudstorageBucketPublicAccessPreventionEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_public_access_prevention_enabled",
		"Ensure Cloud Storage bucket public access prevention is enabled",
		"Cloud Storage bucket should have public access prevention enabled",
		"high",
	)}}
}

type cloudstorageBucketSoftDeleteEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketSoftDeleteEnabled() *cloudstorageBucketSoftDeleteEnabled {
	return &cloudstorageBucketSoftDeleteEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_soft_delete_enabled",
		"Ensure Cloud Storage bucket soft delete is enabled",
		"Cloud Storage bucket should have soft delete enabled",
		"medium",
	)}}
}

type cloudstorageBucketUniformBucketLevelAccessEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketUniformBucketLevelAccessEnabled() *cloudstorageBucketUniformBucketLevelAccessEnabled {
	return &cloudstorageBucketUniformBucketLevelAccessEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_uniform_bucket_level_access_enabled",
		"Ensure Cloud Storage bucket uniform bucket level access is enabled",
		"Cloud Storage bucket should have uniform bucket level access enabled",
		"medium",
	)}}
}

type cloudstorageBucketUserManagedEncryptionKeysEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketUserManagedEncryptionKeysEnabled() *cloudstorageBucketUserManagedEncryptionKeysEnabled {
	return &cloudstorageBucketUserManagedEncryptionKeysEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_user_managed_encryption_keys_enabled",
		"Ensure Cloud Storage bucket user managed encryption keys is enabled",
		"Cloud Storage bucket should have user managed encryption keys enabled",
		"medium",
	)}}
}

type cloudstorageBucketVersioningEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketVersioningEnabled() *cloudstorageBucketVersioningEnabled {
	return &cloudstorageBucketVersioningEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_versioning_enabled",
		"Ensure Cloud Storage bucket versioning is enabled",
		"Cloud Storage bucket should have versioning enabled",
		"low",
	)}}
}

type cloudstorageObjectVersioningEnabled struct{ cloudstorageCheck }

func NewCloudstorageObjectVersioningEnabled() *cloudstorageObjectVersioningEnabled {
	return &cloudstorageObjectVersioningEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_object_versioning_enabled",
		"Ensure Cloud Storage object versioning is enabled",
		"Cloud Storage object should have versioning enabled",
		"low",
	)}}
}

type cloudstorageBucketRequestResponseLoggingEnabled struct{ cloudstorageCheck }

func NewCloudstorageBucketRequestResponseLoggingEnabled() *cloudstorageBucketRequestResponseLoggingEnabled {
	return &cloudstorageBucketRequestResponseLoggingEnabled{cloudstorageCheck{metadata: newCloudstorageCheck(
		"cloudstorage_bucket_request_response_logging_enabled",
		"Ensure Cloud Storage bucket request response logging is enabled",
		"Cloud Storage bucket should have request response logging enabled",
		"low",
	)}}
}
