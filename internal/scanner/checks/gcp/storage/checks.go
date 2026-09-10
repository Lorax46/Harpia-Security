package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"google.golang.org/api/storage/v1"
)

type storageProvider interface {
	Storage(ctx context.Context) (*storage.Service, error)
	ProjectID() string
}

// ========== 1. BucketPublicAccessCheck ==========

type BucketPublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewBucketPublicAccessCheck() *BucketPublicAccessCheck {
	return &BucketPublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "storage_bucket_public_access",
			CheckTitle:     "Storage bucket should not be publicly accessible",
			ServiceName:    "storage",
			Severity:       "critical",
			ResourceType:   "Bucket",
			Description:    "Storage buckets should not be publicly accessible",
			Risk:           "Public buckets expose data to the internet",
			RemediationText: "Remove allUsers and allAuthenticatedUsers from bucket IAM",
			RemediationURL: "https://cloud.google.com/storage/docs/access-control",
			Categories:     []string{"storage", "data"},
		},
	}
}

func (c *BucketPublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketPublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}
	storageService, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := storageService.Buckets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			isPublic := false
			if bucket.IamConfiguration != nil && bucket.IamConfiguration.BucketPolicyOnly != nil {
				isPublic = !bucket.IamConfiguration.BucketPolicyOnly.Enabled
			} else {
				isPublic = true
			}
			status := models.StatusPass
			ext := "Bucket has BucketPolicyOnly enabled"
			if isPublic {
				status = models.StatusFail
				ext = "Bucket does not have BucketPolicyOnly enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "storage",
				ResourceID:     bucket.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 2. BucketEncryptionCheck ==========

type BucketEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewBucketEncryptionCheck() *BucketEncryptionCheck {
	return &BucketEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "storage_bucket_encryption",
			CheckTitle:     "Storage bucket should use customer-managed encryption keys (CMEK)",
			ServiceName:    "storage",
			Severity:       "high",
			ResourceType:   "Bucket",
			Description:    "Storage buckets should use customer-managed encryption keys for data at rest",
			Risk:           "Buckets without CMEK rely on Google-managed keys, reducing control over data encryption",
			RemediationText: "Configure a Cloud KMS key as the default encryption key for the bucket",
			RemediationURL: "https://cloud.google.com/storage/docs/encryption/customer-managed-keys",
			Categories:     []string{"storage", "encryption"},
		},
	}
}

func (c *BucketEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}
	storageService, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := storageService.Buckets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			hasCMEK := false
			if bucket.Encryption != nil && bucket.Encryption.DefaultKmsKeyName != "" {
				hasCMEK = true
			}
			status := models.StatusFail
			ext := "Bucket does not use CMEK (uses Google-managed encryption key)"
			if hasCMEK {
				status = models.StatusPass
				ext = "Bucket uses CMEK for encryption"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "storage",
				ResourceID:     bucket.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 3. BucketVersioningCheck ==========

type BucketVersioningCheck struct {
	metadata models.CheckMetadata
}

func NewBucketVersioningCheck() *BucketVersioningCheck {
	return &BucketVersioningCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "storage_bucket_versioning",
			CheckTitle:     "Storage bucket should have versioning enabled",
			ServiceName:    "storage",
			Severity:       "medium",
			ResourceType:   "Bucket",
			Description:    "Storage buckets should have versioning enabled to protect against accidental deletion or overwriting",
			Risk:           "Without versioning, deleted or overwritten objects cannot be recovered",
			RemediationText: "Enable versioning on the bucket to maintain object history",
			RemediationURL: "https://cloud.google.com/storage/docs/using-object-versioning",
			Categories:     []string{"storage", "backup"},
		},
	}
}

func (c *BucketVersioningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketVersioningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}
	storageService, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := storageService.Buckets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			hasVersioning := false
			if bucket.Versioning != nil && bucket.Versioning.Enabled {
				hasVersioning = true
			}
			status := models.StatusFail
			ext := "Bucket versioning is not enabled"
			if hasVersioning {
				status = models.StatusPass
				ext = "Bucket versioning is enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "storage",
				ResourceID:     bucket.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 4. BucketLoggingCheck ==========

type BucketLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewBucketLoggingCheck() *BucketLoggingCheck {
	return &BucketLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "storage_bucket_logging",
			CheckTitle:     "Storage bucket should have logging enabled",
			ServiceName:    "storage",
			Severity:       "medium",
			ResourceType:   "Bucket",
			Description:    "Storage buckets should have access logging enabled for audit and compliance",
			Risk:           "Without logging, access to bucket objects cannot be tracked or audited",
			RemediationText: "Enable access logging on the bucket to track object access",
			RemediationURL: "https://cloud.google.com/storage/docs/access-logs",
			Categories:     []string{"storage", "logging", "audit"},
		},
	}
}

func (c *BucketLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}
	storageService, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := storageService.Buckets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			hasLogging := false
			if bucket.Logging != nil && bucket.Logging.LogBucket != "" {
				hasLogging = true
			}
			status := models.StatusFail
			ext := "Bucket logging is not enabled"
			if hasLogging {
				status = models.StatusPass
				ext = "Bucket logging is enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "storage",
				ResourceID:     bucket.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ========== 5. BucketUniformAccessCheck ==========

type BucketUniformAccessCheck struct {
	metadata models.CheckMetadata
}

func NewBucketUniformAccessCheck() *BucketUniformAccessCheck {
	return &BucketUniformAccessCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "storage_bucket_uniform_access",
			CheckTitle:     "Storage bucket should have uniform bucket-level access enabled",
			ServiceName:    "storage",
			Severity:       "high",
			ResourceType:   "Bucket",
			Description:    "Storage buckets should use uniform bucket-level access for simplified and consistent permissions",
			Risk:           "Without uniform access, permissions are managed via ACLs which can lead to inconsistent access control",
			RemediationText: "Enable uniform bucket-level access on the bucket and migrate permissions to IAM",
			RemediationURL: "https://cloud.google.com/storage/docs/uniform-bucket-level-access",
			Categories:     []string{"storage", "iam", "access-control"},
		},
	}
}

func (c *BucketUniformAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketUniformAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}
	storageService, err := p.Storage(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := storageService.Buckets.List(p.ProjectID())
	err = req.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			hasUniformAccess := false
			if bucket.IamConfiguration != nil && bucket.IamConfiguration.UniformBucketLevelAccess != nil && bucket.IamConfiguration.UniformBucketLevelAccess.Enabled {
				hasUniformAccess = true
			}
			status := models.StatusFail
			ext := "Uniform bucket-level access is not enabled"
			if hasUniformAccess {
				status = models.StatusPass
				ext = "Uniform bucket-level access is enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "storage",
				ResourceID:     bucket.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}