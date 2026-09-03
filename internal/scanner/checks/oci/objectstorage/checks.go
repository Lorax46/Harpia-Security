package objectstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
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
			Description:     "Object storage buckets should not be publicly accessible",
			RemediationText: "Set bucket visibility to private",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketNotPubliclyAccessibleCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketNotPubliclyAccessibleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		ObjectStore() (objectstorage.ObjectStorageClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa ObjectStore()")
	}

	client, err := p.ObjectStore()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	nsReq := objectstorage.GetNamespaceRequest{
		CompartmentId: &tenancyId,
	}
	nsResp, err := client.GetNamespace(ctx, nsReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter namespace: %w", err)
	}

	namespace := *nsResp.Value

	req := objectstorage.ListBucketsRequest{
		NamespaceName:  common.String(namespace),
		CompartmentId:  &tenancyId,
	}
	
	buckets, err := client.ListBuckets(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		getReq := objectstorage.GetBucketRequest{
			NamespaceName: common.String(namespace),
			BucketName:    common.String(*bucket.Name),
		}
		details, err := client.GetBucket(ctx, getReq)
		if err != nil {
			continue
		}

		if details.PublicAccessType == objectstorage.BucketPublicAccessTypeObjectread {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Bucket %s is publicly accessible", *bucket.Name),
				ResourceID:     *details.Id,
				Provider:       "oci",
				Service:        "objectstorage",
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
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Bucket %s is private", *bucket.Name),
				ResourceID:     *details.Id,
				Provider:       "oci",
				Service:        "objectstorage",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No buckets found",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
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
			Description:     "Object storage buckets should have logging enabled",
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
			StatusExtended: "Check requires implementation - use ListBuckets with logging details",
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
			Description:     "Object storage buckets should have versioning enabled for data protection",
			RemediationText: "Enable versioning for object storage buckets",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketVersioningEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketVersioningEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		ObjectStore() (objectstorage.ObjectStorageClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa ObjectStore()")
	}

	client, err := p.ObjectStore()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	nsReq := objectstorage.GetNamespaceRequest{
		CompartmentId: &tenancyId,
	}
	nsResp, err := client.GetNamespace(ctx, nsReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter namespace: %w", err)
	}

	namespace := *nsResp.Value

	req := objectstorage.ListBucketsRequest{
		NamespaceName:  common.String(namespace),
		CompartmentId:  &tenancyId,
	}
	
	buckets, err := client.ListBuckets(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		getReq := objectstorage.GetBucketRequest{
			NamespaceName: common.String(namespace),
			BucketName:    common.String(*bucket.Name),
		}
		details, err := client.GetBucket(ctx, getReq)
		if err != nil {
			continue
		}

		if details.Versioning == objectstorage.BucketVersioningEnabled {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Bucket %s has versioning enabled", *bucket.Name),
				ResourceID:     *details.Id,
				Provider:       "oci",
				Service:        "objectstorage",
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
				StatusExtended: fmt.Sprintf("Bucket %s has versioning %s", *bucket.Name, string(details.Versioning)),
				ResourceID:     *details.Id,
				Provider:       "oci",
				Service:        "objectstorage",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No buckets found",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
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
			Description:     "Object storage buckets should be encrypted with customer managed keys",
			RemediationText: "Use CMK for bucket encryption",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BucketEncryptedWithCmkCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BucketEncryptedWithCmkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		ObjectStore() (objectstorage.ObjectStorageClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa ObjectStore()")
	}

	client, err := p.ObjectStore()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	nsReq := objectstorage.GetNamespaceRequest{
		CompartmentId: &tenancyId,
	}
	nsResp, err := client.GetNamespace(ctx, nsReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter namespace: %w", err)
	}

	namespace := *nsResp.Value

	req := objectstorage.ListBucketsRequest{
		NamespaceName:  common.String(namespace),
		CompartmentId:  &tenancyId,
	}
	
	buckets, err := client.ListBuckets(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Items {
		getReq := objectstorage.GetBucketRequest{
			NamespaceName: common.String(namespace),
			BucketName:    common.String(*bucket.Name),
		}
		details, err := client.GetBucket(ctx, getReq)
		if err != nil {
			continue
		}

		if details.KmsKeyId != nil && *details.KmsKeyId != "" {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Bucket %s uses CMK for encryption", *bucket.Name),
				ResourceID:     *details.Id,
				Provider:       "oci",
				Service:        "objectstorage",
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
				StatusExtended: fmt.Sprintf("Bucket %s uses Oracle managed keys (no CMK)", *bucket.Name),
				ResourceID:     *details.Id,
				Provider:       "oci",
				Service:        "objectstorage",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No buckets found",
			Provider:       "oci",
			Service:        "objectstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
