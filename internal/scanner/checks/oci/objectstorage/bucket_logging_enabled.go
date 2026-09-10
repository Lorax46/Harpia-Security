package objectstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

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
		NamespaceName: common.String(namespace),
		CompartmentId: &tenancyId,
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

		if details.ObjectEventsEnabled != nil && *details.ObjectEventsEnabled {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Bucket %s has object events enabled (logging)", *bucket.Name),
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
				StatusExtended: fmt.Sprintf("Bucket %s does not have object events enabled (logging)", *bucket.Name),
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
