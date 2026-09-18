package s3

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type s3Provider interface {
	S3(ctx context.Context) (*s3.Client, error)
}

// PublicAccessCheck - verifica se buckets são públicos
type PublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewPublicAccessCheck() *PublicAccessCheck {
	return &PublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_public_access",
			CheckTitle:      "S3 bucket should not be publicly accessible",
			ServiceName:     "s3",
			Severity:        "critical",
			ResourceType:    "Bucket",
			Description:     "S3 buckets should not be publicly accessible",
			RemediationText: "Enable S3 block public access",
			Categories:      []string{"s3", "storage"},
		},
	}
}

func (c *PublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	s3Client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// GetPublicAccessBlock
		pubBlock, err := s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			continue
		}

		isPublic := true
		if pubBlock.PublicAccessBlockConfiguration != nil {
			isPublic = !aws.ToBool(pubBlock.PublicAccessBlockConfiguration.BlockPublicAcls) ||
				!aws.ToBool(pubBlock.PublicAccessBlockConfiguration.BlockPublicPolicy)
		}

		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s has public access blocked", bucketName)
		if isPublic {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s does not have public access fully blocked", bucketName)
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "s3",
			ResourceID:      bucketName,
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// EncryptionCheck - verifica criptografia
type EncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewEncryptionCheck() *EncryptionCheck {
	return &EncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_encryption",
			CheckTitle:      "S3 bucket should have encryption enabled",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "Bucket",
			Description:     "S3 buckets should have encryption enabled",
			RemediationText: "Enable S3 bucket encryption",
			Categories:      []string{"s3", "encryption"},
		},
	}
}

func (c *EncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	s3Client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		enc, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          models.StatusFail,
				StatusExtended:  fmt.Sprintf("Bucket %s does not have encryption enabled", bucketName),
				Provider:        "aws",
				Service:         "s3",
				ResourceID:      bucketName,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
			continue
		}

		hasEncryption := enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0

		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s has encryption enabled", bucketName)
		if !hasEncryption {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s does not have encryption enabled", bucketName)
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "s3",
			ResourceID:      bucketName,
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// VersioningCheck - verifica versioning
type VersioningCheck struct {
	metadata models.CheckMetadata
}

func NewVersioningCheck() *VersioningCheck {
	return &VersioningCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_versioning",
			CheckTitle:      "S3 bucket should have versioning enabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "Bucket",
			Description:     "S3 buckets should have versioning enabled",
			RemediationText: "Enable S3 bucket versioning",
			Categories:      []string{"s3", "data-protection"},
		},
	}
}

func (c *VersioningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VersioningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	s3Client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		versioning, err := s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			continue
		}

		versioned := versioning.Status == "Enabled"

		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s has versioning enabled", bucketName)
		if !versioned {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s does not have versioning enabled", bucketName)
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "s3",
			ResourceID:      bucketName,
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// LoggingCheck - verifica logging
type LoggingCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingCheck() *LoggingCheck {
	return &LoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_logging",
			CheckTitle:      "S3 bucket should have logging enabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "Bucket",
			Description:     "S3 buckets should have logging enabled",
			RemediationText: "Enable S3 bucket logging",
			Categories:      []string{"s3", "logging"},
		},
	}
}

func (c *LoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	s3Client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		logging, err := s3Client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			continue
		}

		hasLogging := logging.LoggingEnabled != nil

		status := models.StatusPass
		ext := fmt.Sprintf("Bucket %s has logging enabled", bucketName)
		if !hasLogging {
			status = models.StatusFail
			ext = fmt.Sprintf("Bucket %s does not have logging enabled", bucketName)
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "s3",
			ResourceID:      bucketName,
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// BlockPublicAccessCheck - verifica block public access a nível de conta
type BlockPublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewBlockPublicAccessCheck() *BlockPublicAccessCheck {
	return &BlockPublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_account_block_public_access",
			CheckTitle:      "S3 account should have block public access enabled",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "Account",
			Description:     "S3 account should have block public access enabled",
			RemediationText: "Enable S3 block public access at account level",
			Categories:      []string{"s3", "security"},
		},
	}
}

func (c *BlockPublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BlockPublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	s3Client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// GetPublicAccessBlock a nível de conta (usando um bucket qualquer para verificar)
	buckets, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar buckets: %w", err)
	}

	if len(buckets.Buckets) == 0 {
		return findings, nil
	}

	bucketName := aws.ToString(buckets.Buckets[0].Name)

	pubBlock, err := s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          models.StatusFail,
			StatusExtended:  "S3 block public access is not configured",
			Provider:        "aws",
			Service:         "s3",
			ResourceID:      "account",
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
		return findings, nil
	}

	blockEnabled := pubBlock.PublicAccessBlockConfiguration != nil &&
		aws.ToBool(pubBlock.PublicAccessBlockConfiguration.BlockPublicAcls) &&
		aws.ToBool(pubBlock.PublicAccessBlockConfiguration.BlockPublicPolicy) &&
		aws.ToBool(pubBlock.PublicAccessBlockConfiguration.IgnorePublicAcls) &&
		aws.ToBool(pubBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets)

	status := models.StatusPass
	ext := "S3 block public access is fully enabled"
	if !blockEnabled {
		status = models.StatusFail
		ext = "S3 block public access is not fully enabled"
	}

	findings = append(findings, models.Finding{
		ID:              c.metadata.CheckID,
		Title:           c.metadata.CheckTitle,
		Description:     c.metadata.Description,
		Severity:        c.metadata.Severity,
		Status:          status,
		StatusExtended:  ext,
		Provider:        "aws",
		Service:         "s3",
		ResourceID:      "account",
		Remediation:     c.metadata.RemediationText,
		Categories:      c.metadata.Categories,
		FoundAt:         time.Now(),
	})

	return findings, nil
}
