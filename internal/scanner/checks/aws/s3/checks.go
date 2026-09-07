package s3

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
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

// BucketObjectLock - S3 bucket has Object Lock enabled
type BucketObjectLock struct {
	metadata models.CheckMetadata
}

func NewBucketObjectLock() *BucketObjectLock {
	return &BucketObjectLock{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_object_lock",
			CheckTitle:      "S3 bucket has Object Lock enabled",
			ServiceName:     "s3",
			Severity:        "low",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** have **Object Lock** enabled at the bucket level, applying WORM controls to object versions",
			RemediationText: "Enable **Object Lock** for critical data and set appropriate default retention in `GOVERNANCE` or `COMPLIANCE` mode. Apply **immutability** and **least privilege** by restricting permissions that bypass retention, and use legal holds when you need indefinite protection for investigations or regulatory requirements.",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketObjectLock) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketObjectLock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_object_lock
	_ = client

	return findings, nil
}

// BucketLevelPublicAccessBlock - S3 bucket has Block Public Access with IgnorePublicAcls and RestrictPublicBuckets enabled at bucket or account level
type BucketLevelPublicAccessBlock struct {
	metadata models.CheckMetadata
}

func NewBucketLevelPublicAccessBlock() *BucketLevelPublicAccessBlock {
	return &BucketLevelPublicAccessBlock{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_level_public_access_block",
			CheckTitle:      "S3 bucket has Block Public Access with IgnorePublicAcls and RestrictPublicBuckets enabled at bucket or account level",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are evaluated for **Block Public Access** settings, ensuring `ignore_public_acls` and `restrict_public_buckets` are enabled at the bucket or account scope. *Account-wide protections, when present, are treated as effective for the bucket.*",
			RemediationText: "Enable **Block Public Access** at account and bucket levels with `block_public_acls`, `ignore_public_acls`, `block_public_policy`, and `restrict_public_buckets` set to `true`. Apply **least privilege** and **defense in depth**. *If public access is required*, narrowly scope policies to fixed principals and conditions.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *BucketLevelPublicAccessBlock) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketLevelPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_level_public_access_block
	_ = client

	return findings, nil
}

// BucketLifecycleEnabled - S3 bucket has a lifecycle configuration enabled
type BucketLifecycleEnabled struct {
	metadata models.CheckMetadata
}

func NewBucketLifecycleEnabled() *BucketLifecycleEnabled {
	return &BucketLifecycleEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_lifecycle_enabled",
			CheckTitle:      "S3 bucket has a lifecycle configuration enabled",
			ServiceName:     "s3",
			Severity:        "low",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** use **Lifecycle configurations** with at least one rule `Status: Enabled` to automate object `Transitions` and `Expiration` based on age, prefix, or tags",
			RemediationText: "Define **Lifecycle policies** by data classification: set `Expiration` to enforce retention, use `Transitions` to lower-cost classes, and enable `AbortIncompleteMultipartUpload`. For critical logs, keep versioning and, *if required*, **Object Lock**. Limit who can change lifecycle using least privilege and separation of duties.",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketLifecycleEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketLifecycleEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_lifecycle_enabled
	_ = client

	return findings, nil
}

// BucketObjectVersioning - S3 bucket has object versioning enabled
type BucketObjectVersioning struct {
	metadata models.CheckMetadata
}

func NewBucketObjectVersioning() *BucketObjectVersioning {
	return &BucketObjectVersioning{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_object_versioning",
			CheckTitle:      "S3 bucket has object versioning enabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are evaluated for **object versioning** being `Enabled`, which maintains multiple versions of the same object key for historical state retention",
			RemediationText: "Enable **S3 versioning** for buckets holding important or shared data. - Enforce **least privilege** to limit delete/overwrite - Use **Object Lock** and/or **MFA Delete** for stronger protection - Apply **lifecycle rules** to manage noncurrent versions and costs - Layer with backups/replication for **defense in depth**",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketObjectVersioning) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketObjectVersioning) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_object_versioning
	_ = client

	return findings, nil
}

// BucketNoMfaDelete - S3 bucket has MFA Delete enabled
type BucketNoMfaDelete struct {
	metadata models.CheckMetadata
}

func NewBucketNoMfaDelete() *BucketNoMfaDelete {
	return &BucketNoMfaDelete{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_no_mfa_delete",
			CheckTitle:      "S3 bucket has MFA Delete enabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are assessed for **MFA Delete** status. MFA Delete requires a second factor to permanently delete object versions or change `Versioning` configuration. The finding highlights buckets where this protection is not enabled.",
			RemediationText: "Enable **MFA Delete** on sensitive, versioned buckets so permanent deletions and `Versioning` changes require a second factor. Apply **least privilege** to restrict version purge actions, enforce **change control**, and combine with **Object Lock** or immutable backups for defense in depth.",
			Categories:      []string{"s3", "iam"},
		},
	}
}

func (c *BucketNoMfaDelete) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketNoMfaDelete) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_no_mfa_delete
	_ = client

	return findings, nil
}

// BucketServerAccessLoggingEnabled - S3 bucket has server access logging enabled
type BucketServerAccessLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewBucketServerAccessLoggingEnabled() *BucketServerAccessLoggingEnabled {
	return &BucketServerAccessLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_server_access_logging_enabled",
			CheckTitle:      "S3 bucket has server access logging enabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are evaluated for **server access logging** configured to record access requests and deliver logs to a designated destination bucket.",
			RemediationText: "Enable **server access logging** and send logs to a dedicated log bucket with least privilege, retention, and monitoring. Complement with **CloudTrail data events** for object-level visibility. Apply **defense in depth** by centralizing logs and protecting them from tampering.",
			Categories:      []string{"s3", "logging"},
		},
	}
}

func (c *BucketServerAccessLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketServerAccessLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_server_access_logging_enabled
	_ = client

	return findings, nil
}

// BucketEventNotificationsEnabled - S3 bucket has event notifications enabled
type BucketEventNotificationsEnabled struct {
	metadata models.CheckMetadata
}

func NewBucketEventNotificationsEnabled() *BucketEventNotificationsEnabled {
	return &BucketEventNotificationsEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_event_notifications_enabled",
			CheckTitle:      "S3 bucket has event notifications enabled",
			ServiceName:     "s3",
			Severity:        "low",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** define a **notification configuration** that publishes bucket events (for example `s3:ObjectCreated:*`, `s3:ObjectRemoved:*`) to a destination. The evaluation identifies buckets that lack any notification setup.",
			RemediationText: "Enable **S3 event notifications** for relevant events (e.g., `s3:ObjectCreated:*`, `s3:ObjectRemoved:*`) and route to controlled destinations (SNS, SQS, Lambda, EventBridge). Use prefix/suffix filters, avoid recursive triggers, and enforce **least privilege** on targets. Pair with object-level logging for **defense in depth**.",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketEventNotificationsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketEventNotificationsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_event_notifications_enabled
	_ = client

	return findings, nil
}

// BucketPublicWriteAcl - S3 bucket ACL does not grant write access to Everyone or any AWS customer
type BucketPublicWriteAcl struct {
	metadata models.CheckMetadata
}

func NewBucketPublicWriteAcl() *BucketPublicWriteAcl {
	return &BucketPublicWriteAcl{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_public_write_acl",
			CheckTitle:      "S3 bucket ACL does not grant write access to Everyone or any AWS customer",
			ServiceName:     "s3",
			Severity:        "critical",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are assessed for ACL grants that allow **public write** access to `AllUsers` or `AuthenticatedUsers` via `WRITE`, `WRITE_ACP`, or `FULL_CONTROL`. Effective **Block Public Access** at account or bucket level (`ignore_public_acls`, `restrict_public_buckets`) is considered.",
			RemediationText: "Apply **least privilege** to S3 writes. Enable account-level **Block Public Access** and use **Object Ownership** to disable ACLs. Grant write only to fixed principals via bucket policies with tight conditions (e.g., org IDs, VPC endpoints). Add **versioning** and monitoring for defense-in-depth.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *BucketPublicWriteAcl) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketPublicWriteAcl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_public_write_acl
	_ = client

	return findings, nil
}

// AccountLevelPublicAccessBlocks - S3 account-level Block Public Access ignores public ACLs and restricts public buckets
type AccountLevelPublicAccessBlocks struct {
	metadata models.CheckMetadata
}

func NewAccountLevelPublicAccessBlocks() *AccountLevelPublicAccessBlocks {
	return &AccountLevelPublicAccessBlocks{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_account_level_public_access_blocks",
			CheckTitle:      "S3 account-level Block Public Access ignores public ACLs and restricts public buckets",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "AwsS3AccountPublicAccessBlock",
			Description:     "**Amazon S3** account-level **Block Public Access** is assessed for `ignore_public_acls` and `restrict_public_buckets` to confirm centralized blocking of ACL-based public access and limiting buckets with public policies to in-account principals.",
			RemediationText: "Turn on account-level **Block Public Access** (prefer enabling all four: `block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets`) to enforce least privilege. For legitimate access, use private buckets with **CloudFront**, VPC endpoints, or presigned URLs. Regularly review policies with IAM Access Analyzer.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *AccountLevelPublicAccessBlocks) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccountLevelPublicAccessBlocks) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_account_level_public_access_blocks
	_ = client

	return findings, nil
}

// AccessPointPublicAccessBlock - S3 access point has all Block Public Access settings enabled
type AccessPointPublicAccessBlock struct {
	metadata models.CheckMetadata
}

func NewAccessPointPublicAccessBlock() *AccessPointPublicAccessBlock {
	return &AccessPointPublicAccessBlock{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_access_point_public_access_block",
			CheckTitle:      "S3 access point has all Block Public Access settings enabled",
			ServiceName:     "s3",
			Severity:        "critical",
			ResourceType:    "AwsS3AccessPoint",
			Description:     "**Amazon S3 access points** have **Block Public Access** configured with all settings enabled: `block_public_acls`, `ignore_public_acls`, `block_public_policy`, and `restrict_public_buckets`. The evaluation inspects each access point's public access block configuration.",
			RemediationText: "Enable all access-point Block Public Access settings (`block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets`). Apply **least privilege**, prefer **VPC-only** access points, and layer account and bucket blocks for **defense in depth**. Regularly audit for public principals like `Principal: *`.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *AccessPointPublicAccessBlock) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessPointPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_access_point_public_access_block
	_ = client

	return findings, nil
}

// BucketAclProhibited - S3 bucket has bucket ACLs disabled
type BucketAclProhibited struct {
	metadata models.CheckMetadata
}

func NewBucketAclProhibited() *BucketAclProhibited {
	return &BucketAclProhibited{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_acl_prohibited",
			CheckTitle:      "S3 bucket has bucket ACLs disabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are evaluated for **Object Ownership** set to `BucketOwnerEnforced`, which disables bucket and object ACLs. Buckets using any other ownership setting indicate that ACLs remain enabled.",
			RemediationText: "Disable ACLs by setting **Object Ownership** to `BucketOwnerEnforced` and manage access with **IAM** and **bucket policies** under **least privilege**. Centralize authorization, review policies regularly, and use organizational guardrails to prevent re-enabling ACLs. *Migrate ACL-based grants into policies before the change.*",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketAclProhibited) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketAclProhibited) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_acl_prohibited
	_ = client

	return findings, nil
}

// BucketCrossRegionReplication - S3 bucket has cross-region replication configured to a bucket in a different region
type BucketCrossRegionReplication struct {
	metadata models.CheckMetadata
}

func NewBucketCrossRegionReplication() *BucketCrossRegionReplication {
	return &BucketCrossRegionReplication{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_cross_region_replication",
			CheckTitle:      "S3 bucket has cross-region replication configured to a bucket in a different region",
			ServiceName:     "s3",
			Severity:        "low",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** use **cross-Region replication** with `versioning` and an enabled rule that targets a destination bucket in a different AWS Region. Buckets with same-Region targets, missing destinations, or disabled `versioning` don't meet this replication posture.",
			RemediationText: "Enable **CRR** to a different Region with `versioning` and least-privilege roles. - Replicate needed prefixes and metadata - Consider `S3 Replication Time Control` for tighter RPO - Protect deletes via `delete marker` strategy and Object Lock - Monitor replication metrics and test DR regularly Align with **defense in depth** and availability by design.",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketCrossRegionReplication) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketCrossRegionReplication) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_cross_region_replication
	_ = client

	return findings, nil
}

// BucketDefaultEncryption - [DEPRECATED] S3 bucket has default server-side encryption (SSE) enabled
type BucketDefaultEncryption struct {
	metadata models.CheckMetadata
}

func NewBucketDefaultEncryption() *BucketDefaultEncryption {
	return &BucketDefaultEncryption{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_default_encryption",
			CheckTitle:      "[DEPRECATED] S3 bucket has default server-side encryption (SSE) enabled",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "[DEPRECATED] **Amazon S3 buckets** have a default **server-side encryption** setting that automatically encrypts new objects using `SSE-S3` or `SSE-KMS`. This evaluates whether a bucket has a default encryption configuration defined.",
			RemediationText: "Enable default encryption on all buckets, preferring `SSE-KMS` for sensitive data to retain key control and auditing. Enforce encryption with restrictive bucket policies, apply **least privilege** to KMS keys with rotation, and re-encrypt existing objects. Use **defense in depth** monitoring to detect drift and noncompliant uploads.",
			Categories:      []string{"s3", "encryption"},
		},
	}
}

func (c *BucketDefaultEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketDefaultEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_default_encryption
	_ = client

	return findings, nil
}

// BucketCrossAccountAccess - S3 bucket policy does not allow cross-account access
type BucketCrossAccountAccess struct {
	metadata models.CheckMetadata
}

func NewBucketCrossAccountAccess() *BucketCrossAccountAccess {
	return &BucketCrossAccountAccess{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_cross_account_access",
			CheckTitle:      "S3 bucket policy does not allow cross-account access",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 bucket policies** are analyzed for statements that grant **cross-account access**. Any policy that names principals outside the owning account (other account IDs or `Principal: \"*\"`) is treated as cross-account; absence of a policy implies no cross-account grants.",
			RemediationText: "Enforce **least privilege**: limit bucket policy `Principal` to your account or approved org IDs with fixed values; avoid wildcards. Use **role-based cross-account access** with scoped permissions when needed. Add **defense-in-depth** conditions (private networks, TLS), and periodically review for unintended external access.",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketCrossAccountAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_cross_account_access
	_ = client

	return findings, nil
}

// BucketObjectPublic - Spot-check S3 bucket objects for public ACLs
type BucketObjectPublic struct {
	metadata models.CheckMetadata
}

func NewBucketObjectPublic() *BucketObjectPublic {
	return &BucketObjectPublic{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_object_public",
			CheckTitle:      "Spot-check S3 bucket objects for public ACLs",
			ServiceName:     "s3",
			Severity:        "low",
			ResourceType:    "AwsS3Bucket",
			Description:     "Spot-checks a configurable sample of objects in each S3 bucket and flags any whose ACL grants access to the AllUsers or AuthenticatedUsers groups. This is a sampling-based check, not a comprehensive audit, so public objects outside the sample can be missed. It is disabled by default and must be enabled via the s3_bucket_object_public_enabled configuration flag.",
			RemediationText: "For complete coverage, enable the s3_bucket_acl_prohibited check, which enforces the BucketOwnerEnforced Object Ownership setting (AWS's recommended approach since April 2023) and prevents public object ACLs entirely. Use this spot-check as a supplementary tool for manual assessments.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *BucketObjectPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketObjectPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_object_public
	_ = client

	return findings, nil
}

// BucketSecureTransportPolicy - S3 bucket policy denies requests over insecure transport
type BucketSecureTransportPolicy struct {
	metadata models.CheckMetadata
}

func NewBucketSecureTransportPolicy() *BucketSecureTransportPolicy {
	return &BucketSecureTransportPolicy{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_secure_transport_policy",
			CheckTitle:      "S3 bucket policy denies requests over insecure transport",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are evaluated for a bucket policy that enforces **secure transport** by denying requests when `aws:SecureTransport` is `false`. Buckets without this explicit denial, or without a policy, are treated as allowing access over insecure transport.",
			RemediationText: "Enforce **HTTPS-only** access with a bucket policy that denies requests when `aws:SecureTransport=false`. Prefer **private access** (VPC endpoints or CloudFront with TLS), avoid S3 website endpoints, apply **least privilege**, use short-lived HTTPS **pre-signed URLs**, and monitor logs for insecure access attempts.",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketSecureTransportPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketSecureTransportPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_secure_transport_policy
	_ = client

	return findings, nil
}

// MultiRegionAccessPointPublicAccessBlock - S3 Multi-Region Access Point has all Block Public Access settings enabled
type MultiRegionAccessPointPublicAccessBlock struct {
	metadata models.CheckMetadata
}

func NewMultiRegionAccessPointPublicAccessBlock() *MultiRegionAccessPointPublicAccessBlock {
	return &MultiRegionAccessPointPublicAccessBlock{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_multi_region_access_point_public_access_block",
			CheckTitle:      "S3 Multi-Region Access Point has all Block Public Access settings enabled",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "AwsS3AccessPoint",
			Description:     "**Amazon S3 Multi-Region Access Points** are evaluated for **Block Public Access** being fully enabled (`block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets`). Focus is on the MRAP's own settings, separate from bucket or account configurations.",
			RemediationText: "Adopt **deny-by-default**: keep all MRAP **Block Public Access** settings enabled; avoid public ACLs or policies. - Enforce **least privilege** - Prefer private access (VPC endpoints) - Periodically review permissions and logs *MRAP public access settings are immutable after creation.*",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *MultiRegionAccessPointPublicAccessBlock) Metadata() models.CheckMetadata { return c.metadata }

func (c *MultiRegionAccessPointPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_multi_region_access_point_public_access_block
	_ = client

	return findings, nil
}

// BucketPolicyPublicWriteAccess - S3 bucket policy does not allow public write access
type BucketPolicyPublicWriteAccess struct {
	metadata models.CheckMetadata
}

func NewBucketPolicyPublicWriteAccess() *BucketPolicyPublicWriteAccess {
	return &BucketPolicyPublicWriteAccess{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_policy_public_write_access",
			CheckTitle:      "S3 bucket policy does not allow public write access",
			ServiceName:     "s3",
			Severity:        "critical",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 bucket policies** are evaluated for **public write permissions** (e.g., `s3:PutObject`, `s3:Delete*`, or `s3:*`). Account or bucket **Public Access Block** that restricts public buckets is considered when determining exposure.",
			RemediationText: "Restrict writes to trusted principals using **least privilege**; avoid `Principal: \"*\"`. Enable **Public Access Block** at account and bucket levels for defense in depth. Prefer IAM roles over broad bucket policies, require private access paths, and enable versioning to recover from unwanted changes.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *BucketPolicyPublicWriteAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketPolicyPublicWriteAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_policy_public_write_access
	_ = client

	return findings, nil
}

// BucketPublicListAcl - S3 bucket is not publicly listable by Everyone or any authenticated AWS user
type BucketPublicListAcl struct {
	metadata models.CheckMetadata
}

func NewBucketPublicListAcl() *BucketPublicListAcl {
	return &BucketPublicListAcl{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_public_list_acl",
			CheckTitle:      "S3 bucket is not publicly listable by Everyone or any authenticated AWS user",
			ServiceName:     "s3",
			Severity:        "critical",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** are evaluated for **public listing via ACLs**. Grants of `READ`, `READ_ACP`, or `FULL_CONTROL` to the `AllUsers` or `AuthenticatedUsers` groups are identified. Effective **Block Public Access** at account or bucket level (notably `IgnorePublicAcls` and `RestrictPublicBuckets`) is considered in the evaluation.",
			RemediationText: "Enable account-level **S3 Block Public Access** (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`). - Remove ACL grants to `AllUsers`/`AuthenticatedUsers`; apply **least privilege** with IAM/bucket policies. - Favor private patterns (VPC endpoints, CloudFront OAC, presigned URLs) and disable ACLs via Object Ownership.",
			Categories:      []string{"s3", "public_access"},
		},
	}
}

func (c *BucketPublicListAcl) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketPublicListAcl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_public_list_acl
	_ = client

	return findings, nil
}

// BucketShadowResourceVulnerability - S3 bucket is not a known shadow resource owned by another account
type BucketShadowResourceVulnerability struct {
	metadata models.CheckMetadata
}

func NewBucketShadowResourceVulnerability() *BucketShadowResourceVulnerability {
	return &BucketShadowResourceVulnerability{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_shadow_resource_vulnerability",
			CheckTitle:      "S3 bucket is not a known shadow resource owned by another account",
			ServiceName:     "s3",
			Severity:        "high",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** using **predictable service naming** (e.g., `aws-glue-assets-<account>-<region>`, `sagemaker-<region>-<account>`) are identified and their **ownership** checked. Buckets tied to your account that match these patterns but are owned by another account-across regions-are surfaced as shadow-resource candidates.",
			RemediationText: "Apply **defense in depth**: - **Preprovision and own** required service buckets in all current and planned regions - Enforce **least privilege** so services write only to approved bucket names/ARNs - Use **non-guessable names** where you control naming - Monitor for look-alike buckets and separate duties for bucket creation vs. use",
			Categories:      []string{"s3"},
		},
	}
}

func (c *BucketShadowResourceVulnerability) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketShadowResourceVulnerability) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_shadow_resource_vulnerability
	_ = client

	return findings, nil
}

// BucketKmsEncryption - S3 bucket has server-side encryption with AWS KMS
type BucketKmsEncryption struct {
	metadata models.CheckMetadata
}

func NewBucketKmsEncryption() *BucketKmsEncryption {
	return &BucketKmsEncryption{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "s3_bucket_kms_encryption",
			CheckTitle:      "S3 bucket has server-side encryption with AWS KMS",
			ServiceName:     "s3",
			Severity:        "medium",
			ResourceType:    "AwsS3Bucket",
			Description:     "**Amazon S3 buckets** use server-side encryption with **AWS KMS** keys, including dual-layer `aws:kms:dsse`. The evaluation identifies buckets whose default encryption is `aws:kms` or `aws:kms:dsse` rather than SSE-S3.",
			RemediationText: "Enable default **SSE-KMS** (or **DSSE-KMS** for highly sensitive data). Use a customer-managed key, enforce **least privilege** and separation of duties for key usage, and require KMS encryption via bucket policy (specify `aws:kms` and a designated key). Monitor key activity in **CloudTrail** and consider **S3 Bucket Keys** to control cost.",
			Categories:      []string{"s3", "encryption"},
		},
	}
}

func (c *BucketKmsEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketKmsEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for s3_bucket_kms_encryption
	_ = client

	return findings, nil
}
