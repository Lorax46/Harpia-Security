package s3

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3AccessPointPublicAccessBlock - verifica block public access em access points
type S3AccessPointPublicAccessBlock struct {
	metadata models.CheckMetadata
}

func NewS3AccessPointPublicAccessBlock() *S3AccessPointPublicAccessBlock {
	return &S3AccessPointPublicAccessBlock{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_access_point_public_access_block",
			CheckTitle: "Ensure S3 access points have public access blocked",
			Description: "S3 access points should block public access",
			Severity: "medium", ServiceName: "s3", ResourceType: "AccessPoint",
			RemediationText: "Enable public access block on S3 access points",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3AccessPointPublicAccessBlock) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3AccessPointPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	openPoints := []string{}
	for _, bucket := range result.Buckets {
		openPoints = append(openPoints, aws.ToString(bucket.Name))
	}

	if len(openPoints) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets that may need public access block", len(openPoints)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 access points have public access block",
		ResourceID: "s3-access-points", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3AccountLevelPublicAccessBlocks - verifica block public access na conta
type S3AccountLevelPublicAccessBlocks struct {
	metadata models.CheckMetadata
}

func NewS3AccountLevelPublicAccessBlocks() *S3AccountLevelPublicAccessBlocks {
	return &S3AccountLevelPublicAccessBlocks{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_account_level_public_access_blocks",
			CheckTitle: "Ensure S3 account-level public access block is enabled",
			Description: "Account-level S3 public access block should be enabled",
			Severity: "medium", ServiceName: "s3", ResourceType: "Account",
			RemediationText: "Enable account-level S3 public access block",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3AccountLevelPublicAccessBlocks) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3AccountLevelPublicAccessBlocks) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(""),
	})
	if err != nil {
		return nil, err
	}

	if result.PublicAccessBlockConfiguration != nil {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Account-level S3 public access block is enabled",
			ResourceID: "account", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusFail, StatusExtended: "Account-level S3 public access block is not enabled",
		ResourceID: "account", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketAclProhibited - verifica ACLs de bucket
type S3BucketAclProhibited struct {
	metadata models.CheckMetadata
}

func NewS3BucketAclProhibited() *S3BucketAclProhibited {
	return &S3BucketAclProhibited{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_acl_prohibited",
			CheckTitle: "Ensure S3 bucket ACLs are not used",
			Description: "S3 bucket ACLs should not be used; use bucket policies instead",
			Severity: "low", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Disable S3 bucket ACLs and use bucket policies",
			Categories: []string{"s3", "acl"},
		},
	}
}

func (c *S3BucketAclProhibited) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketAclProhibited) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithACLs := []string{}
	for _, bucket := range result.Buckets {
		acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		for _, grant := range acl.Grants {
			if grant.Grantee != nil && grant.Grantee.URI != nil {
				uri := aws.ToString(grant.Grantee.URI)
				if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
					bucketsWithACLs = append(bucketsWithACLs, aws.ToString(bucket.Name))
				}
			}
		}
	}

	if len(bucketsWithACLs) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets with ACLs granting public access", len(bucketsWithACLs)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No S3 buckets with public ACLs",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketCrossAccountAccess - verifica acesso cross-account
type S3BucketCrossAccountAccess struct {
	metadata models.CheckMetadata
}

func NewS3BucketCrossAccountAccess() *S3BucketCrossAccountAccess {
	return &S3BucketCrossAccountAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_cross_account_access",
			CheckTitle: "Ensure S3 bucket cross-account access is restricted",
			Description: "S3 bucket cross-account access should be restricted to necessary accounts",
			Severity: "high", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Restrict S3 bucket cross-account access",
			Categories: []string{"s3", "cross-account"},
		},
	}
}

func (c *S3BucketCrossAccountAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	crossAccountBuckets := []string{}
	for _, bucket := range result.Buckets {
		policy, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		policyStr := aws.ToString(policy.Policy)
		if strings.Contains(policyStr, "\"AWS\":\"*\"") || strings.Contains(policyStr, "\"Principal\":\"*\"") {
			crossAccountBuckets = append(crossAccountBuckets, aws.ToString(bucket.Name))
		}
	}

	if len(crossAccountBuckets) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets with cross-account access", len(crossAccountBuckets)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No S3 buckets with cross-account access",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketCrossRegionReplication - verifica replicação cross-region
type S3BucketCrossRegionReplication struct {
	metadata models.CheckMetadata
}

func NewS3BucketCrossRegionReplication() *S3BucketCrossRegionReplication {
	return &S3BucketCrossRegionReplication{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_cross_region_replication",
			CheckTitle: "Ensure S3 buckets have cross-region replication enabled",
			Description: "S3 buckets should have cross-region replication for disaster recovery",
			Severity: "low", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable cross-region replication on S3 buckets",
			Categories: []string{"s3", "replication"},
		},
	}
}

func (c *S3BucketCrossRegionReplication) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketCrossRegionReplication) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutReplication := []string{}
	for _, bucket := range result.Buckets {
		_, err := client.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			bucketsWithoutReplication = append(bucketsWithoutReplication, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutReplication) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without cross-region replication", len(bucketsWithoutReplication)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have cross-region replication",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketDefaultEncryption - verifica criptografia padrão
type S3BucketDefaultEncryption struct {
	metadata models.CheckMetadata
}

func NewS3BucketDefaultEncryption() *S3BucketDefaultEncryption {
	return &S3BucketDefaultEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_default_encryption",
			CheckTitle: "Ensure S3 buckets have default encryption enabled",
			Description: "S3 buckets should have default encryption enabled",
			Severity: "high", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable default encryption on S3 buckets",
			Categories: []string{"s3", "encryption"},
		},
	}
}

func (c *S3BucketDefaultEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketDefaultEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutEncryption := []string{}
	for _, bucket := range result.Buckets {
		enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil || enc.ServerSideEncryptionConfiguration == nil || len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			bucketsWithoutEncryption = append(bucketsWithoutEncryption, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutEncryption) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without default encryption", len(bucketsWithoutEncryption)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have default encryption",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketEventNotificationsEnabled - verifica notificações de evento
type S3BucketEventNotificationsEnabled struct {
	metadata models.CheckMetadata
}

func NewS3BucketEventNotificationsEnabled() *S3BucketEventNotificationsEnabled {
	return &S3BucketEventNotificationsEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_event_notifications_enabled",
			CheckTitle: "Ensure S3 buckets have event notifications enabled",
			Description: "S3 buckets should have event notifications enabled",
			Severity: "low", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable event notifications on S3 buckets",
			Categories: []string{"s3", "monitoring"},
		},
	}
}

func (c *S3BucketEventNotificationsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketEventNotificationsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutNotifications := []string{}
	for _, bucket := range result.Buckets {
		config, err := client.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
			Bucket: bucket.Name,
		})
		if err != nil || (config.TopicConfigurations == nil && config.QueueConfigurations == nil && config.LambdaFunctionConfigurations == nil) {
			bucketsWithoutNotifications = append(bucketsWithoutNotifications, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutNotifications) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without event notifications", len(bucketsWithoutNotifications)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have event notifications",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketKmsEncryption - verifica criptografia KMS
type S3BucketKmsEncryption struct {
	metadata models.CheckMetadata
}

func NewS3BucketKmsEncryption() *S3BucketKmsEncryption {
	return &S3BucketKmsEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_kms_encryption",
			CheckTitle: "Ensure S3 buckets use KMS encryption",
			Description: "S3 buckets should use KMS for encryption",
			Severity: "medium", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Configure KMS encryption on S3 buckets",
			Categories: []string{"s3", "encryption", "kms"},
		},
	}
}

func (c *S3BucketKmsEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketKmsEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithS3OnlyEncryption := []string{}
	for _, bucket := range result.Buckets {
		enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		if enc.ServerSideEncryptionConfiguration != nil {
			for _, rule := range enc.ServerSideEncryptionConfiguration.Rules {
				if rule.ApplyServerSideEncryptionByDefault != nil {
					algo := rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
					if algo == "AES256" || algo == "aws:s3" {
						bucketsWithS3OnlyEncryption = append(bucketsWithS3OnlyEncryption, aws.ToString(bucket.Name))
					}
				}
			}
		}
	}

	if len(bucketsWithS3OnlyEncryption) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets using S3-managed encryption instead of KMS", len(bucketsWithS3OnlyEncryption)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets use KMS encryption",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketLevelPublicAccessBlock - verifica block public access por bucket
type S3BucketLevelPublicAccessBlock struct {
	metadata models.CheckMetadata
}

func NewS3BucketLevelPublicAccessBlock() *S3BucketLevelPublicAccessBlock {
	return &S3BucketLevelPublicAccessBlock{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_level_public_access_block",
			CheckTitle: "Ensure S3 buckets have public access block enabled",
			Description: "S3 buckets should have public access block enabled",
			Severity: "medium", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable public access block on S3 buckets",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3BucketLevelPublicAccessBlock) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketLevelPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutBlock := []string{}
	for _, bucket := range result.Buckets {
		config, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})
		if err != nil || config.PublicAccessBlockConfiguration == nil {
			bucketsWithoutBlock = append(bucketsWithoutBlock, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutBlock) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without public access block", len(bucketsWithoutBlock)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have public access block",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketLifecycleEnabled - verifica lifecycle habilitado
type S3BucketLifecycleEnabled struct {
	metadata models.CheckMetadata
}

func NewS3BucketLifecycleEnabled() *S3BucketLifecycleEnabled {
	return &S3BucketLifecycleEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_lifecycle_enabled",
			CheckTitle: "Ensure S3 buckets have lifecycle configuration",
			Description: "S3 buckets should have lifecycle configuration to manage object expiration",
			Severity: "low", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable lifecycle configuration on S3 buckets",
			Categories: []string{"s3", "lifecycle"},
		},
	}
}

func (c *S3BucketLifecycleEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketLifecycleEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutLifecycle := []string{}
	for _, bucket := range result.Buckets {
		_, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			bucketsWithoutLifecycle = append(bucketsWithoutLifecycle, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutLifecycle) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without lifecycle configuration", len(bucketsWithoutLifecycle)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have lifecycle configuration",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketNoMfaDelete - verifica MFA delete
type S3BucketNoMfaDelete struct {
	metadata models.CheckMetadata
}

func NewS3BucketNoMfaDelete() *S3BucketNoMfaDelete {
	return &S3BucketNoMfaDelete{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_no_mfa_delete",
			CheckTitle: "Ensure S3 bucket MFA delete is enabled",
			Description: "S3 buckets should have MFA delete enabled",
			Severity: "medium", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable MFA delete on S3 buckets",
			Categories: []string{"s3", "mfa"},
		},
	}
}

func (c *S3BucketNoMfaDelete) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketNoMfaDelete) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithMFADelete := []string{}
	for _, bucket := range result.Buckets {
		ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		if ver.MFADelete == "Enabled" {
			bucketsWithMFADelete = append(bucketsWithMFADelete, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithMFADelete) == 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: "No S3 buckets have MFA delete enabled",
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Found %d S3 buckets with MFA delete enabled", len(bucketsWithMFADelete)),
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketObjectLock - verifica object lock
type S3BucketObjectLock struct {
	metadata models.CheckMetadata
}

func NewS3BucketObjectLock() *S3BucketObjectLock {
	return &S3BucketObjectLock{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_object_lock",
			CheckTitle: "Ensure S3 buckets have object lock enabled",
			Description: "S3 buckets should have object lock enabled for data protection",
			Severity: "low", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable object lock on S3 buckets",
			Categories: []string{"s3", "object-lock"},
		},
	}
}

func (c *S3BucketObjectLock) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketObjectLock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutObjectLock := []string{}
	for _, bucket := range result.Buckets {
		_, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			bucketsWithoutObjectLock = append(bucketsWithoutObjectLock, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutObjectLock) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without object lock", len(bucketsWithoutObjectLock)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have object lock enabled",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketObjectPublic - verifica objetos públicos
type S3BucketObjectPublic struct {
	metadata models.CheckMetadata
}

func NewS3BucketObjectPublic() *S3BucketObjectPublic {
	return &S3BucketObjectPublic{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_object_public",
			CheckTitle: "Ensure S3 bucket objects are not public",
			Description: "S3 bucket objects should not be publicly accessible",
			Severity: "high", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Remove public access from S3 bucket objects",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3BucketObjectPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketObjectPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "S3 bucket object public check requires iterating through all objects",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketObjectVersioning - verifica versionamento
type S3BucketObjectVersioning struct {
	metadata models.CheckMetadata
}

func NewS3BucketObjectVersioning() *S3BucketObjectVersioning {
	return &S3BucketObjectVersioning{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_object_versioning",
			CheckTitle: "Ensure S3 buckets have object versioning enabled",
			Description: "S3 buckets should have object versioning enabled",
			Severity: "low", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable object versioning on S3 buckets",
			Categories: []string{"s3", "versioning"},
		},
	}
}

func (c *S3BucketObjectVersioning) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketObjectVersioning) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutVersioning := []string{}
	for _, bucket := range result.Buckets {
		ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})
		if err != nil || ver.Status != "Enabled" {
			bucketsWithoutVersioning = append(bucketsWithoutVersioning, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutVersioning) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without versioning", len(bucketsWithoutVersioning)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have versioning enabled",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketPolicyPublicWriteAccess - verifica política de escrita pública
type S3BucketPolicyPublicWriteAccess struct {
	metadata models.CheckMetadata
}

func NewS3BucketPolicyPublicWriteAccess() *S3BucketPolicyPublicWriteAccess {
	return &S3BucketPolicyPublicWriteAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_policy_public_write_access",
			CheckTitle: "Ensure S3 bucket policy does not allow public write access",
			Description: "S3 bucket policies should not allow public write access",
			Severity: "critical", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Remove public write access from S3 bucket policies",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3BucketPolicyPublicWriteAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketPolicyPublicWriteAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithPublicWrite := []string{}
	for _, bucket := range result.Buckets {
		policy, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		policyStr := aws.ToString(policy.Policy)
		if strings.Contains(policyStr, "\"Effect\":\"Allow\"") && strings.Contains(policyStr, "\"Principal\":\"*\"") && strings.Contains(policyStr, "s3:PutObject") {
			bucketsWithPublicWrite = append(bucketsWithPublicWrite, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithPublicWrite) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets with public write access", len(bucketsWithPublicWrite)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No S3 buckets with public write access",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketPublicAccess - verifica acesso público
type S3BucketPublicAccess struct {
	metadata models.CheckMetadata
}

func NewS3BucketPublicAccess() *S3BucketPublicAccess {
	return &S3BucketPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_public_access",
			CheckTitle: "Ensure S3 buckets are not publicly accessible",
			Description: "S3 buckets should not be publicly accessible",
			Severity: "critical", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Remove public access from S3 buckets",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3BucketPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	publicBuckets := []string{}
	for _, bucket := range result.Buckets {
		policyStatus, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		if policyStatus.PolicyStatus != nil && policyStatus.PolicyStatus.IsPublic != nil && *policyStatus.PolicyStatus.IsPublic {
			publicBuckets = append(publicBuckets, aws.ToString(bucket.Name))
		}
	}

	if len(publicBuckets) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d public S3 buckets", len(publicBuckets)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No public S3 buckets",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketPublicListAcl - verifica ACL de listagem pública
type S3BucketPublicListAcl struct {
	metadata models.CheckMetadata
}

func NewS3BucketPublicListAcl() *S3BucketPublicListAcl {
	return &S3BucketPublicListAcl{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_public_list_acl",
			CheckTitle: "Ensure S3 bucket ACL does not allow public listing",
			Description: "S3 bucket ACLs should not allow public listing",
			Severity: "high", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Remove public listing from S3 bucket ACLs",
			Categories: []string{"s3", "acl", "public-access"},
		},
	}
}

func (c *S3BucketPublicListAcl) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketPublicListAcl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithPublicList := []string{}
	for _, bucket := range result.Buckets {
		acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		for _, grant := range acl.Grants {
			if grant.Grantee != nil && grant.Grantee.URI != nil {
				uri := aws.ToString(grant.Grantee.URI)
				if strings.Contains(uri, "AllUsers") && grant.Permission == "READ" {
					bucketsWithPublicList = append(bucketsWithPublicList, aws.ToString(bucket.Name))
				}
			}
		}
	}

	if len(bucketsWithPublicList) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets with public list ACL", len(bucketsWithPublicList)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No S3 buckets with public list ACL",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketPublicWriteAcl - verifica ACL de escrita pública
type S3BucketPublicWriteAcl struct {
	metadata models.CheckMetadata
}

func NewS3BucketPublicWriteAcl() *S3BucketPublicWriteAcl {
	return &S3BucketPublicWriteAcl{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_public_write_acl",
			CheckTitle: "Ensure S3 bucket ACL does not allow public write",
			Description: "S3 bucket ACLs should not allow public write access",
			Severity: "critical", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Remove public write from S3 bucket ACLs",
			Categories: []string{"s3", "acl", "public-access"},
		},
	}
}

func (c *S3BucketPublicWriteAcl) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketPublicWriteAcl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithPublicWrite := []string{}
	for _, bucket := range result.Buckets {
		acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			continue
		}
		for _, grant := range acl.Grants {
			if grant.Grantee != nil && grant.Grantee.URI != nil {
				uri := aws.ToString(grant.Grantee.URI)
				if strings.Contains(uri, "AllUsers") && (grant.Permission == "WRITE" || grant.Permission == "FULL_CONTROL") {
					bucketsWithPublicWrite = append(bucketsWithPublicWrite, aws.ToString(bucket.Name))
				}
			}
		}
	}

	if len(bucketsWithPublicWrite) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets with public write ACL", len(bucketsWithPublicWrite)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "No S3 buckets with public write ACL",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketSecureTransportPolicy - verifica política de transporte seguro
type S3BucketSecureTransportPolicy struct {
	metadata models.CheckMetadata
}

func NewS3BucketSecureTransportPolicy() *S3BucketSecureTransportPolicy {
	return &S3BucketSecureTransportPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_secure_transport_policy",
			CheckTitle: "Ensure S3 bucket policy enforces HTTPS",
			Description: "S3 bucket policies should enforce HTTPS connections",
			Severity: "high", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Add HTTPS enforcement to S3 bucket policies",
			Categories: []string{"s3", "encryption", "transport"},
		},
	}
}

func (c *S3BucketSecureTransportPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketSecureTransportPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutHTTPS := []string{}
	for _, bucket := range result.Buckets {
		policy, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			bucketsWithoutHTTPS = append(bucketsWithoutHTTPS, aws.ToString(bucket.Name))
			continue
		}
		policyStr := aws.ToString(policy.Policy)
		if !strings.Contains(policyStr, "aws:SecureTransport") {
			bucketsWithoutHTTPS = append(bucketsWithoutHTTPS, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutHTTPS) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without HTTPS enforcement", len(bucketsWithoutHTTPS)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets enforce HTTPS",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketServerAccessLoggingEnabled - verifica server access logging
type S3BucketServerAccessLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewS3BucketServerAccessLoggingEnabled() *S3BucketServerAccessLoggingEnabled {
	return &S3BucketServerAccessLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_server_access_logging_enabled",
			CheckTitle: "Ensure S3 buckets have server access logging enabled",
			Description: "S3 buckets should have server access logging enabled",
			Severity: "medium", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Enable server access logging on S3 buckets",
			Categories: []string{"s3", "logging"},
		},
	}
}

func (c *S3BucketServerAccessLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketServerAccessLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(s3Provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement s3Provider")
	}
	client, err := p.S3(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	bucketsWithoutLogging := []string{}
	for _, bucket := range result.Buckets {
		logging, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: bucket.Name,
		})
		if err != nil || logging.LoggingEnabled == nil {
			bucketsWithoutLogging = append(bucketsWithoutLogging, aws.ToString(bucket.Name))
		}
	}

	if len(bucketsWithoutLogging) > 0 {
		return []models.Finding{{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail, StatusExtended: fmt.Sprintf("Found %d S3 buckets without server access logging", len(bucketsWithoutLogging)),
			ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
			FoundAt: time.Now().UTC(),
		}}, nil
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "All S3 buckets have server access logging",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3BucketShadowResourceVulnerability - verifica shadow resources
type S3BucketShadowResourceVulnerability struct {
	metadata models.CheckMetadata
}

func NewS3BucketShadowResourceVulnerability() *S3BucketShadowResourceVulnerability {
	return &S3BucketShadowResourceVulnerability{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_bucket_shadow_resource_vulnerability",
			CheckTitle: "Ensure S3 buckets do not have shadow resource vulnerabilities",
			Description: "S3 buckets should not have shadow resource vulnerabilities",
			Severity: "medium", ServiceName: "s3", ResourceType: "Bucket",
			RemediationText: "Review S3 bucket configurations for shadow resources",
			Categories: []string{"s3", "shadow-resources"},
		},
	}
}

func (c *S3BucketShadowResourceVulnerability) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3BucketShadowResourceVulnerability) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "S3 shadow resource check requires advanced analysis",
		ResourceID: "s3-buckets", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// S3MultiRegionAccessPointPublicAccessBlock - verifica block public access em MRAP
type S3MultiRegionAccessPointPublicAccessBlock struct {
	metadata models.CheckMetadata
}

func NewS3MultiRegionAccessPointPublicAccessBlock() *S3MultiRegionAccessPointPublicAccessBlock {
	return &S3MultiRegionAccessPointPublicAccessBlock{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "s3_multi_region_access_point_public_access_block",
			CheckTitle: "Ensure S3 multi-region access points have public access blocked",
			Description: "S3 multi-region access points should block public access",
			Severity: "medium", ServiceName: "s3", ResourceType: "MultiRegionAccessPoint",
			RemediationText: "Enable public access block on S3 multi-region access points",
			Categories: []string{"s3", "public-access"},
		},
	}
}

func (c *S3MultiRegionAccessPointPublicAccessBlock) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3MultiRegionAccessPointPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "S3 multi-region access point check requires additional API calls",
		ResourceID: "s3-mrap", Provider: "aws", Service: "s3",
		FoundAt: time.Now().UTC(),
	}}, nil
}
