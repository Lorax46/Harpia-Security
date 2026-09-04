package s3

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// S3BucketObjectLock - S3 bucket has Object Lock enabled
type S3BucketObjectLock struct {
    metadata models.CheckMetadata
}

func NewS3BucketObjectLock() *S3BucketObjectLock {
    return &S3BucketObjectLock{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_object_lock",
            CheckTitle: "S3 bucket has Object Lock enabled",
            ServiceName: "s3",
            Severity: "low",
            Description: "**Amazon S3 buckets** have **Object Lock** enabled at the bucket level, applying WORM controls to object versions",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketObjectLock) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketObjectLock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketLevelPublicAccessBlock - S3 bucket has Block Public Access with IgnorePublicAcls and RestrictPublicBuckets enabled at bucket or account level
type S3BucketLevelPublicAccessBlock struct {
    metadata models.CheckMetadata
}

func NewS3BucketLevelPublicAccessBlock() *S3BucketLevelPublicAccessBlock {
    return &S3BucketLevelPublicAccessBlock{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_level_public_access_block",
            CheckTitle: "S3 bucket has Block Public Access with IgnorePublicAcls and RestrictPublicBuckets enabled at bucket or account level",
            ServiceName: "s3",
            Severity: "high",
            Description: "**Amazon S3 buckets** are evaluated for **Block Public Access** settings, ensuring `ignore_public_acls` and `restrict_public_buckets` are enabled at the bucket or account scope.  *Account-wide protections, when present, are treated as effective for the bucket.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketLevelPublicAccessBlock) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketLevelPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketLifecycleEnabled - S3 bucket has a lifecycle configuration enabled
type S3BucketLifecycleEnabled struct {
    metadata models.CheckMetadata
}

func NewS3BucketLifecycleEnabled() *S3BucketLifecycleEnabled {
    return &S3BucketLifecycleEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_lifecycle_enabled",
            CheckTitle: "S3 bucket has a lifecycle configuration enabled",
            ServiceName: "s3",
            Severity: "low",
            Description: "**Amazon S3 buckets** use **Lifecycle configurations** with at least one rule `Status: Enabled` to automate object `Transitions` and `Expiration` based on age, prefix, or tags",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketLifecycleEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketLifecycleEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketObjectVersioning - S3 bucket has object versioning enabled
type S3BucketObjectVersioning struct {
    metadata models.CheckMetadata
}

func NewS3BucketObjectVersioning() *S3BucketObjectVersioning {
    return &S3BucketObjectVersioning{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_object_versioning",
            CheckTitle: "S3 bucket has object versioning enabled",
            ServiceName: "s3",
            Severity: "medium",
            Description: "**Amazon S3 buckets** are evaluated for **object versioning** being `Enabled`, which maintains multiple versions of the same object key for historical state retention",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketObjectVersioning) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketObjectVersioning) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketNoMfaDelete - S3 bucket has MFA Delete enabled
type S3BucketNoMfaDelete struct {
    metadata models.CheckMetadata
}

func NewS3BucketNoMfaDelete() *S3BucketNoMfaDelete {
    return &S3BucketNoMfaDelete{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_no_mfa_delete",
            CheckTitle: "S3 bucket has MFA Delete enabled",
            ServiceName: "s3",
            Severity: "medium",
            Description: "**Amazon S3 buckets** are assessed for **MFA Delete** status. MFA Delete requires a second factor to permanently delete object versions or change `Versioning` configuration. The finding highlights buckets where this protection is not enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketNoMfaDelete) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketNoMfaDelete) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketServerAccessLoggingEnabled - S3 bucket has server access logging enabled
type S3BucketServerAccessLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewS3BucketServerAccessLoggingEnabled() *S3BucketServerAccessLoggingEnabled {
    return &S3BucketServerAccessLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_server_access_logging_enabled",
            CheckTitle: "S3 bucket has server access logging enabled",
            ServiceName: "s3",
            Severity: "medium",
            Description: "**Amazon S3 buckets** are evaluated for **server access logging** configured to record access requests and deliver logs to a designated destination bucket.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketServerAccessLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketServerAccessLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketEventNotificationsEnabled - S3 bucket has event notifications enabled
type S3BucketEventNotificationsEnabled struct {
    metadata models.CheckMetadata
}

func NewS3BucketEventNotificationsEnabled() *S3BucketEventNotificationsEnabled {
    return &S3BucketEventNotificationsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_event_notifications_enabled",
            CheckTitle: "S3 bucket has event notifications enabled",
            ServiceName: "s3",
            Severity: "low",
            Description: "**Amazon S3 buckets** define a **notification configuration** that publishes bucket events (for example `s3:ObjectCreated:*`, `s3:ObjectRemoved:*`) to a destination. The evaluation identifies buckets that lack any notification setup.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketEventNotificationsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketEventNotificationsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketPublicWriteAcl - S3 bucket ACL does not grant write access to Everyone or any AWS customer
type S3BucketPublicWriteAcl struct {
    metadata models.CheckMetadata
}

func NewS3BucketPublicWriteAcl() *S3BucketPublicWriteAcl {
    return &S3BucketPublicWriteAcl{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_public_write_acl",
            CheckTitle: "S3 bucket ACL does not grant write access to Everyone or any AWS customer",
            ServiceName: "s3",
            Severity: "critical",
            Description: "**Amazon S3 buckets** are assessed for ACL grants that allow **public write** access to `AllUsers` or `AuthenticatedUsers` via `WRITE`, `WRITE_ACP`, or `FULL_CONTROL`. Effective **Block Public Access** at account or bucket level (`ignore_public_acls`, `restrict_public_buckets`) is considered.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketPublicWriteAcl) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketPublicWriteAcl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3AccountLevelPublicAccessBlocks - S3 account-level Block Public Access ignores public ACLs and restricts public buckets
type S3AccountLevelPublicAccessBlocks struct {
    metadata models.CheckMetadata
}

func NewS3AccountLevelPublicAccessBlocks() *S3AccountLevelPublicAccessBlocks {
    return &S3AccountLevelPublicAccessBlocks{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_account_level_public_access_blocks",
            CheckTitle: "S3 account-level Block Public Access ignores public ACLs and restricts public buckets",
            ServiceName: "s3",
            Severity: "high",
            Description: "**Amazon S3** account-level **Block Public Access** is assessed for `ignore_public_acls` and `restrict_public_buckets` to confirm centralized blocking of ACL-based public access and limiting buckets with public policies to in-account principals.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3AccountLevelPublicAccessBlocks) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3AccountLevelPublicAccessBlocks) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3AccessPointPublicAccessBlock - S3 access point has all Block Public Access settings enabled
type S3AccessPointPublicAccessBlock struct {
    metadata models.CheckMetadata
}

func NewS3AccessPointPublicAccessBlock() *S3AccessPointPublicAccessBlock {
    return &S3AccessPointPublicAccessBlock{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_access_point_public_access_block",
            CheckTitle: "S3 access point has all Block Public Access settings enabled",
            ServiceName: "s3",
            Severity: "critical",
            Description: "**Amazon S3 access points** have **Block Public Access** configured with all settings enabled: `block_public_acls`, `ignore_public_acls`, `block_public_policy`, and `restrict_public_buckets`.  The evaluation inspects each access point's public access block configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3AccessPointPublicAccessBlock) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3AccessPointPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketAclProhibited - S3 bucket has bucket ACLs disabled
type S3BucketAclProhibited struct {
    metadata models.CheckMetadata
}

func NewS3BucketAclProhibited() *S3BucketAclProhibited {
    return &S3BucketAclProhibited{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_acl_prohibited",
            CheckTitle: "S3 bucket has bucket ACLs disabled",
            ServiceName: "s3",
            Severity: "medium",
            Description: "**Amazon S3 buckets** are evaluated for **Object Ownership** set to `BucketOwnerEnforced`, which disables bucket and object ACLs. Buckets using any other ownership setting indicate that ACLs remain enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketAclProhibited) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketAclProhibited) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketCrossRegionReplication - S3 bucket has cross-region replication configured to a bucket in a different region
type S3BucketCrossRegionReplication struct {
    metadata models.CheckMetadata
}

func NewS3BucketCrossRegionReplication() *S3BucketCrossRegionReplication {
    return &S3BucketCrossRegionReplication{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_cross_region_replication",
            CheckTitle: "S3 bucket has cross-region replication configured to a bucket in a different region",
            ServiceName: "s3",
            Severity: "low",
            Description: "**Amazon S3 buckets** use **cross-Region replication** with `versioning` and an enabled rule that targets a destination bucket in a different AWS Region.  Buckets with same-Region targets, missing destinations, or disabled `versioning` don't meet this replication posture.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketCrossRegionReplication) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketCrossRegionReplication) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketDefaultEncryption - [DEPRECATED] S3 bucket has default server-side encryption (SSE) enabled
type S3BucketDefaultEncryption struct {
    metadata models.CheckMetadata
}

func NewS3BucketDefaultEncryption() *S3BucketDefaultEncryption {
    return &S3BucketDefaultEncryption{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_default_encryption",
            CheckTitle: "[DEPRECATED] S3 bucket has default server-side encryption (SSE) enabled",
            ServiceName: "s3",
            Severity: "medium",
            Description: "[DEPRECATED] **Amazon S3 buckets** have a default **server-side encryption** setting that automatically encrypts new objects using `SSE-S3` or `SSE-KMS`. This evaluates whether a bucket has a default encryption configuration defined.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketDefaultEncryption) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketDefaultEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketCrossAccountAccess - S3 bucket policy does not allow cross-account access
type S3BucketCrossAccountAccess struct {
    metadata models.CheckMetadata
}

func NewS3BucketCrossAccountAccess() *S3BucketCrossAccountAccess {
    return &S3BucketCrossAccountAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_cross_account_access",
            CheckTitle: "S3 bucket policy does not allow cross-account access",
            ServiceName: "s3",
            Severity: "high",
            Description: "**Amazon S3 bucket policies** are analyzed for statements that grant **cross-account access**.  Any policy that names principals outside the owning account (other account IDs or `Principal: '*'`) is treated as cross-account; absence of a policy implies no cross-account grants.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketCrossAccountAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketObjectPublic - Spot-check S3 bucket objects for public ACLs
type S3BucketObjectPublic struct {
    metadata models.CheckMetadata
}

func NewS3BucketObjectPublic() *S3BucketObjectPublic {
    return &S3BucketObjectPublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_object_public",
            CheckTitle: "Spot-check S3 bucket objects for public ACLs",
            ServiceName: "s3",
            Severity: "low",
            Description: "Spot-checks a configurable sample of objects in each S3 bucket and flags any whose ACL grants access to the AllUsers or AuthenticatedUsers groups. This is a sampling-based check, not a comprehensive audit, so public objects outside the sample can be missed. It is disabled by default and must be enabled via the s3_bucket_object_public_enabled configuration flag.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketObjectPublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketObjectPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketSecureTransportPolicy - S3 bucket policy denies requests over insecure transport
type S3BucketSecureTransportPolicy struct {
    metadata models.CheckMetadata
}

func NewS3BucketSecureTransportPolicy() *S3BucketSecureTransportPolicy {
    return &S3BucketSecureTransportPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_secure_transport_policy",
            CheckTitle: "S3 bucket policy denies requests over insecure transport",
            ServiceName: "s3",
            Severity: "medium",
            Description: "**Amazon S3 buckets** are evaluated for a bucket policy that enforces **secure transport** by denying requests when `aws:SecureTransport` is `false`.  Buckets without this explicit denial, or without a policy, are treated as allowing access over insecure transport.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketSecureTransportPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketSecureTransportPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3MultiRegionAccessPointPublicAccessBlock - S3 Multi-Region Access Point has all Block Public Access settings enabled
type S3MultiRegionAccessPointPublicAccessBlock struct {
    metadata models.CheckMetadata
}

func NewS3MultiRegionAccessPointPublicAccessBlock() *S3MultiRegionAccessPointPublicAccessBlock {
    return &S3MultiRegionAccessPointPublicAccessBlock{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_multi_region_access_point_public_access_block",
            CheckTitle: "S3 Multi-Region Access Point has all Block Public Access settings enabled",
            ServiceName: "s3",
            Severity: "high",
            Description: "**Amazon S3 Multi-Region Access Points** are evaluated for **Block Public Access** being fully enabled (`block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets`).  Focus is on the MRAP's own settings, separate from bucket or account configurations.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3MultiRegionAccessPointPublicAccessBlock) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3MultiRegionAccessPointPublicAccessBlock) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketPolicyPublicWriteAccess - S3 bucket policy does not allow public write access
type S3BucketPolicyPublicWriteAccess struct {
    metadata models.CheckMetadata
}

func NewS3BucketPolicyPublicWriteAccess() *S3BucketPolicyPublicWriteAccess {
    return &S3BucketPolicyPublicWriteAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_policy_public_write_access",
            CheckTitle: "S3 bucket policy does not allow public write access",
            ServiceName: "s3",
            Severity: "critical",
            Description: "**Amazon S3 bucket policies** are evaluated for **public write permissions** (e.g., `s3:PutObject`, `s3:Delete*`, or `s3:*`). Account or bucket **Public Access Block** that restricts public buckets is considered when determining exposure.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketPolicyPublicWriteAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketPolicyPublicWriteAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketPublicListAcl - S3 bucket is not publicly listable by Everyone or any authenticated AWS user
type S3BucketPublicListAcl struct {
    metadata models.CheckMetadata
}

func NewS3BucketPublicListAcl() *S3BucketPublicListAcl {
    return &S3BucketPublicListAcl{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_public_list_acl",
            CheckTitle: "S3 bucket is not publicly listable by Everyone or any authenticated AWS user",
            ServiceName: "s3",
            Severity: "critical",
            Description: "**Amazon S3 buckets** are evaluated for **public listing via ACLs**. Grants of `READ`, `READ_ACP`, or `FULL_CONTROL` to the `AllUsers` or `AuthenticatedUsers` groups are identified. Effective **Block Public Access** at account or bucket level (notably `IgnorePublicAcls` and `RestrictPublicBuckets`) is considered in the evaluation.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketPublicListAcl) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketPublicListAcl) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketShadowResourceVulnerability - S3 bucket is not a known shadow resource owned by another account
type S3BucketShadowResourceVulnerability struct {
    metadata models.CheckMetadata
}

func NewS3BucketShadowResourceVulnerability() *S3BucketShadowResourceVulnerability {
    return &S3BucketShadowResourceVulnerability{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_shadow_resource_vulnerability",
            CheckTitle: "S3 bucket is not a known shadow resource owned by another account",
            ServiceName: "s3",
            Severity: "high",
            Description: "**Amazon S3 buckets** using **predictable service naming** (e.g., `aws-glue-assets-<account>-<region>`, `sagemaker-<region>-<account>`) are identified and their **ownership** checked.  Buckets tied to your account that match these patterns but are owned by another account-across regions-are surfaced as shadow-resource candidates.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketShadowResourceVulnerability) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketShadowResourceVulnerability) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketPublicAccess - S3 bucket is not publicly accessible to Everyone or Authenticated Users
type S3BucketPublicAccess struct {
    metadata models.CheckMetadata
}

func NewS3BucketPublicAccess() *S3BucketPublicAccess {
    return &S3BucketPublicAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_public_access",
            CheckTitle: "S3 bucket is not publicly accessible to Everyone or Authenticated Users",
            ServiceName: "s3",
            Severity: "critical",
            Description: "**Amazon S3 buckets** are evaluated for **public access** via ACLs and bucket policies. The check identifies account or bucket `PublicAccessBlock` protections (`IgnorePublicAcls`, `RestrictPublicBuckets`) and flags buckets granting group access to `AllUsers` or `AuthenticatedUsers`, or with a public bucket policy.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketPublicAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// S3BucketKmsEncryption - S3 bucket has server-side encryption with AWS KMS
type S3BucketKmsEncryption struct {
    metadata models.CheckMetadata
}

func NewS3BucketKmsEncryption() *S3BucketKmsEncryption {
    return &S3BucketKmsEncryption{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "s3_bucket_kms_encryption",
            CheckTitle: "S3 bucket has server-side encryption with AWS KMS",
            ServiceName: "s3",
            Severity: "medium",
            Description: "**Amazon S3 buckets** use server-side encryption with **AWS KMS** keys, including dual-layer `aws:kms:dsse`. The evaluation identifies buckets whose default encryption is `aws:kms` or `aws:kms:dsse` rather than SSE-S3.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"s3"},
        },
    }
}

func (c *S3BucketKmsEncryption) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *S3BucketKmsEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "s3",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

