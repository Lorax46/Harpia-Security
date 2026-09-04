package efs

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// EfsHaveBackupEnabled - EFS file system has backup enabled
type EfsHaveBackupEnabled struct {
    metadata models.CheckMetadata
}

func NewEfsHaveBackupEnabled() *EfsHaveBackupEnabled {
    return &EfsHaveBackupEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_have_backup_enabled",
            CheckTitle: "EFS file system has backup enabled",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**Amazon EFS file systems** are assessed for automated backups configured via the `backup policy`. The finding highlights file systems where backups are not enabled or are being disabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsHaveBackupEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsHaveBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EfsAccessPointEnforceUserIdentity - EFS file system has all access points with a defined POSIX user
type EfsAccessPointEnforceUserIdentity struct {
    metadata models.CheckMetadata
}

func NewEfsAccessPointEnforceUserIdentity() *EfsAccessPointEnforceUserIdentity {
    return &EfsAccessPointEnforceUserIdentity{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_access_point_enforce_user_identity",
            CheckTitle: "EFS file system has all access points with a defined POSIX user",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**Amazon EFS access points** are evaluated for a defined **POSIX user** (`uid`, `gid`, optional secondary groups). The check inspects each access point on a file system and flags those without a configured POSIX user identity.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsAccessPointEnforceUserIdentity) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsAccessPointEnforceUserIdentity) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EfsMountTargetNotPubliclyAccessible - EFS file system has no publicly accessible mount targets
type EfsMountTargetNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewEfsMountTargetNotPubliclyAccessible() *EfsMountTargetNotPubliclyAccessible {
    return &EfsMountTargetNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_mount_target_not_publicly_accessible",
            CheckTitle: "EFS file system has no publicly accessible mount targets",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**EFS mount targets** associated with VPC subnets that auto-assign public IPv4 addresses (`mapPublicIpOnLaunch=true`) are identified per file system.  The evaluation focuses on the subnet attribute linked to each mount target.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsMountTargetNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsMountTargetNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EfsMultiAzEnabled - EFS file system is Multi-AZ with more than one mount target
type EfsMultiAzEnabled struct {
    metadata models.CheckMetadata
}

func NewEfsMultiAzEnabled() *EfsMultiAzEnabled {
    return &EfsMultiAzEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_multi_az_enabled",
            CheckTitle: "EFS file system is Multi-AZ with more than one mount target",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**Amazon EFS** file systems are assessed for **multi-AZ resilience**: Regional type (no `availability_zone_id`) with mount targets in more than one Availability Zone. Single-AZ (One Zone) or Regional with only one mount target is identified for attention.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsMultiAzEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EfsEncryptionAtRestEnabled - EFS file system has encryption at rest enabled
type EfsEncryptionAtRestEnabled struct {
    metadata models.CheckMetadata
}

func NewEfsEncryptionAtRestEnabled() *EfsEncryptionAtRestEnabled {
    return &EfsEncryptionAtRestEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_encryption_at_rest_enabled",
            CheckTitle: "EFS file system has encryption at rest enabled",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**Amazon EFS file system** has **encryption at rest** enabled using AWS KMS to protect file data and metadata stored on the service",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsEncryptionAtRestEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsEncryptionAtRestEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EfsAccessPointEnforceRootDirectory - EFS file system has no access points allowing access to the root directory
type EfsAccessPointEnforceRootDirectory struct {
    metadata models.CheckMetadata
}

func NewEfsAccessPointEnforceRootDirectory() *EfsAccessPointEnforceRootDirectory {
    return &EfsAccessPointEnforceRootDirectory{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_access_point_enforce_root_directory",
            CheckTitle: "EFS file system has no access points allowing access to the root directory",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**Amazon EFS access points** are evaluated to ensure they enforce a non-root directory. The check identifies access points whose configured root directory `Path` is `/`, meaning clients would mount the file system's root instead of a scoped subdirectory.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsAccessPointEnforceRootDirectory) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsAccessPointEnforceRootDirectory) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EfsNotPubliclyAccessible - EFS file system policy does not allow access to any client within the VPC
type EfsNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewEfsNotPubliclyAccessible() *EfsNotPubliclyAccessible {
    return &EfsNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "efs_not_publicly_accessible",
            CheckTitle: "EFS file system policy does not allow access to any client within the VPC",
            ServiceName: "efs",
            Severity: "medium",
            Description: "**Amazon EFS** file system policy is assessed for **public or VPC-wide access**. Policies with broad `Principal` values or that permit any client in the VPC without the `elasticfilesystem:AccessedViaMountTarget` condition are identified.  *An absent or empty policy is treated as open to VPC clients.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"efs"},
        },
    }
}

func (c *EfsNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EfsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "efs",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

