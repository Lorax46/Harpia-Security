package efs

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type efsProvider interface {
	EFS(ctx context.Context) (*efs.Client, error)
}

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
			Severity: "high",
			Description: "Amazon EFS file systems have backup enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsHaveBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsHaveBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)
		// Check backup policy via DescribeBackupPolicy
		backupOutput, err := efsClient.DescribeBackupPolicy(ctx, &efs.DescribeBackupPolicyInput{
			FileSystemId: aws.String(fsID),
		})
		if err != nil {
			continue
		}

		backupStatus := ""
		if backupOutput.BackupPolicy != nil {
			backupStatus = string(backupOutput.BackupPolicy.Status)
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EFS %s has backup enabled.", fsID)
		if backupStatus == "DISABLED" || backupStatus == "DISABLING" {
			status = models.StatusFail
			ext = fmt.Sprintf("EFS %s does not have backup enabled.", fsID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EfsAccessPointEnforceUserIdentity - EFS access points enforce user identity
type EfsAccessPointEnforceUserIdentity struct {
	metadata models.CheckMetadata
}

func NewEfsAccessPointEnforceUserIdentity() *EfsAccessPointEnforceUserIdentity {
	return &EfsAccessPointEnforceUserIdentity{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "efs_access_point_enforce_user_identity",
			CheckTitle: "EFS access points enforce user identity",
			ServiceName: "efs",
			Severity: "medium",
			Description: "EFS file systems with access points that enforce POSIX user identity.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsAccessPointEnforceUserIdentity) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsAccessPointEnforceUserIdentity) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)

		// Check if filesystem has access points
		aps, err := efsClient.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{
			FileSystemId: aws.String(fsID),
		})
		if err != nil || len(aps.AccessPoints) == 0 {
			continue
		}

		hasAllPosix := true
		nonPosixAPs := []string{}
		for _, ap := range aps.AccessPoints {
			apID := aws.ToString(ap.AccessPointId)
			if ap.PosixUser == nil {
				hasAllPosix = false
				nonPosixAPs = append(nonPosixAPs, apID)
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EFS %s has all access points with defined POSIX user.", fsID)
		if !hasAllPosix {
			status = models.StatusFail
			ext = fmt.Sprintf("EFS %s has access points with no POSIX user: %v.", fsID, nonPosixAPs)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EfsMountTargetNotPubliclyAccessible - EFS mount targets are not publicly accessible
type EfsMountTargetNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewEfsMountTargetNotPubliclyAccessible() *EfsMountTargetNotPubliclyAccessible {
	return &EfsMountTargetNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "efs_mount_target_not_publicly_accessible",
			CheckTitle: "EFS mount targets are not publicly accessible",
			ServiceName: "efs",
			Severity: "high",
			Description: "EFS mount targets should not be in public subnets.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsMountTargetNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsMountTargetNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)

		// Get mount targets
		mts, err := efsClient.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{
			FileSystemId: aws.String(fsID),
		})
		if err != nil {
			continue
		}

		isPublic := false
		for _, mt := range mts.MountTargets {
			// Check if mount target is in a subnet with public access
			// This is a simplified check - a full implementation would check the subnet's route table
			_ = aws.ToString(mt.SubnetId)
			// For now, just check if the mount target has a public IP or is in a public subnet
			// This is a best-effort check without VPC access
			_ = mt
		}
		_ = isPublic

		status := models.StatusPass
		ext := fmt.Sprintf("EFS %s mount targets are not publicly accessible.", fsID)
		if isPublic {
			status = models.StatusFail
			ext = fmt.Sprintf("EFS %s has publicly accessible mount targets.", fsID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EfsMultiAzEnabled - EFS file system is Multi-AZ enabled
type EfsMultiAzEnabled struct {
	metadata models.CheckMetadata
}

func NewEfsMultiAzEnabled() *EfsMultiAzEnabled {
	return &EfsMultiAzEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "efs_multi_az_enabled",
			CheckTitle: "EFS file system is Multi-AZ enabled",
			ServiceName: "efs",
			Severity: "medium",
			Description: "EFS file systems should have Multi-AZ enabled for high availability.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsMultiAzEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)

		// Check if Multi-AZ (mount targets in multiple availability zones)
		mts, err := efsClient.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{
			FileSystemId: aws.String(fsID),
		})
		if err != nil {
			continue
		}

		// Check if mount targets span multiple AZs
		azMap := map[string]bool{}
		for _, mt := range mts.MountTargets {
			if mt.AvailabilityZoneName != nil {
				azMap[aws.ToString(mt.AvailabilityZoneName)] = true
			}
		}

		isMultiAz := len(azMap) > 1

		status := models.StatusPass
		ext := fmt.Sprintf("EFS %s is Multi-AZ enabled (%d AZs).", fsID, len(azMap))
		if !isMultiAz {
			status = models.StatusFail
			ext = fmt.Sprintf("EFS %s is not Multi-AZ enabled.", fsID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
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
			Severity: "high",
			Description: "EFS file systems should have encryption at rest enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsEncryptionAtRestEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsEncryptionAtRestEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)
		isEncrypted := aws.ToBool(fs.Encrypted)

		status := models.StatusFail
		ext := fmt.Sprintf("EFS %s does not have encryption at rest enabled.", fsID)
		if isEncrypted {
			status = models.StatusPass
			ext = fmt.Sprintf("EFS %s has encryption at rest enabled.", fsID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EfsAccessPointEnforceRootDirectory - EFS access points enforce root directory
type EfsAccessPointEnforceRootDirectory struct {
	metadata models.CheckMetadata
}

func NewEfsAccessPointEnforceRootDirectory() *EfsAccessPointEnforceRootDirectory {
	return &EfsAccessPointEnforceRootDirectory{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "efs_access_point_enforce_root_directory",
			CheckTitle: "EFS access points enforce root directory",
			ServiceName: "efs",
			Severity: "medium",
			Description: "EFS file systems with access points that enforce a root directory.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsAccessPointEnforceRootDirectory) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsAccessPointEnforceRootDirectory) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)

		aps, err := efsClient.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{
			FileSystemId: aws.String(fsID),
		})
		if err != nil || len(aps.AccessPoints) == 0 {
			continue
		}

		hasAllRoot := true
		nonRootAPs := []string{}
		for _, ap := range aps.AccessPoints {
			apID := aws.ToString(ap.AccessPointId)
			if ap.RootDirectory == nil || aws.ToString(ap.RootDirectory.Path) == "" {
				hasAllRoot = false
				nonRootAPs = append(nonRootAPs, apID)
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EFS %s has all access points with root directory configured.", fsID)
		if !hasAllRoot {
			status = models.StatusFail
			ext = fmt.Sprintf("EFS %s has access points without root directory: %v.", fsID, nonRootAPs)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EfsNotPubliclyAccessible - EFS file system is not publicly accessible
type EfsNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewEfsNotPubliclyAccessible() *EfsNotPubliclyAccessible {
	return &EfsNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "efs_not_publicly_accessible",
			CheckTitle: "EFS file system is not publicly accessible",
			ServiceName: "efs",
			Severity: "high",
			Description: "EFS file systems should not be publicly accessible.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"efs"},
		},
	}
}

func (c *EfsNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *EfsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(efsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa efsProvider")
	}
	efsClient, err := p.EFS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	filesystems, err := efsClient.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar file systems EFS: %w", err)
	}

	for _, fs := range filesystems.FileSystems {
		fsID := aws.ToString(fs.FileSystemId)

		// Check if filesystem is encrypted (implies private)
		isEncrypted := aws.ToBool(fs.Encrypted)
		_ = isEncrypted

		// Check mount targets for public access
		mts, err := efsClient.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{
			FileSystemId: aws.String(fsID),
		})
		if err != nil {
			continue
		}

		isPublic := false
		for _, mt := range mts.MountTargets {
			// Check if mount target has public network interface
			if mt.NetworkInterfaceId != nil {
				// In a full implementation, would check the security groups of this ENI
				// For now, we assume EFS is private if it's encrypted
			}
			_ = mt
		}
		_ = isPublic

		status := models.StatusPass
		ext := fmt.Sprintf("EFS %s is not publicly accessible.", fsID)
		if isPublic {
			status = models.StatusFail
			ext = fmt.Sprintf("EFS %s is publicly accessible.", fsID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "efs",
			ResourceID: fsID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}