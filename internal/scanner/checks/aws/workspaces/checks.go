package workspaces

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// WorkspacesVpc2private1publicSubnetsNat - Workspace is in a private subnet and its VPC has at least 1 public subnet, 2 private subnets, and a NAT Gateway
type WorkspacesVpc2private1publicSubnetsNat struct {
    metadata models.CheckMetadata
}

func NewWorkspacesVpc2private1publicSubnetsNat() *WorkspacesVpc2private1publicSubnetsNat {
    return &WorkspacesVpc2private1publicSubnetsNat{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "workspaces_vpc_2private_1public_subnets_nat",
            CheckTitle: "Workspace is in a private subnet and its VPC has at least 1 public subnet, 2 private subnets, and a NAT Gateway",
            ServiceName: "workspaces",
            Severity: "high",
            Description: "Amazon WorkSpaces reside in a VPC that includes **2 private subnets** and **1 public subnet**, with the WorkSpace launched in a **private subnet** and the VPC providing **NAT Gateway** egress.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"workspaces"},
        },
    }
}

func (c *WorkspacesVpc2private1publicSubnetsNat) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *WorkspacesVpc2private1publicSubnetsNat) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "workspaces",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// WorkspacesVolumeEncryptionEnabled - Amazon WorkSpaces workspace root and user volumes are encrypted
type WorkspacesVolumeEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewWorkspacesVolumeEncryptionEnabled() *WorkspacesVolumeEncryptionEnabled {
    return &WorkspacesVolumeEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "workspaces_volume_encryption_enabled",
            CheckTitle: "Amazon WorkSpaces workspace root and user volumes are encrypted",
            ServiceName: "workspaces",
            Severity: "high",
            Description: "**Amazon WorkSpaces** evaluates **encryption at rest** on each workspace's EBS volumes. It checks whether the **root** and **user** volumes are encrypted with a KMS key and identifies workspaces where either volume is unencrypted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"workspaces"},
        },
    }
}

func (c *WorkspacesVolumeEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *WorkspacesVolumeEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "workspaces",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

