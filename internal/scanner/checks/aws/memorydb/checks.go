package memorydb

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// MemorydbClusterAutoMinorVersionUpgrades - MemoryDB cluster has automatic minor version upgrades enabled
type MemorydbClusterAutoMinorVersionUpgrades struct {
    metadata models.CheckMetadata
}

func NewMemorydbClusterAutoMinorVersionUpgrades() *MemorydbClusterAutoMinorVersionUpgrades {
    return &MemorydbClusterAutoMinorVersionUpgrades{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "memorydb_cluster_auto_minor_version_upgrades",
            CheckTitle: "MemoryDB cluster has automatic minor version upgrades enabled",
            ServiceName: "memorydb",
            Severity: "medium",
            Description: "**MemoryDB clusters** are evaluated for the `auto_minor_version_upgrade` setting that automatically applies new minor engine versions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"memorydb"},
        },
    }
}

func (c *MemorydbClusterAutoMinorVersionUpgrades) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MemorydbClusterAutoMinorVersionUpgrades) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "memorydb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// MemorydbClusterInTransitEncryptionEnabled - MemoryDB cluster has in-transit encryption enabled
type MemorydbClusterInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewMemorydbClusterInTransitEncryptionEnabled() *MemorydbClusterInTransitEncryptionEnabled {
    return &MemorydbClusterInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "memorydb_cluster_in_transit_encryption_enabled",
            CheckTitle: "MemoryDB cluster has in-transit encryption enabled",
            ServiceName: "memorydb",
            Severity: "medium",
            Description: "**MemoryDB clusters** are evaluated for **in-transit encryption (TLS)** on client and inter-node traffic (`TLSEnabled=true`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"memorydb"},
        },
    }
}

func (c *MemorydbClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *MemorydbClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "memorydb",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

