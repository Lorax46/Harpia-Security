package storagegateway

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// StoragegatewayFileshareEncryptionEnabled - Storage Gateway file share is encrypted with KMS CMK
type StoragegatewayFileshareEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewStoragegatewayFileshareEncryptionEnabled() *StoragegatewayFileshareEncryptionEnabled {
    return &StoragegatewayFileshareEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "storagegateway_fileshare_encryption_enabled",
            CheckTitle: "Storage Gateway file share is encrypted with KMS CMK",
            ServiceName: "storagegateway",
            Severity: "medium",
            Description: "Storage Gateway file shares configured with **customer-managed KMS keys (CMKs)** for server-side encryption of objects written to S3.  File shares without an explicit KMS key (e.g., `SSE-KMS` or `DSSE-KMS`) are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"storagegateway"},
        },
    }
}

func (c *StoragegatewayFileshareEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *StoragegatewayFileshareEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "storagegateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// StoragegatewayGatewayFaultTolerant - AWS Storage Gateway gateway is not hosted on EC2
type StoragegatewayGatewayFaultTolerant struct {
    metadata models.CheckMetadata
}

func NewStoragegatewayGatewayFaultTolerant() *StoragegatewayGatewayFaultTolerant {
    return &StoragegatewayGatewayFaultTolerant{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "storagegateway_gateway_fault_tolerant",
            CheckTitle: "AWS Storage Gateway gateway is not hosted on EC2",
            ServiceName: "storagegateway",
            Severity: "medium",
            Description: "AWS Storage Gateway hosted on an **EC2 instance** is flagged by assessing each gateway's hosting environment, distinguishing **single-instance EC2** deployments from **non-EC2** platforms that can leverage platform-level high availability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"storagegateway"},
        },
    }
}

func (c *StoragegatewayGatewayFaultTolerant) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *StoragegatewayGatewayFaultTolerant) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "storagegateway",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

