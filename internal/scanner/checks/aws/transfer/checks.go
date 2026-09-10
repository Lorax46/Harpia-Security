package transfer

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// TransferServerPqcSshKexEnabled - AWS Transfer Family server uses a post-quantum hybrid SSH key exchange security policy
type TransferServerPqcSshKexEnabled struct {
    metadata models.CheckMetadata
}

func NewTransferServerPqcSshKexEnabled() *TransferServerPqcSshKexEnabled {
    return &TransferServerPqcSshKexEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "transfer_server_pqc_ssh_kex_enabled",
            CheckTitle: "AWS Transfer Family server uses a post-quantum hybrid SSH key exchange security policy",
            ServiceName: "transfer",
            Severity: "low",
            Description: "**AWS Transfer Family servers** (SFTP, FTPS, AS2) are assessed for use of an approved **post-quantum (PQ) hybrid SSH key exchange security policy**. Servers whose `SecurityPolicyName` is not in the configured allowlist of PQ-ready Transfer Family security policies leave file-transfer sessions exposed to **harvest-now, decrypt-later** attacks.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"transfer"},
        },
    }
}

func (c *TransferServerPqcSshKexEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *TransferServerPqcSshKexEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "transfer",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// TransferServerInTransitEncryptionEnabled - Transfer Family server has encryption in transit enabled
type TransferServerInTransitEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewTransferServerInTransitEncryptionEnabled() *TransferServerInTransitEncryptionEnabled {
    return &TransferServerInTransitEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "transfer_server_in_transit_encryption_enabled",
            CheckTitle: "Transfer Family server has encryption in transit enabled",
            ServiceName: "transfer",
            Severity: "high",
            Description: "**AWS Transfer Family servers** are evaluated for presence of the unencrypted `FTP` protocol among enabled protocols, as opposed to encrypted options like SFTP, FTPS, or AS2.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"transfer"},
        },
    }
}

func (c *TransferServerInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *TransferServerInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "transfer",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

