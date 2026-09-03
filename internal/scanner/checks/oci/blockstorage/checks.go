package blockstorage

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// BlockstorageBlockVolumeEncryptedWithCmk - medium
type BlockstorageBlockVolumeEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

// NewBlockstorageBlockVolumeEncryptedWithCmk cria nova instância
func NewBlockstorageBlockVolumeEncryptedWithCmk() *BlockstorageBlockVolumeEncryptedWithCmk {
	return &BlockstorageBlockVolumeEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "blockstorage_block_volume_encrypted_with_cmk",
			CheckTitle:     "Block volume is encrypted with a Customer Managed Key (CMK)",
			ServiceName:    "blockstorage",
			Severity:       "medium",
			Description:    "**OCI block volumes** use **Customer-Managed Keys** (`CMK`) from Vault for at-rest encryption instead of Oracle-managed keys.  Identifies whether a bl",
			RemediationText: "Use **Customer-Managed Keys** in Vault for all block volumes. - Enforce least privilege and separati",
			Categories:     []string{"blockstorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *BlockstorageBlockVolumeEncryptedWithCmk) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *BlockstorageBlockVolumeEncryptedWithCmk) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "blockstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// BlockstorageBootVolumeEncryptedWithCmk - medium
type BlockstorageBootVolumeEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

// NewBlockstorageBootVolumeEncryptedWithCmk cria nova instância
func NewBlockstorageBootVolumeEncryptedWithCmk() *BlockstorageBootVolumeEncryptedWithCmk {
	return &BlockstorageBootVolumeEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "blockstorage_boot_volume_encrypted_with_cmk",
			CheckTitle:     "Boot volume is encrypted with Customer Managed Key",
			ServiceName:    "blockstorage",
			Severity:       "medium",
			Description:    "Boot volumes use **customer-managed keys (CMEK)** when a Vault key is assigned (`kms_key_id` present), rather than default Oracle-managed encryption.",
			RemediationText: "Encrypt boot volumes with **customer-managed keys** and enforce **least privilege** on key usage. De",
			Categories:     []string{"blockstorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *BlockstorageBootVolumeEncryptedWithCmk) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *BlockstorageBootVolumeEncryptedWithCmk) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "blockstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

