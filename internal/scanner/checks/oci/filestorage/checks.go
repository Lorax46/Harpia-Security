package filestorage

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// FilestorageFileSystemEncryptedWithCmk - medium
type FilestorageFileSystemEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

// NewFilestorageFileSystemEncryptedWithCmk cria nova instância
func NewFilestorageFileSystemEncryptedWithCmk() *FilestorageFileSystemEncryptedWithCmk {
	return &FilestorageFileSystemEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "filestorage_file_system_encrypted_with_cmk",
			CheckTitle:     "File Storage file system is encrypted with a customer-managed KMS key",
			ServiceName:    "filestorage",
			Severity:       "medium",
			Description:    "**OCI File Storage** file systems use **Customer-Managed Keys** (`CMEK`) for encryption when a KMS key is associated, instead of the default Oracle-ma",
			RemediationText: "Encrypt file systems with **Customer-Managed Keys** in OCI KMS. Apply **least privilege** on key usa",
			Categories:     []string{"filestorage"},
		},
	}
}

// Metadata retorna os metadados
func (c *FilestorageFileSystemEncryptedWithCmk) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *FilestorageFileSystemEncryptedWithCmk) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "filestorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

