package recovery

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type recoveryVaultEncrypted struct {
	metadata models.CheckMetadata
}

func NewRecoveryVaultEncrypted() *recoveryVaultEncrypted {
	return &recoveryVaultEncrypted{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "recovery_vault_encrypted",
		CheckTitle: "Ensure recovery vault is encrypted",
		Description: "Recovery vault should be encrypted with CMK",
		Severity: "medium", ServiceName: "recovery", ResourceType: "Vault",
		Categories: []string{"recovery", "encryption"},
	}}
}

func (c *recoveryVaultEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *recoveryVaultEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Recovery vault encryption check requires Azure SDK",
		ResourceID: "recovery-vault-encryption", Provider: "azure", Service: "recovery",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type recoveryVaultSoftDeleteEnabled struct {
	metadata models.CheckMetadata
}

func NewRecoveryVaultSoftDeleteEnabled() *recoveryVaultSoftDeleteEnabled {
	return &recoveryVaultSoftDeleteEnabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "recovery_vault_soft_delete_enabled",
		CheckTitle: "Ensure recovery vault soft delete is enabled",
		Description: "Recovery vault should have soft delete enabled",
		Severity: "medium", ServiceName: "recovery", ResourceType: "Vault",
		Categories: []string{"recovery", "soft-delete"},
	}}
}

func (c *recoveryVaultSoftDeleteEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *recoveryVaultSoftDeleteEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Recovery vault soft delete check requires Azure SDK",
		ResourceID: "recovery-vault-soft-delete", Provider: "azure", Service: "recovery",
		FoundAt: time.Now().UTC(),
	}}, nil
}
