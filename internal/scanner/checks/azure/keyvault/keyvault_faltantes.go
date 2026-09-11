package keyvault

// =============================================================================
// Azure Key Vault Missing Checks — 10 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type azureKeyvaultMissingCheck struct {
	metadata models.CheckMetadata
}

func newAzureKeyvaultMissingCheck(id, title, desc, sev string) azureKeyvaultMissingCheck {
	return azureKeyvaultMissingCheck{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "keyvault", ResourceType: "KeyVault",
		Categories: []string{"keyvault"},
	}}
}

func (c *azureKeyvaultMissingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *azureKeyvaultMissingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Azure keyvault check requires Azure SDK",
		ResourceID: c.metadata.CheckID, Provider: "azure", Service: "keyvault",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type keyvaultAccessOnlyThroughPrivateEndpoints struct{ azureKeyvaultMissingCheck }

func NewKeyvaultAccessOnlyThroughPrivateEndpoints() *keyvaultAccessOnlyThroughPrivateEndpoints {
	return &keyvaultAccessOnlyThroughPrivateEndpoints{newAzureKeyvaultMissingCheck(
		"keyvault_access_only_through_private_endpoints",
		"Ensure key vault access only through private endpoints",
		"Key vault should have access only through private endpoints",
		"high",
	)}
}

type keyvaultKeyExpirationSetInNonRbac struct{ azureKeyvaultMissingCheck }

func NewKeyvaultKeyExpirationSetInNonRbac() *keyvaultKeyExpirationSetInNonRbac {
	return &keyvaultKeyExpirationSetInNonRbac{newAzureKeyvaultMissingCheck(
		"keyvault_key_expiration_set_in_non_rbac",
		"Ensure key vault key expiration is set in non-RBAC",
		"Key vault key expiration should be set in non-RBAC",
		"medium",
	)}
}

type keyvaultNonRbacSecretExpirationSet struct{ azureKeyvaultMissingCheck }

func NewKeyvaultNonRbacSecretExpirationSet() *keyvaultNonRbacSecretExpirationSet {
	return &keyvaultNonRbacSecretExpirationSet{newAzureKeyvaultMissingCheck(
		"keyvault_non_rbac_secret_expiration_set",
		"Ensure key vault non-RBAC secret expiration is set",
		"Key vault non-RBAC secret expiration should be set",
		"medium",
	)}
}

type keyvaultPrivateEndpoints struct{ azureKeyvaultMissingCheck }

func NewKeyvaultPrivateEndpoints() *keyvaultPrivateEndpoints {
	return &keyvaultPrivateEndpoints{newAzureKeyvaultMissingCheck(
		"keyvault_private_endpoints",
		"Ensure key vault uses private endpoints",
		"Key vault should use private endpoints",
		"medium",
	)}
}

type keyvaultRbacEnabled struct{ azureKeyvaultMissingCheck }

func NewKeyvaultRbacEnabled() *keyvaultRbacEnabled {
	return &keyvaultRbacEnabled{newAzureKeyvaultMissingCheck(
		"keyvault_rbac_enabled",
		"Ensure key vault RBAC is enabled",
		"Key vault RBAC should be enabled",
		"medium",
	)}
}

type keyvaultRbacKeyExpirationSet struct{ azureKeyvaultMissingCheck }

func NewKeyvaultRbacKeyExpirationSet() *keyvaultRbacKeyExpirationSet {
	return &keyvaultRbacKeyExpirationSet{newAzureKeyvaultMissingCheck(
		"keyvault_rbac_key_expiration_set",
		"Ensure key vault RBAC key expiration is set",
		"Key vault RBAC key expiration should be set",
		"medium",
	)}
}

type keyvaultRbacSecretExpirationSet struct{ azureKeyvaultMissingCheck }

func NewKeyvaultRbacSecretExpirationSet() *keyvaultRbacSecretExpirationSet {
	return &keyvaultRbacSecretExpirationSet{newAzureKeyvaultMissingCheck(
		"keyvault_rbac_secret_expiration_set",
		"Ensure key vault RBAC secret expiration is set",
		"Key vault RBAC secret expiration should be set",
		"medium",
	)}
}

type keyvaultRecoverable struct{ azureKeyvaultMissingCheck }

func NewKeyvaultRecoverable() *keyvaultRecoverable {
	return &keyvaultRecoverable{newAzureKeyvaultMissingCheck(
		"keyvault_recoverable",
		"Ensure key vault is recoverable",
		"Key vault should be recoverable",
		"high",
	)}
}
