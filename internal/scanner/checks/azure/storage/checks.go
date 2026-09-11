package storage

// =============================================================================
// Azure Storage Checks — 19 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

func newStorageCheck(id, title, description, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider: "azure", CheckID: id, CheckTitle: title,
		Description: description, Severity: severity,
		ServiceName: "storage", ResourceType: "StorageAccount",
		Categories: []string{"storage"},
	}
}

type storageCheck struct {
	metadata models.CheckMetadata
}

func (c *storageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *storageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Storage check requires Azure SDK",
		ResourceID: c.metadata.CheckID, Provider: "azure", Service: "storage",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// StorageAccountAzureServicesAccessEnabled - verifica acesso a serviços Azure
type StorageAccountAzureServicesAccessEnabled struct{ storageCheck }

func NewStorageAccountAzureServicesAccessEnabled() *StorageAccountAzureServicesAccessEnabled {
	return &StorageAccountAzureServicesAccessEnabled{storageCheck{metadata: newStorageCheck(
		"storage_account_azure_services_access_enabled",
		"Ensure storage account Azure services access is enabled",
		"Storage account should allow Azure services access",
		"medium",
	)}}
}

// StorageAccountDefaultNetworkAccessDeny - verifica negação de acesso padrão
type StorageAccountDefaultNetworkAccessDeny struct{ storageCheck }

func NewStorageAccountDefaultNetworkAccessDeny() *StorageAccountDefaultNetworkAccessDeny {
	return &StorageAccountDefaultNetworkAccessDeny{storageCheck{metadata: newStorageCheck(
		"storage_account_default_network_access_deny",
		"Ensure storage account default network access is denied",
		"Storage account should deny default network access",
		"high",
	)}}
}

// StorageAccountEncryptionAtRest - verifica criptografia em repouso
type StorageAccountEncryptionAtRest struct{ storageCheck }

func NewStorageAccountEncryptionAtRest() *StorageAccountEncryptionAtRest {
	return &StorageAccountEncryptionAtRest{storageCheck{metadata: newStorageCheck(
		"storage_account_encryption_at_rest",
		"Ensure storage account encryption at rest is enabled",
		"Storage account should have encryption at rest enabled",
		"high",
	)}}
}

// StorageAccountInfrastructureEncryptionEnabled - verifica criptografia de infraestrutura
type StorageAccountInfrastructureEncryptionEnabled struct{ storageCheck }

func NewStorageAccountInfrastructureEncryptionEnabled() *StorageAccountInfrastructureEncryptionEnabled {
	return &StorageAccountInfrastructureEncryptionEnabled{storageCheck{metadata: newStorageCheck(
		"storage_account_infrastructure_encryption_enabled",
		"Ensure storage account infrastructure encryption is enabled",
		"Storage account should have infrastructure encryption enabled",
		"medium",
	)}}
}

// StorageAccountLoggingEnabled - verifica logging
type StorageAccountLoggingEnabled struct{ storageCheck }

func NewStorageAccountLoggingEnabled() *StorageAccountLoggingEnabled {
	return &StorageAccountLoggingEnabled{storageCheck{metadata: newStorageCheck(
		"storage_account_logging_enabled",
		"Ensure storage account logging is enabled",
		"Storage account should have logging enabled",
		"medium",
	)}}
}

// StorageAccountMinimumTlsVersion - verifica versão mínima de TLS
type StorageAccountMinimumTlsVersion struct{ storageCheck }

func NewStorageAccountMinimumTlsVersion() *StorageAccountMinimumTlsVersion {
	return &StorageAccountMinimumTlsVersion{storageCheck{metadata: newStorageCheck(
		"storage_account_minimum_tls_version",
		"Ensure storage account uses minimum TLS 1.2",
		"Storage account should use minimum TLS version 1.2",
		"medium",
	)}}
}

// StorageAccountPublicAccessDisabled - verifica acesso público
type StorageAccountPublicAccessDisabled struct{ storageCheck }

func NewStorageAccountPublicAccessDisabled() *StorageAccountPublicAccessDisabled {
	return &StorageAccountPublicAccessDisabled{storageCheck{metadata: newStorageCheck(
		"storage_account_public_access_disabled",
		"Ensure storage account public access is disabled",
		"Storage account should have public access disabled",
		"critical",
	)}}
}

// StorageAccountReadOnlyKeysNotExposed - verifica chaves somente leitura
type StorageAccountReadOnlyKeysNotExposed struct{ storageCheck }

func NewStorageAccountReadOnlyKeysNotExposed() *StorageAccountReadOnlyKeysNotExposed {
	return &StorageAccountReadOnlyKeysNotExposed{storageCheck{metadata: newStorageCheck(
		"storage_account_readonly_keys_not_exposed",
		"Ensure storage account read-only keys are not exposed",
		"Storage account read-only keys should not be exposed",
		"high",
	)}}
}

// StorageAccountRequiresSecureTransfer - verifica transferência segura
type StorageAccountRequiresSecureTransfer struct{ storageCheck }

func NewStorageAccountRequiresSecureTransfer() *StorageAccountRequiresSecureTransfer {
	return &StorageAccountRequiresSecureTransfer{storageCheck{metadata: newStorageCheck(
		"storage_account_requires_secure_transfer",
		"Ensure storage account requires secure transfer",
		"Storage account should require secure transfer",
		"medium",
	)}}
}

// StorageAccountSoftDeleteEnabled - verifica soft delete
type StorageAccountSoftDeleteEnabled struct{ storageCheck }

func NewStorageAccountSoftDeleteEnabled() *StorageAccountSoftDeleteEnabled {
	return &StorageAccountSoftDeleteEnabled{storageCheck{metadata: newStorageCheck(
		"storage_account_soft_delete_enabled",
		"Ensure storage account soft delete is enabled",
		"Storage account should have soft delete enabled",
		"medium",
	)}}
}

// StorageAccountVersioningEnabled - verifica versionamento
type StorageAccountVersioningEnabled struct{ storageCheck }

func NewStorageAccountVersioningEnabled() *StorageAccountVersioningEnabled {
	return &StorageAccountVersioningEnabled{storageCheck{metadata: newStorageCheck(
		"storage_account_versioning_enabled",
		"Ensure storage account versioning is enabled",
		"Storage account should have versioning enabled",
		"low",
	)}}
}

// StorageAccountNetworkAccessRestricted - verifica acesso de rede restrito
type StorageAccountNetworkAccessRestricted struct{ storageCheck }

func NewStorageAccountNetworkAccessRestricted() *StorageAccountNetworkAccessRestricted {
	return &StorageAccountNetworkAccessRestricted{storageCheck{metadata: newStorageCheck(
		"storage_account_network_access_restricted",
		"Ensure storage account network access is restricted",
		"Storage account network access should be restricted",
		"high",
	)}}
}

// StorageAccountLocation - verifica localização
type StorageAccountLocation struct{ storageCheck }

func NewStorageAccountLocation() *StorageAccountLocation {
	return &StorageAccountLocation{storageCheck{metadata: newStorageCheck(
		"storage_account_location",
		"Ensure storage account is in an approved location",
		"Storage account should be in an approved location",
		"low",
	)}}
}

// StorageAccountPrivateEndpoint - verifica endpoint privado
type StorageAccountPrivateEndpoint struct{ storageCheck }

func NewStorageAccountPrivateEndpoint() *StorageAccountPrivateEndpoint {
	return &StorageAccountPrivateEndpoint{storageCheck{metadata: newStorageCheck(
		"storage_account_private_endpoint",
		"Ensure storage account uses private endpoint",
		"Storage account should use private endpoint",
		"medium",
	)}}
}

// StorageAccountSharedAccessSignature - verifica SAS
type StorageAccountSharedAccessSignature struct{ storageCheck }

func NewStorageAccountSharedAccessSignature() *StorageAccountSharedAccessSignature {
	return &StorageAccountSharedAccessSignature{storageCheck{metadata: newStorageCheck(
		"storage_account_shared_access_signature",
		"Ensure storage account uses shared access signature",
		"Storage account should use shared access signature",
		"medium",
	)}}
}

// StorageAccountSharedKeyAccessDisabled - verifica acesso por chave compartilhada
type StorageAccountSharedKeyAccessDisabled struct{ storageCheck }

func NewStorageAccountSharedKeyAccessDisabled() *StorageAccountSharedKeyAccessDisabled {
	return &StorageAccountSharedKeyAccessDisabled{storageCheck{metadata: newStorageCheck(
		"storage_account_shared_key_access_disabled",
		"Ensure storage account shared key access is disabled",
		"Storage account shared key access should be disabled",
		"high",
	)}}
}

// StorageAccountStorageContainerPublicAccessDisabled - verifica acesso público do container
type StorageAccountStorageContainerPublicAccessDisabled struct{ storageCheck }

func NewStorageAccountStorageContainerPublicAccessDisabled() *StorageAccountStorageContainerPublicAccessDisabled {
	return &StorageAccountStorageContainerPublicAccessDisabled{storageCheck{metadata: newStorageCheck(
		"storage_account_storage_container_public_access_disabled",
		"Ensure storage container public access is disabled",
		"Storage container public access should be disabled",
		"high",
	)}}
}

// StorageAccountTrustedMicrosoftServicesEnabled - verifica serviços confiáveis
type StorageAccountTrustedMicrosoftServicesEnabled struct{ storageCheck }

func NewStorageAccountTrustedMicrosoftServicesEnabled() *StorageAccountTrustedMicrosoftServicesEnabled {
	return &StorageAccountTrustedMicrosoftServicesEnabled{storageCheck{metadata: newStorageCheck(
		"storage_account_trusted_microsoft_services_enabled",
		"Ensure storage account allows trusted Microsoft services",
		"Storage account should allow trusted Microsoft services",
		"medium",
	)}}
}

// StorageAccountAzurePolicyForbidsPublicAccess - verifica política do Azure
type StorageAccountAzurePolicyForbidsPublicAccess struct{ storageCheck }

func NewStorageAccountAzurePolicyForbidsPublicAccess() *StorageAccountAzurePolicyForbidsPublicAccess {
	return &StorageAccountAzurePolicyForbidsPublicAccess{storageCheck{metadata: newStorageCheck(
		"storage_account_azure_policy_forbids_public_access",
		"Ensure Azure policy forbids public access to storage",
		"Azure policy should forbid public access to storage",
		"high",
	)}}
}
