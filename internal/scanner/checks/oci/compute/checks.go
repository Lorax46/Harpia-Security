package compute

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ComputeInstanceLegacyMetadataEndpointDisabled - high
type ComputeInstanceLegacyMetadataEndpointDisabled struct {
	metadata models.CheckMetadata
}

// NewComputeInstanceLegacyMetadataEndpointDisabled cria nova instância
func NewComputeInstanceLegacyMetadataEndpointDisabled() *ComputeInstanceLegacyMetadataEndpointDisabled {
	return &ComputeInstanceLegacyMetadataEndpointDisabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "compute_instance_legacy_metadata_endpoint_disabled",
			CheckTitle:     "Compute instance legacy metadata service endpoint is disabled",
			ServiceName:    "compute",
			Severity:       "high",
			Description:    "**OCI compute instance metadata service** is configured so legacy **IMDS v1** endpoints are disabled, requiring session-authorized **IMDS v2** request",
			RemediationText: "Disable **IMDS v1** and require **IMDS v2** across all instances. Migrate applications to session-au",
			Categories:     []string{"compute"},
		},
	}
}

// Metadata retorna os metadados
func (c *ComputeInstanceLegacyMetadataEndpointDisabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ComputeInstanceLegacyMetadataEndpointDisabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// ComputeInstanceInTransitEncryptionEnabled - high
type ComputeInstanceInTransitEncryptionEnabled struct {
	metadata models.CheckMetadata
}

// NewComputeInstanceInTransitEncryptionEnabled cria nova instância
func NewComputeInstanceInTransitEncryptionEnabled() *ComputeInstanceInTransitEncryptionEnabled {
	return &ComputeInstanceInTransitEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "compute_instance_in_transit_encryption_enabled",
			CheckTitle:     "Compute instance has in-transit encryption enabled",
			ServiceName:    "compute",
			Severity:       "high",
			Description:    "**OCI compute instances** are evaluated for **in-transit encryption** on paravirtualized block or boot volume attachments, confirming that data exchan",
			RemediationText: "Enable **in-transit encryption** for all paravirtualized volume attachments and make it standard in ",
			Categories:     []string{"compute"},
		},
	}
}

// Metadata retorna os metadados
func (c *ComputeInstanceInTransitEncryptionEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ComputeInstanceInTransitEncryptionEnabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// ComputeInstanceSecureBootEnabled - medium
type ComputeInstanceSecureBootEnabled struct {
	metadata models.CheckMetadata
}

// NewComputeInstanceSecureBootEnabled cria nova instância
func NewComputeInstanceSecureBootEnabled() *ComputeInstanceSecureBootEnabled {
	return &ComputeInstanceSecureBootEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "compute_instance_secure_boot_enabled",
			CheckTitle:     "Compute instance has Secure Boot enabled",
			ServiceName:    "compute",
			Severity:       "medium",
			Description:    "**OCI compute instances** have **UEFI Secure Boot** enabled so the platform firmware loads only trusted, signed bootloaders, kernels, and drivers at s",
			RemediationText: "Enable **Secure Boot** across instances and prefer **shielded instances**. Pair with **TPM** and **M",
			Categories:     []string{"compute"},
		},
	}
}

// Metadata retorna os metadados
func (c *ComputeInstanceSecureBootEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *ComputeInstanceSecureBootEnabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

