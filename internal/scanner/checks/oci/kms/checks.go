package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// KmsKeyRotationEnabled verifica se a rotação de chave KMS está habilitada
type KmsKeyRotationEnabled struct {
	metadata models.CheckMetadata
}

func NewKmsKeyRotationEnabled() *KmsKeyRotationEnabled {
	return &KmsKeyRotationEnabled{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "kms_key_rotation_enabled",
			CheckTitle:      "Customer-managed KMS key has rotation enabled with interval of 365 days or less",
			ServiceName:     "kms",
			Severity:        "high",
			Description:     "OCI KMS customer-managed keys should have automatic rotation enabled or be manually rotated within 365 days.",
			RemediationText: "Enable automatic key rotation and set an interval <= 365 days.",
			Categories:      []string{"kms"},
		},
	}
}

func (c *KmsKeyRotationEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *KmsKeyRotationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		KmsVault() (keymanagement.KmsVaultClient, error)
		Config() common.ConfigurationProvider
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa KmsVault() ou Config()")
	}

	vaultClient, err := p.KmsVault()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	config := p.Config()
	findings := []models.Finding{}

	// Listar todos os vaults no tenancy
	vaultsReq := keymanagement.ListVaultsRequest{
		CompartmentId: &tenancyId,
	}

	vaultsResp, err := vaultClient.ListVaults(ctx, vaultsReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar vaults KMS: %w", err)
	}

	for _, vault := range vaultsResp.Items {
		if vault.LifecycleState != "ACTIVE" {
			continue
		}

		// Criar cliente de gerenciamento para o endpoint deste vault
		managementEndpoint := vault.ManagementEndpoint
		if managementEndpoint == nil || *managementEndpoint == "" {
			continue
		}

		mgmtClient, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(
			config,
			*managementEndpoint,
		)
		if err != nil {
			continue
		}

		// Listar keys neste vault
		keysReq := keymanagement.ListKeysRequest{
			CompartmentId: &tenancyId,
		}

		keysResp, err := mgmtClient.ListKeys(ctx, keysReq)
		if err != nil {
			continue
		}

		for _, keySummary := range keysResp.Items {
			if keySummary.LifecycleState != "ENABLED" {
				continue
			}

			// Obter detalhes completos da key (para info de rotação)
			keyReq := keymanagement.GetKeyRequest{
				KeyId: keySummary.Id,
			}

			keyDetails, err := mgmtClient.GetKey(ctx, keyReq)
			if err != nil {
				continue
			}

			key := keyDetails.Key

			now := time.Now().UTC()
			maxAge := 365 * 24 * time.Hour

			manuallyRotated := false
			if key.TimeCreated != nil {
				age := now.Sub(key.TimeCreated.Time)
				if age <= maxAge {
					manuallyRotated = true
				}
			}

			hasRotation := false
			rotationInfo := ""

			if key.IsAutoRotationEnabled != nil && *key.IsAutoRotationEnabled {
				hasRotation = true
				if key.AutoKeyRotationDetails != nil && key.AutoKeyRotationDetails.RotationIntervalInDays != nil {
					rotationInfo = fmt.Sprintf("auto-rotation enabled with interval of %d days", *key.AutoKeyRotationDetails.RotationIntervalInDays)
				} else {
					rotationInfo = "auto-rotation enabled"
				}
			} else if manuallyRotated {
				hasRotation = true
				rotationInfo = "manually rotated within the last 365 days"
			} else if key.AutoKeyRotationDetails != nil && key.AutoKeyRotationDetails.RotationIntervalInDays != nil && *key.AutoKeyRotationDetails.RotationIntervalInDays <= 365 {
				hasRotation = true
				rotationInfo = fmt.Sprintf("rotation interval set to %d days", *key.AutoKeyRotationDetails.RotationIntervalInDays)
			}

			if hasRotation {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("KMS key %s has %s.", safeString(key.DisplayName), rotationInfo),
					ResourceID:     safeString(key.Id),
					Provider:       "oci",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			} else {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("KMS key %s has not been rotated within the last 365 days and does not have auto-rotation enabled.", safeString(key.DisplayName)),
					ResourceID:     safeString(key.Id),
					Provider:       "oci",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No KMS keys found",
			Provider:       "oci",
			Service:        "kms",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
