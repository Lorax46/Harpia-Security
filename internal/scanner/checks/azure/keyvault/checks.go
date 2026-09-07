package keyvault

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type keyVaultProvider interface {
	KeyVaultsClient(ctx context.Context) (*armkeyvault.VaultsClient, error)
}

// ==================== Purge Protection Enabled ====================

type PurgeProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewPurgeProtectionCheck() *PurgeProtectionCheck {
	return &PurgeProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "keyvault_purge_protection_enabled",
			CheckTitle:      "Key Vault should have purge protection enabled",
			ServiceName:     "keyvault",
			Severity:        "critical",
			ResourceType:    "KeyVault",
			ResourceGroup:   "KeyVault",
			Description:     "Key Vault should have purge protection enabled to prevent immediate deletion of secrets",
			Risk:            "Without purge protection, deleted keys/secrets cannot be recovered",
			RemediationText: "Enable purge protection on Key Vault",
			Categories:      []string{"keyvault", "security"},
		},
	}
}

func (c *PurgeProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PurgeProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(keyVaultProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa keyVaultProvider")
	}

	client, err := p.KeyVaultsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar key vaults: %w", err)
		}
		for _, kv := range page.Value {
			if kv == nil || kv.Name == nil {
				continue
			}
			vaultResp, err := client.Get(ctx, "", *kv.Name, nil)
			if err != nil {
				continue
			}
			purgeProtection := vaultResp.Properties != nil && vaultResp.Properties.EnablePurgeProtection != nil && *vaultResp.Properties.EnablePurgeProtection
			status := models.StatusFail
			ext := fmt.Sprintf("Key Vault %s does not have purge protection enabled", *kv.Name)
			if purgeProtection {
				status = models.StatusPass
				ext = fmt.Sprintf("Key Vault %s has purge protection enabled", *kv.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "keyvault",
				ResourceID:      *kv.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Soft Delete Enabled ====================

type SoftDeleteCheck struct {
	metadata models.CheckMetadata
}

func NewSoftDeleteCheck() *SoftDeleteCheck {
	return &SoftDeleteCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "keyvault_soft_delete_enabled",
			CheckTitle:      "Key Vault should have soft delete enabled",
			ServiceName:     "keyvault",
			Severity:        "high",
			ResourceType:    "KeyVault",
			ResourceGroup:   "KeyVault",
			Description:     "Key Vault should have soft delete enabled to allow recovery of deleted vaults and secrets",
			Risk:            "Without soft delete, deleted vaults cannot be recovered",
			RemediationText: "Enable soft delete on Key Vault",
			Categories:      []string{"keyvault", "backup"},
		},
	}
}

func (c *SoftDeleteCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SoftDeleteCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(keyVaultProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa keyVaultProvider")
	}

	client, err := p.KeyVaultsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar key vaults: %w", err)
		}
		for _, kv := range page.Value {
			if kv == nil || kv.Name == nil {
				continue
			}
			vaultResp, err := client.Get(ctx, "", *kv.Name, nil)
			if err != nil {
				continue
			}
			softDelete := vaultResp.Properties != nil && vaultResp.Properties.EnableSoftDelete != nil && *vaultResp.Properties.EnableSoftDelete
			status := models.StatusFail
			ext := fmt.Sprintf("Key Vault %s does not have soft delete enabled", *kv.Name)
			if softDelete {
				status = models.StatusPass
				ext = fmt.Sprintf("Key Vault %s has soft delete enabled", *kv.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "keyvault",
				ResourceID:      *kv.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== RBAC Authorization ====================

type RBACAuthorizationCheck struct {
	metadata models.CheckMetadata
}

func NewRBACAuthorizationCheck() *RBACAuthorizationCheck {
	return &RBACAuthorizationCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "keyvault_rbac_authorization",
			CheckTitle:      "Key Vault should use Azure RBAC authorization",
			ServiceName:     "keyvault",
			Severity:        "medium",
			ResourceType:    "KeyVault",
			ResourceGroup:   "KeyVault",
			Description:     "Key Vault should use Azure RBAC for authorization instead of access policies",
			Risk:            "Legacy access policies are less flexible and harder to audit",
			RemediationText: "Enable Azure RBAC authorization on Key Vault",
			Categories:      []string{"keyvault", "iam"},
		},
	}
}

func (c *RBACAuthorizationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RBACAuthorizationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(keyVaultProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa keyVaultProvider")
	}

	client, err := p.KeyVaultsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar key vaults: %w", err)
		}
		for _, kv := range page.Value {
			if kv == nil || kv.Name == nil {
				continue
			}
			vaultResp, err := client.Get(ctx, "", *kv.Name, nil)
			if err != nil {
				continue
			}
			rbac := vaultResp.Properties != nil && vaultResp.Properties.EnableRbacAuthorization != nil && *vaultResp.Properties.EnableRbacAuthorization
			status := models.StatusFail
			ext := fmt.Sprintf("Key Vault %s does not use RBAC authorization", *kv.Name)
			if rbac {
				status = models.StatusPass
				ext = fmt.Sprintf("Key Vault %s uses RBAC authorization", *kv.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "keyvault",
				ResourceID:      *kv.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}
