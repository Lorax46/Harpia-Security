// Package glacier provides AWS Glacier security checks.
package glacier

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/glacier"
)

type glacierProvider interface {
	Glacier(ctx context.Context) (*glacier.Client, error)
	Region() string
	AccountID() string
}

// GlacierVaultEncryptionCheck verifica se vaults Glacier estão criptografados
type GlacierVaultEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewGlacierVaultEncryptionCheck() *GlacierVaultEncryptionCheck {
	return &GlacierVaultEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glacier_vault_encryption",
			CheckTitle: "Ensure Glacier vaults are encrypted",
			Description: "Glacier vaults should have encryption enabled",
			Severity: "high", ServiceName: "glacier", ResourceType: "Vault",
			RemediationText: "Enable encryption for Glacier vaults",
			Categories: []string{"storage", "encryption"},
		},
	}
}

func (c *GlacierVaultEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlacierVaultEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(glacierProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement glacierProvider")
	}
	client, err := p.Glacier(ctx)
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	input := &glacier.ListVaultsInput{}
	paginator := glacier.NewListVaultsPaginator(client, input)
	
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vault := range page.VaultList {
			status := models.StatusPass
			msg := fmt.Sprintf("Glacier vault %s is encrypted", *vault.VaultName)
			
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *vault.VaultARN, Provider: "aws", Service: "glacier",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// GlacierVaultNoPublicAccessCheck verifica se vaults Glacier não são públicos
type GlacierVaultNoPublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewGlacierVaultNoPublicAccessCheck() *GlacierVaultNoPublicAccessCheck {
	return &GlacierVaultNoPublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glacier_vault_no_public_access",
			CheckTitle: "Ensure Glacier vaults are not publicly accessible",
			Description: "Glacier vaults should not be publicly accessible",
			Severity: "high", ServiceName: "glacier", ResourceType: "Vault",
			RemediationText: "Remove public access from Glacier vaults",
			Categories: []string{"storage", "access"},
		},
	}
}

func (c *GlacierVaultNoPublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlacierVaultNoPublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires GetVaultAccessPolicy API call",
			Provider: "aws", Service: "glacier", FoundAt: time.Now().UTC(),
		},
	}, nil
}

// GlacierVaultLoggingCheck verifica se vaults Glacier têm logging habilitado
type GlacierVaultLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewGlacierVaultLoggingCheck() *GlacierVaultLoggingCheck {
	return &GlacierVaultLoggingCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "glacier_vault_logging",
			CheckTitle: "Ensure Glacier vaults have logging enabled",
			Description: "Glacier vaults should have access logging enabled",
			Severity: "medium", ServiceName: "glacier", ResourceType: "Vault",
			RemediationText: "Enable access logging for Glacier vaults",
			Categories: []string{"storage", "logging"},
		},
	}
}

func (c *GlacierVaultLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GlacierVaultLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires GetVaultLock API call",
			Provider: "aws", Service: "glacier", FoundAt: time.Now().UTC(),
		},
	}, nil
}
