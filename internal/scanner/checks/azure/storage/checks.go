package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type storageProvider interface {
	StorageAccountsClient(ctx context.Context) (*armstorage.AccountsClient, error)
}

// ==================== HTTPS Traffic Only ====================

type HTTPSOnlyCheck struct {
	metadata models.CheckMetadata
}

func NewHTTPSOnlyCheck() *HTTPSOnlyCheck {
	return &HTTPSOnlyCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "storage_https_traffic_only",
			CheckTitle:      "Storage Accounts should use HTTPS only",
			ServiceName:     "storage",
			Severity:        "critical",
			ResourceType:    "StorageAccount",
			ResourceGroup:   "Storage",
			Description:     "Storage Accounts should require HTTPS traffic only",
			Risk:            "HTTP traffic allows data to be intercepted",
			RemediationText: "Enable HTTPS-only traffic on Storage Accounts",
			Categories:      []string{"storage", "network"},
		},
	}
}

func (c *HTTPSOnlyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HTTPSOnlyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}

	client, err := p.StorageAccountsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar storage accounts: %w", err)
		}
		for _, sa := range page.Value {
			if sa == nil || sa.Name == nil {
				continue
			}
			httpsOnly := sa.Properties != nil && sa.Properties.EnableHTTPSTrafficOnly != nil && *sa.Properties.EnableHTTPSTrafficOnly
			status := models.StatusFail
			ext := fmt.Sprintf("Storage Account %s allows HTTP traffic", *sa.Name)
			if httpsOnly {
				status = models.StatusPass
				ext = fmt.Sprintf("Storage Account %s requires HTTPS only", *sa.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "storage",
				ResourceID:      *sa.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Storage Encryption at Rest ====================

type StorageEncryptionAtRestCheck struct {
	metadata models.CheckMetadata
}

func NewStorageEncryptionAtRestCheck() *StorageEncryptionAtRestCheck {
	return &StorageEncryptionAtRestCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "storage_encryption_at_rest",
			CheckTitle:      "Storage Accounts should have encryption at rest",
			ServiceName:     "storage",
			Severity:        "high",
			ResourceType:    "StorageAccount",
			ResourceGroup:   "Storage",
			Description:     "Storage Accounts should have encryption at rest enabled for blobs and files",
			Risk:            "Without encryption, stored data can be accessed by unauthorized parties",
			RemediationText: "Enable encryption at rest on Storage Accounts",
			Categories:      []string{"storage", "encryption"},
		},
	}
}

func (c *StorageEncryptionAtRestCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StorageEncryptionAtRestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}

	client, err := p.StorageAccountsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar storage accounts: %w", err)
		}
		for _, sa := range page.Value {
			if sa == nil || sa.Name == nil {
				continue
			}
			encrypted := false
			if sa.Properties != nil && sa.Properties.Encryption.Services != nil {
				if sa.Properties.Encryption.Services.Blob != nil {
					encrypted = sa.Properties.Encryption.Services.Blob.Enabled != nil && *sa.Properties.Encryption.Services.Blob.Enabled
				}
				if sa.Properties.Encryption.Services.File != nil && !encrypted {
					encrypted = sa.Properties.Encryption.Services.File.Enabled != nil && *sa.Properties.Encryption.Services.File.Enabled
				}
			}
			status := models.StatusFail
			ext := fmt.Sprintf("Storage Account %s does not have encryption at rest", *sa.Name)
			if encrypted {
				status = models.StatusPass
				ext = fmt.Sprintf("Storage Account %s has encryption at rest enabled", *sa.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "storage",
				ResourceID:      *sa.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Storage Public Access Disabled ====================

type PublicAccessDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewPublicAccessDisabledCheck() *PublicAccessDisabledCheck {
	return &PublicAccessDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "storage_public_access_disabled",
			CheckTitle:      "Storage Accounts should not allow public access",
			ServiceName:     "storage",
			Severity:        "critical",
			ResourceType:    "StorageAccount",
			ResourceGroup:   "Storage",
			Description:     "Storage Accounts should not allow public blob access",
			Risk:            "Public access to storage can expose sensitive data",
			RemediationText: "Disable public blob access on Storage Accounts",
			Categories:      []string{"storage", "security"},
		},
	}
}

func (c *PublicAccessDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicAccessDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}

	client, err := p.StorageAccountsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar storage accounts: %w", err)
		}
		for _, sa := range page.Value {
			if sa == nil || sa.Name == nil {
				continue
			}
			publicAccess := sa.Properties != nil && sa.Properties.AllowBlobPublicAccess != nil && *sa.Properties.AllowBlobPublicAccess
			status := models.StatusPass
			ext := fmt.Sprintf("Storage Account %s does not allow public blob access", *sa.Name)
			if publicAccess {
				status = models.StatusFail
				ext = fmt.Sprintf("Storage Account %s allows public blob access", *sa.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "storage",
				ResourceID:      *sa.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Minimum TLS Version ====================

type MinimumTLSVersionCheck struct {
	metadata models.CheckMetadata
}

func NewMinimumTLSVersionCheck() *MinimumTLSVersionCheck {
	return &MinimumTLSVersionCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "storage_minimum_tls_version",
			CheckTitle:      "Storage Accounts should use TLS 1.2 minimum",
			ServiceName:     "storage",
			Severity:        "medium",
			ResourceType:    "StorageAccount",
			ResourceGroup:   "Storage",
			Description:     "Storage Accounts should use TLS 1.2 as minimum version",
			Risk:            "Older TLS versions are vulnerable to known attacks",
			RemediationText: "Set MinimumTlsVersion to TLS1_2 on Storage Accounts",
			Categories:      []string{"storage", "network"},
		},
	}
}

func (c *MinimumTLSVersionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MinimumTLSVersionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}

	client, err := p.StorageAccountsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar storage accounts: %w", err)
		}
		for _, sa := range page.Value {
			if sa == nil || sa.Name == nil {
				continue
			}
			tlsOK := sa.Properties != nil && sa.Properties.MinimumTLSVersion != nil && *sa.Properties.MinimumTLSVersion == "TLS1_2"
			status := models.StatusFail
			ext := fmt.Sprintf("Storage Account %s does not require TLS 1.2", *sa.Name)
			if tlsOK {
				status = models.StatusPass
				ext = fmt.Sprintf("Storage Account %s requires TLS 1.2", *sa.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "storage",
				ResourceID:      *sa.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Storage Shared Key Access Disabled ====================

type SharedKeyAccessDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewSharedKeyAccessDisabledCheck() *SharedKeyAccessDisabledCheck {
	return &SharedKeyAccessDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "storage_shared_key_access_disabled",
			CheckTitle:      "Storage Accounts should disable shared key access",
			ServiceName:     "storage",
			Severity:        "medium",
			ResourceType:    "StorageAccount",
			ResourceGroup:   "Storage",
			Description:     "Storage Accounts should disable shared key access and require Azure AD authentication",
			Risk:            "Shared key access can be exploited if keys are compromised",
			RemediationText: "Disable shared key access on Storage Accounts and use Azure AD",
			Categories:      []string{"storage", "authentication"},
		},
	}
}

func (c *SharedKeyAccessDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SharedKeyAccessDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(storageProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa storageProvider")
	}

	client, err := p.StorageAccountsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar storage accounts: %w", err)
		}
		for _, sa := range page.Value {
			if sa == nil || sa.Name == nil {
				continue
			}
			keyAccess := sa.Properties != nil && sa.Properties.AllowSharedKeyAccess != nil && *sa.Properties.AllowSharedKeyAccess
			status := models.StatusPass
			ext := fmt.Sprintf("Storage Account %s has shared key access disabled", *sa.Name)
			if keyAccess {
				status = models.StatusFail
				ext = fmt.Sprintf("Storage Account %s allows shared key access", *sa.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "storage",
				ResourceID:      *sa.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}
