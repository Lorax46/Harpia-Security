package filestorage

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/filestorage"
)

// FilestorageFileSystemEncryptedWithCmk verifica se o file system está criptografado com CMK
type FilestorageFileSystemEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

func NewFilestorageFileSystemEncryptedWithCmk() *FilestorageFileSystemEncryptedWithCmk {
	return &FilestorageFileSystemEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "filestorage_file_system_encrypted_with_cmk",
			CheckTitle:      "File Storage file system is encrypted with a customer-managed KMS key",
			ServiceName:     "filestorage",
			Severity:        "medium",
			Description:     "OCI File Storage file systems should use Customer-Managed Keys (CMEK) for encryption.",
			RemediationText: "Encrypt file systems with Customer-Managed Keys in OCI KMS.",
			Categories:      []string{"filestorage"},
		},
	}
}

func (c *FilestorageFileSystemEncryptedWithCmk) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *FilestorageFileSystemEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		FileStorage() (filestorage.FileStorageClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa FileStorage()")
	}

	client, err := p.FileStorage()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	// Listar mount targets primeiro (precisam do availability domain)
	mtReq := filestorage.ListMountTargetsRequest{
		CompartmentId: &tenancyId,
	}

	mtResp, err := client.ListMountTargets(ctx, mtReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar mount targets: %w", err)
	}

	// Extrair availability domains únicos dos mount targets
	adMap := map[string]bool{}
	for _, mt := range mtResp.Items {
		if mt.AvailabilityDomain != nil {
			adMap[*mt.AvailabilityDomain] = true
		}
	}

	// Para cada availability domain, listar file systems
	for ad := range adMap {
		fsReq := filestorage.ListFileSystemsRequest{
			CompartmentId:      &tenancyId,
			AvailabilityDomain: &ad,
		}

		fsResp, err := client.ListFileSystems(ctx, fsReq)
		if err != nil {
			continue
		}

		for _, fs := range fsResp.Items {
			if fs.LifecycleState != "ACTIVE" {
				continue
			}

			if fs.KmsKeyId != nil && *fs.KmsKeyId != "" {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("File system %s is encrypted with CMK (KMS key: %s).", safeString(fs.DisplayName), *fs.KmsKeyId),
					ResourceID:     safeString(fs.Id),
					Provider:       "oci",
					Service:        "filestorage",
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
					StatusExtended: fmt.Sprintf("File system %s uses Oracle-managed key (not CMK).", safeString(fs.DisplayName)),
					ResourceID:     safeString(fs.Id),
					Provider:       "oci",
					Service:        "filestorage",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	// Se não encontrou mount targets, tentar listar sem AD específico
	if len(adMap) == 0 {
		fsReq := filestorage.ListFileSystemsRequest{
			CompartmentId: &tenancyId,
		}

		fsResp, err := client.ListFileSystems(ctx, fsReq)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar file systems: %w", err)
		}

		for _, fs := range fsResp.Items {
			if fs.LifecycleState != "ACTIVE" {
				continue
			}

			if fs.KmsKeyId != nil && *fs.KmsKeyId != "" {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("File system %s is encrypted with CMK (KMS key: %s).", safeString(fs.DisplayName), *fs.KmsKeyId),
					ResourceID:     safeString(fs.Id),
					Provider:       "oci",
					Service:        "filestorage",
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
					StatusExtended: fmt.Sprintf("File system %s uses Oracle-managed key (not CMK).", safeString(fs.DisplayName)),
					ResourceID:     safeString(fs.Id),
					Provider:       "oci",
					Service:        "filestorage",
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
			StatusExtended: "No active file systems found",
			Provider:       "oci",
			Service:        "filestorage",
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
