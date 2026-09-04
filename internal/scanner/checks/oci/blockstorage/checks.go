package blockstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// BlockVolumeEncryptedWithCmkCheck verifica se volumes de blocos usam CMK
type BlockVolumeEncryptedWithCmkCheck struct {
	metadata models.CheckMetadata
}

func NewBlockVolumeEncryptedWithCmkCheck() *BlockVolumeEncryptedWithCmkCheck {
	return &BlockVolumeEncryptedWithCmkCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "blockstorage_block_volume_encrypted_with_cmk",
			CheckTitle:      "Ensure block volumes are encrypted with CMK",
			ServiceName:     "blockstorage",
			Severity:        "medium",
			Description:     "Block volumes should be encrypted with customer managed keys",
			RemediationText: "Use CMK for block volume encryption",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BlockVolumeEncryptedWithCmkCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BlockVolumeEncryptedWithCmkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Storage() (core.BlockstorageClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Storage()")
	}

	client, err := p.Storage()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := core.ListVolumesRequest{
		CompartmentId: &tenancyId,
	}
	volumes, err := client.ListVolumes(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar volumes: %w", err)
	}

	for _, volume := range volumes.Items {
		if volume.KmsKeyId != nil && *volume.KmsKeyId != "" {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Volume %s uses CMK for encryption", *volume.DisplayName),
				ResourceID:     *volume.Id,
				Provider:       "oci",
				Service:        "blockstorage",
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
				StatusExtended: fmt.Sprintf("Volume %s uses Oracle managed keys (no CMK)", *volume.DisplayName),
				ResourceID:     *volume.Id,
				Provider:       "oci",
				Service:        "blockstorage",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No block volumes found",
			Provider:       "oci",
			Service:        "blockstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// BootVolumeEncryptedWithCmkCheck verifica se boot volumes usam CMK
type BootVolumeEncryptedWithCmkCheck struct {
	metadata models.CheckMetadata
}

func NewBootVolumeEncryptedWithCmkCheck() *BootVolumeEncryptedWithCmkCheck {
	return &BootVolumeEncryptedWithCmkCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "blockstorage_boot_volume_encrypted_with_cmk",
			CheckTitle:      "Ensure boot volumes are encrypted with CMK",
			ServiceName:     "blockstorage",
			Severity:        "medium",
			Description:     "Boot volumes should be encrypted with customer managed keys",
			RemediationText: "Use CMK for boot volume encryption",
			Categories:      []string{"storage"},
		},
	}
}

func (c *BootVolumeEncryptedWithCmkCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *BootVolumeEncryptedWithCmkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Storage() (core.BlockstorageClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Storage()")
	}

	client, err := p.Storage()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := core.ListBootVolumesRequest{
		CompartmentId: &tenancyId,
	}
	volumes, err := client.ListBootVolumes(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar boot volumes: %w", err)
	}

	for _, volume := range volumes.Items {
		if volume.KmsKeyId != nil && *volume.KmsKeyId != "" {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("Boot volume %s uses CMK for encryption", *volume.DisplayName),
				ResourceID:     *volume.Id,
				Provider:       "oci",
				Service:        "blockstorage",
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
				StatusExtended: fmt.Sprintf("Boot volume %s uses Oracle managed keys (no CMK)", *volume.DisplayName),
				ResourceID:     *volume.Id,
				Provider:       "oci",
				Service:        "blockstorage",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No boot volumes found",
			Provider:       "oci",
			Service:        "blockstorage",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
