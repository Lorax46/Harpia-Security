package compute

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type computeProvider interface {
	ComputeClient(ctx context.Context) (*armcompute.VirtualMachinesClient, error)
	DisksClient(ctx context.Context) (*armcompute.DisksClient, error)
	NetworkInterfacesClient(ctx context.Context) (*armnetwork.InterfacesClient, error)
	PublicIPAddressesClient(ctx context.Context) (*armnetwork.PublicIPAddressesClient, error)
}

// ==================== VM Encrypted at Rest ====================

type VMEncryptedAtRestCheck struct {
	metadata models.CheckMetadata
}

func NewVMEncryptedAtRestCheck() *VMEncryptedAtRestCheck {
	return &VMEncryptedAtRestCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "compute_vm_encrypted_at_rest",
			CheckTitle:      "VM OS disk should have encryption at rest enabled",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "VirtualMachine",
			Description:     "Azure VMs should have OS disk encryption at rest enabled",
			RemediationText: "Enable OS disk encryption using Azure Disk Encryption",
			Categories:      []string{"compute", "encryption"},
		},
	}
}

func (c *VMEncryptedAtRestCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMEncryptedAtRestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	client, err := p.ComputeClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar VMs: %w", err)
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			encrypted := false
			if vm.Properties != nil &&
				vm.Properties.StorageProfile != nil &&
				vm.Properties.StorageProfile.OSDisk != nil &&
				vm.Properties.StorageProfile.OSDisk.EncryptionSettings != nil &&
				vm.Properties.StorageProfile.OSDisk.EncryptionSettings.Enabled != nil {
				encrypted = *vm.Properties.StorageProfile.OSDisk.EncryptionSettings.Enabled
			}
			status := models.StatusFail
			ext := fmt.Sprintf("VM %s OS disk is not encrypted at rest", *vm.Name)
			if encrypted {
				status = models.StatusPass
				ext = fmt.Sprintf("VM %s OS disk is encrypted at rest", *vm.Name)
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "azure",
				Service:        "compute",
				ResourceID:     *vm.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== VM Public IP Disabled ====================

type VMPublicIPDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewVMPublicIPDisabledCheck() *VMPublicIPDisabledCheck {
	return &VMPublicIPDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "compute_vm_public_ip_disabled",
			CheckTitle:      "VMs should not have public IPs directly attached",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "VirtualMachine",
			Description:     "VMs should not have public IPs directly attached",
			RemediationText: "Remove public IPs from VMs",
			Categories:      []string{"compute", "network"},
		},
	}
}

func (c *VMPublicIPDisabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMPublicIPDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	client, err := p.ComputeClient(ctx)
	if err != nil {
		return nil, err
	}

	nicClient, err := p.NetworkInterfacesClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar VMs: %w", err)
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			hasPublicIP := false
			if vm.Properties != nil && vm.Properties.NetworkProfile != nil {
				for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
					if nicRef == nil || nicRef.ID == nil {
						continue
					}
					parts := splitAzureResourceID(*nicRef.ID)
					if len(parts) < 9 {
						continue
					}
					rg := parts[4]
					nicResp, err := nicClient.Get(ctx, rg, parts[8], nil)
					if err != nil {
						continue
					}
					if nicResp.Properties != nil && nicResp.Properties.IPConfigurations != nil {
						for _, ipCfg := range nicResp.Properties.IPConfigurations {
							if ipCfg.Properties != nil &&
								ipCfg.Properties.PublicIPAddress != nil &&
								ipCfg.Properties.PublicIPAddress.ID != nil {
								hasPublicIP = true
								break
							}
						}
					}
				}
			}
			status := models.StatusPass
			ext := fmt.Sprintf("VM %s does not have public IP", *vm.Name)
			if hasPublicIP {
				status = models.StatusFail
				ext = fmt.Sprintf("VM %s has public IP attached", *vm.Name)
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "azure",
				Service:        "compute",
				ResourceID:     *vm.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Disk Encrypted at Rest ====================

type DiskEncryptedAtRestCheck struct {
	metadata models.CheckMetadata
}

func NewDiskEncryptedAtRestCheck() *DiskEncryptedAtRestCheck {
	return &DiskEncryptedAtRestCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "compute_disk_encrypted_at_rest",
			CheckTitle:      "Managed disks should be encrypted at rest",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Disk",
			Description:     "Managed disks should be encrypted at rest",
			RemediationText: "Enable encryption on managed disks",
			Categories:      []string{"compute", "encryption"},
		},
	}
}

func (c *DiskEncryptedAtRestCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DiskEncryptedAtRestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	client, err := p.DisksClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar discos: %w", err)
		}
		for _, disk := range page.Value {
			if disk == nil || disk.Name == nil {
				continue
			}
			encrypted := false
			if disk.Properties != nil && disk.Properties.Encryption.Type != nil {
				encType := *disk.Properties.Encryption.Type
				encrypted = encType == "EncryptionAtRestWithCustomerKey" || encType == "EncryptionAtRestWithPlatformAndCustomerKeys"
			}
			status := models.StatusFail
			ext := fmt.Sprintf("Disk %s is not encrypted with customer key", *disk.Name)
			if encrypted {
				status = models.StatusPass
				ext = fmt.Sprintf("Disk %s is encrypted with customer key", *disk.Name)
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "azure",
				Service:        "compute",
				ResourceID:     *disk.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== VM Uses Managed Disks ====================

type VMUsesManagedDisksCheck struct {
	metadata models.CheckMetadata
}

func NewVMUsesManagedDisksCheck() *VMUsesManagedDisksCheck {
	return &VMUsesManagedDisksCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "compute_vm_uses_managed_disks",
			CheckTitle:      "VMs should use managed disks",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "VirtualMachine",
			Description:     "VMs should use managed disks instead of blob storage",
			RemediationText: "Migrate VMs from unmanaged to managed disks",
			Categories:      []string{"compute", "storage"},
		},
	}
}

func (c *VMUsesManagedDisksCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMUsesManagedDisksCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	client, err := p.ComputeClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar VMs: %w", err)
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			managed := false
			if vm.Properties != nil &&
				vm.Properties.StorageProfile != nil &&
				vm.Properties.StorageProfile.OSDisk != nil &&
				vm.Properties.StorageProfile.OSDisk.ManagedDisk != nil {
				managed = true
			}
			status := models.StatusFail
			ext := fmt.Sprintf("VM %s does not use managed disks", *vm.Name)
			if managed {
				status = models.StatusPass
				ext = fmt.Sprintf("VM %s uses managed disks", *vm.Name)
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "azure",
				Service:        "compute",
				ResourceID:     *vm.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}
	return findings, nil
}

// splitAzureResourceID splits an Azure resource ID into its component parts
func splitAzureResourceID(id string) []string {
	parts := make([]string, 0)
	current := ""
	for _, c := range id {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
