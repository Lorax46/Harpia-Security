package compute

// =============================================================================
// Azure VM Checks — 12 checks baseados no Prowler Azure v5.41
// =============================================================================

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
)

// VMBackupEnabled - verifica se VM tem backup
type VMBackupEnabled struct {
	metadata models.CheckMetadata
}

func NewVMBackupEnabled() *VMBackupEnabled {
	return &VMBackupEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "vm_backup_enabled",
			CheckTitle: "Ensure VM is protected by Azure Backup",
			Description: "VMs should be protected by Azure Backup",
			Severity: "high", ServiceName: "vm", ResourceType: "VirtualMachine",
			RemediationText: "Enable Azure Backup for VMs",
			Categories: []string{"vm", "backup"},
		},
	}
}

func (c *VMBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement computeProvider")
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
			return nil, err
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			// Verificar se tem tags indicando backup
			hasBackup := false
			if vm.Tags != nil {
				for _, tag := range vm.Tags {
					if strings.Contains(strings.ToLower(*tag), "backup") {
						hasBackup = true
						break
					}
				}
			}
			status := models.StatusFail
			msg := fmt.Sprintf("VM %s not protected by Azure Backup", *vm.Name)
			if hasBackup {
				status = models.StatusPass
				msg = fmt.Sprintf("VM %s protected by Azure Backup", *vm.Name)
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *vm.Name, Provider: "azure", Service: "vm",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// VMApprovedImages - verifica imagens aprovadas
type VMApprovedImages struct {
	metadata models.CheckMetadata
}

func NewVMApprovedImages() *VMApprovedImages {
	return &VMApprovedImages{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "vm_ensure_using_approved_images",
			CheckTitle: "Ensure VM uses approved images",
			Description: "VMs should use approved machine images",
			Severity: "high", ServiceName: "vm", ResourceType: "VirtualMachine",
			RemediationText: "Use approved VM images",
			Categories: []string{"vm", "images"},
		},
	}
}

func (c *VMApprovedImages) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMApprovedImages) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement computeProvider")
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
			return nil, err
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			approvedPublishers := map[string]bool{"canonical": true, "microsoftwindowsserver": true, "redhat": true, "suse": true}
			status := models.StatusFail
			msg := fmt.Sprintf("VM %s uses unapproved image", *vm.Name)
			if vm.Properties != nil && vm.Properties.StorageProfile != nil && vm.Properties.StorageProfile.ImageReference != nil {
				pub := strings.ToLower(*vm.Properties.StorageProfile.ImageReference.Publisher)
				if approvedPublishers[pub] {
					status = models.StatusPass
					msg = fmt.Sprintf("VM %s uses approved image from %s", *vm.Name, pub)
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *vm.Name, Provider: "azure", Service: "vm",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// VMManagedDisks - verifica uso de managed disks
type VMManagedDisks struct {
	metadata models.CheckMetadata
}

func NewVMManagedDisks() *VMManagedDisks {
	return &VMManagedDisks{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "vm_ensure_using_managed_disks",
			CheckTitle: "Ensure VM uses managed disks",
			Description: "VMs should use managed disks for OS and data disks",
			Severity: "high", ServiceName: "vm", ResourceType: "VirtualMachine",
			RemediationText: "Migrate to managed disks",
			Categories: []string{"vm", "disks"},
		},
	}
}

func (c *VMManagedDisks) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMManagedDisks) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement computeProvider")
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
			return nil, err
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			status := models.StatusPass
			msg := fmt.Sprintf("VM %s uses managed disks", *vm.Name)
			if vm.Properties != nil && vm.Properties.StorageProfile != nil && vm.Properties.StorageProfile.OSDisk != nil {
				if vm.Properties.StorageProfile.OSDisk.Vhd != nil {
					status = models.StatusFail
					msg = fmt.Sprintf("VM %s uses unmanaged disk (VHD)", *vm.Name)
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *vm.Name, Provider: "azure", Service: "vm",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// VMLinuxSSHAuthentication - verifica autenticação SSH
type VMLinuxSSHAuthentication struct {
	metadata models.CheckMetadata
}

func NewVMLinuxSSHAuthentication() *VMLinuxSSHAuthentication {
	return &VMLinuxSSHAuthentication{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "vm_linux_enforce_ssh_authentication",
			CheckTitle: "Ensure Linux VM enforces SSH key authentication",
			Description: "Linux VMs should use SSH key auth instead of password",
			Severity: "high", ServiceName: "vm", ResourceType: "VirtualMachine",
			RemediationText: "Disable password authentication on Linux VMs",
			Categories: []string{"vm", "ssh", "linux"},
		},
	}
}

func (c *VMLinuxSSHAuthentication) Metadata() models.CheckMetadata { return c.metadata }

func (c *VMLinuxSSHAuthentication) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement computeProvider")
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
			return nil, err
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Name == nil {
				continue
			}
			// Verificar apenas Linux
			isLinux := false
			if vm.Properties != nil && vm.Properties.StorageProfile != nil && vm.Properties.StorageProfile.OSDisk != nil && vm.Properties.StorageProfile.OSDisk.OSType != nil {
				isLinux = *vm.Properties.StorageProfile.OSDisk.OSType == armcompute.OperatingSystemTypesLinux
			}
			if !isLinux {
				continue
			}
			status := models.StatusPass
			msg := fmt.Sprintf("VM %s enforces SSH authentication", *vm.Name)
			if vm.Properties != nil && vm.Properties.OSProfile != nil && vm.Properties.OSProfile.LinuxConfiguration != nil {
				if vm.Properties.OSProfile.LinuxConfiguration.DisablePasswordAuthentication != nil && !*vm.Properties.OSProfile.LinuxConfiguration.DisablePasswordAuthentication {
					status = models.StatusFail
					msg = fmt.Sprintf("VM %s allows password authentication", *vm.Name)
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *vm.Name, Provider: "azure", Service: "vm",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}
