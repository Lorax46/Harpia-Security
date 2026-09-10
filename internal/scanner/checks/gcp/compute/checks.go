package compute

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/compute/v1"
)

// Provider interface for Compute checks
type computeProvider interface {
	Compute(ctx context.Context) (*compute.Service, error)
	ProjectID() string
}

// Helper functions
func containsPort(ports []string, target string) bool {
	for _, port := range ports {
		if port == target {
			return true
		}
		if strings.Contains(port, "-") {
			parts := strings.Split(port, "-")
			if len(parts) == 2 {
				if parts[0] <= target && target <= parts[1] {
					return true
				}
			}
		}
	}
	return false
}

func containsString(m map[string]string, s string) bool {
	for k, v := range m {
		if strings.Contains(strings.ToLower(k), s) || strings.Contains(strings.ToLower(v), s) {
			return true
		}
	}
	return false
}

// FirewallRdpAccessFromTheInternetAllowedCheck struct
type FirewallRdpAccessFromTheInternetAllowedCheck struct {
	metadata models.CheckMetadata
}

func NewFirewallRdpAccessFromTheInternetAllowedCheck() *FirewallRdpAccessFromTheInternetAllowedCheck {
	return &FirewallRdpAccessFromTheInternetAllowedCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_firewall_rdp_access_from_the_internet_allowed",
			CheckTitle:      "Firewall rule does not allow ingress from 0.0.0.0/0 to TCP port 3389 (RDP)",
			ServiceName:     "compute",
			Severity:        "critical",
			ResourceType:    "Firewall",
			ResourceGroup:   "Compute",
			Description:     "VPC firewall rules permitting inbound RDP (TCP 3389) from 0.0.0.0/0 are flagged.",
			Risk:            "VPC firewall rules permitting inbound RDP (TCP 3389) from 0.0.0.0/0 are flagged.",
			RemediationText: "Restrict RDP to trusted IP ranges or a hardened bastion/IAP proxy.",
			RemediationURL:  "https://cloud.google.com/vpc/docs/firewalls",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *FirewallRdpAccessFromTheInternetAllowedCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *FirewallRdpAccessFromTheInternetAllowedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	firewalls, err := computeClient.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar firewalls: %w", err)
	}

	hasRDPExposure := false
	for _, fw := range firewalls.Items {
		if fw.Direction == "INGRESS" {
			for _, allowed := range fw.Allowed {
				if allowed.IPProtocol == "tcp" && containsPort(allowed.Ports, "3389") {
					for _, source := range fw.SourceRanges {
						if source == "0.0.0.0/0" {
							hasRDPExposure = true
							findings = append(findings, models.Finding{
								ID:             c.metadata.CheckID,
								Title:          c.metadata.CheckTitle,
								Description:    c.metadata.Description,
								Severity:       c.metadata.Severity,
								Status:         models.StatusFail,
								StatusExtended: fmt.Sprintf("Firewall rule %s allows RDP from 0.0.0.0/0", fw.Name),
								ResourceID:     fw.Name,
								ResourceARN:    fmt.Sprintf("projects/%s/global/firewalls/%s", projectID, fw.Name),
								Provider:       "gcp",
								Service:        "compute",
								Remediation:    c.metadata.RemediationText,
								Categories:     c.metadata.Categories,
								FoundAt:        time.Now(),
							})
						}
					}
				}
			}
		}
	}

	if !hasRDPExposure {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("No firewall rules expose RDP to the internet in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// FirewallSshAccessFromTheInternetAllowedCheck struct
type FirewallSshAccessFromTheInternetAllowedCheck struct {
	metadata models.CheckMetadata
}

func NewFirewallSshAccessFromTheInternetAllowedCheck() *FirewallSshAccessFromTheInternetAllowedCheck {
	return &FirewallSshAccessFromTheInternetAllowedCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_firewall_ssh_access_from_the_internet_allowed",
			CheckTitle:      "Firewall does not expose TCP port 22 (SSH) to the Internet",
			ServiceName:     "compute",
			Severity:        "critical",
			ResourceType:    "Firewall",
			ResourceGroup:   "Compute",
			Description:     "VPC firewall rules allowing Internet-sourced ingress (0.0.0.0/0) to TCP port 22 (SSH) are identified.",
			Risk:            "VPC firewall rules allowing Internet-sourced ingress (0.0.0.0/0) to TCP port 22 (SSH) are identified.",
			RemediationText: "Restrict SSH to trusted sources; avoid 0.0.0.0/0. Prefer bastion hosts or IAP TCP forwarding.",
			RemediationURL:  "https://cloud.google.com/vpc/docs/firewalls",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *FirewallSshAccessFromTheInternetAllowedCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *FirewallSshAccessFromTheInternetAllowedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	firewalls, err := computeClient.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar firewalls: %w", err)
	}

	hasSSHExposure := false
	for _, fw := range firewalls.Items {
		if fw.Direction == "INGRESS" {
			for _, allowed := range fw.Allowed {
				if allowed.IPProtocol == "tcp" && containsPort(allowed.Ports, "22") {
					for _, source := range fw.SourceRanges {
						if source == "0.0.0.0/0" {
							hasSSHExposure = true
							findings = append(findings, models.Finding{
								ID:             c.metadata.CheckID,
								Title:          c.metadata.CheckTitle,
								Description:    c.metadata.Description,
								Severity:       c.metadata.Severity,
								Status:         models.StatusFail,
								StatusExtended: fmt.Sprintf("Firewall rule %s allows SSH from 0.0.0.0/0", fw.Name),
								ResourceID:     fw.Name,
								ResourceARN:    fmt.Sprintf("projects/%s/global/firewalls/%s", projectID, fw.Name),
								Provider:       "gcp",
								Service:        "compute",
								Remediation:    c.metadata.RemediationText,
								Categories:     c.metadata.Categories,
								FoundAt:        time.Now(),
							})
						}
					}
				}
			}
		}
	}

	if !hasSSHExposure {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("No firewall rules expose SSH to the internet in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ImageNotPubliclySharedCheck struct
type ImageNotPubliclySharedCheck struct {
	metadata models.CheckMetadata
}

func NewImageNotPubliclySharedCheck() *ImageNotPubliclySharedCheck {
	return &ImageNotPubliclySharedCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_image_not_publicly_shared",
			CheckTitle:      "Compute Engine disk image is not publicly shared",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Image",
			ResourceGroup:   "Compute",
			Description:     "Custom disk images should not be shared publicly with allAuthenticatedUsers.",
			Risk:            "Custom disk images should not be shared publicly with allAuthenticatedUsers.",
			RemediationText: "Restrict access to custom disk images by removing the allAuthenticatedUsers IAM binding.",
			RemediationURL:  "https://cloud.google.com/compute/docs/images",
			Categories:      []string{"compute", "sharing"},
		},
	}
}

func (c *ImageNotPubliclySharedCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *ImageNotPubliclySharedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	images, err := computeClient.Images.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar images: %w", err)
	}

	hasPublicImage := false
	for _, img := range images.Items {
		if containsString(img.Labels, "public") || img.Status != "READY" {
			hasPublicImage = true
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Image %s may be publicly accessible", img.Name),
				ResourceID:     img.Name,
				ResourceARN:    fmt.Sprintf("projects/%s/global/images/%s", projectID, img.Name),
				Provider:       "gcp",
				Service:        "compute",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if !hasPublicImage {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("No publicly shared images found in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// InstanceAutomaticRestartEnabledCheck struct
type InstanceAutomaticRestartEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceAutomaticRestartEnabledCheck() *InstanceAutomaticRestartEnabledCheck {
	return &InstanceAutomaticRestartEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_automatic_restart_enabled",
			CheckTitle:      "Compute Engine VM instances have Automatic Restart enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Google Compute Engine virtual machine instances are evaluated to ensure that Automatic Restart is enabled.",
			Risk:            "Google Compute Engine virtual machine instances are evaluated to ensure that Automatic Restart is enabled.",
			RemediationText: "Enable the Automatic Restart feature for Compute Engine VM instances.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "availability"},
		},
	}
}

func (c *InstanceAutomaticRestartEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceAutomaticRestartEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_automatic_restart_enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceAutomaticRestartEnabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceAutomaticRestartEnabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceBlockProjectWideSshKeysDisabledCheck struct
type InstanceBlockProjectWideSshKeysDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceBlockProjectWideSshKeysDisabledCheck() *InstanceBlockProjectWideSshKeysDisabledCheck {
	return &InstanceBlockProjectWideSshKeysDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_block_project_wide_ssh_keys_disabled",
			CheckTitle:      "VM instance has Block project-wide SSH keys enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VMs are evaluated for the metadata key block-project-ssh-keys set to true.",
			Risk:            "Compute Engine VMs are evaluated for the metadata key block-project-ssh-keys set to true.",
			RemediationText: "Set block-project-ssh-keys=true to prevent shared key inheritance.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "access"},
		},
	}
}

func (c *InstanceBlockProjectWideSshKeysDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceBlockProjectWideSshKeysDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_block_project_wide_ssh_keys_disabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceBlockProjectWideSshKeysDisabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceBlockProjectWideSshKeysDisabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceConfidentialComputingEnabledCheck struct
type InstanceConfidentialComputingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceConfidentialComputingEnabledCheck() *InstanceConfidentialComputingEnabledCheck {
	return &InstanceConfidentialComputingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_confidential_computing_enabled",
			CheckTitle:      "Compute instance has Confidential Computing enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Google Compute Engine VMs configured as Confidential VMs encrypt data in use with hardware-based memory protection.",
			Risk:            "Google Compute Engine VMs configured as Confidential VMs encrypt data in use with hardware-based memory protection.",
			RemediationText: "Enable Confidential VMs for workloads processing sensitive data.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "security"},
		},
	}
}

func (c *InstanceConfidentialComputingEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceConfidentialComputingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_confidential_computing_enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceConfidentialComputingEnabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceConfidentialComputingEnabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceDefaultServiceAccountDisabledCheck struct
type InstanceDefaultServiceAccountDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceDefaultServiceAccountDisabledCheck() *InstanceDefaultServiceAccountDisabledCheck {
	return &InstanceDefaultServiceAccountDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_default_service_account_disabled",
			CheckTitle:      "Compute Engine instance does not use the default service account",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VMs are evaluated for use of the default service account.",
			Risk:            "Compute Engine VMs are evaluated for use of the default service account.",
			RemediationText: "Avoid the default service account. Create per-workload service accounts with least privilege.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "iam"},
		},
	}
}

func (c *InstanceDefaultServiceAccountDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceDefaultServiceAccountDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_default_service_account_disabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceDefaultServiceAccountDisabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceDefaultServiceAccountDisabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceDeletionProtectionEnabledCheck struct
type InstanceDeletionProtectionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceDeletionProtectionEnabledCheck() *InstanceDeletionProtectionEnabledCheck {
	return &InstanceDeletionProtectionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_deletion_protection_enabled",
			CheckTitle:      "VM instance has deletion protection enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "This check verifies whether GCP Compute Engine VM instances have deletion protection enabled.",
			Risk:            "This check verifies whether GCP Compute Engine VM instances have deletion protection enabled.",
			RemediationText: "Enable deletion protection on all production and business-critical VM instances.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "protection"},
		},
	}
}

func (c *InstanceDeletionProtectionEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceDeletionProtectionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_deletion_protection_enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceDeletionProtectionEnabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceDeletionProtectionEnabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceDiskEncryptionCmekCheck struct
type InstanceDiskEncryptionCmekCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceDiskEncryptionCmekCheck() *InstanceDiskEncryptionCmekCheck {
	return &InstanceDiskEncryptionCmekCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_disk_encryption_cmek",
			CheckTitle:      "VM instance disks are encrypted with Customer-Managed Keys (CMEK)",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VM disks should use Customer-Managed Encryption Keys (CMEK) rather than Google-managed keys.",
			Risk:            "Compute Engine VM disks should use Customer-Managed Encryption Keys (CMEK) rather than Google-managed keys.",
			RemediationText: "Configure VM disks to use CMEK via Cloud KMS for enhanced key control.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "encryption"},
		},
	}
}

func (c *InstanceDiskEncryptionCmekCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceDiskEncryptionCmekCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_disk_encryption_cmek in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceDiskEncryptionCmekCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceDiskEncryptionCmekCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceDiskEncryptionDisabledCheck struct
type InstanceDiskEncryptionDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceDiskEncryptionDisabledCheck() *InstanceDiskEncryptionDisabledCheck {
	return &InstanceDiskEncryptionDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_disk_encryption_disabled",
			CheckTitle:      "VM instance disk encryption status is monitored",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VM disks should have proper encryption configuration.",
			Risk:            "Compute Engine VM disks should have proper encryption configuration.",
			RemediationText: "Ensure all VM disks use appropriate encryption. Prefer CMEK for sensitive workloads.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "encryption"},
		},
	}
}

func (c *InstanceDiskEncryptionDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceDiskEncryptionDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_disk_encryption_disabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceDiskEncryptionDisabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceDiskEncryptionDisabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceDisplayDisabledCheck struct
type InstanceDisplayDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceDisplayDisabledCheck() *InstanceDisplayDisabledCheck {
	return &InstanceDisplayDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_display_disabled",
			CheckTitle:      "VM instance has Display Device disabled",
			ServiceName:     "compute",
			Severity:        "low",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VMs should have display device disabled unless required.",
			Risk:            "Compute Engine VMs should have display device disabled unless required.",
			RemediationText: "Disable display device on VM instances unless explicitly needed.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "hardening"},
		},
	}
}

func (c *InstanceDisplayDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceDisplayDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_display_disabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceDisplayDisabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceDisplayDisabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceIpForwardingDisabledCheck struct
type InstanceIpForwardingDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceIpForwardingDisabledCheck() *InstanceIpForwardingDisabledCheck {
	return &InstanceIpForwardingDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_ip_forwarding_disabled",
			CheckTitle:      "Compute Engine VM instance has IP forwarding disabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VM instances with canIpForward enabled are identified.",
			Risk:            "Compute Engine VM instances with canIpForward enabled are identified.",
			RemediationText: "Disable IP forwarding on general-purpose VMs.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *InstanceIpForwardingDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceIpForwardingDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_ip_forwarding_disabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceIpForwardingDisabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceIpForwardingDisabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceNoPublicIpCheck struct
type InstanceNoPublicIpCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceNoPublicIpCheck() *InstanceNoPublicIpCheck {
	return &InstanceNoPublicIpCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_no_public_ip",
			CheckTitle:      "VM instance does not have a public IP address",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VM instances with an assigned external (public) IP address are identified.",
			Risk:            "Compute Engine VM instances with an assigned external (public) IP address are identified.",
			RemediationText: "Adopt private-only VMs and remove external IPs. Use Cloud NAT for egress.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *InstanceNoPublicIpCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceNoPublicIpCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_no_public_ip in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceNoPublicIpCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceNoPublicIpCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceNoSerialPortsCheck struct
type InstanceNoSerialPortsCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceNoSerialPortsCheck() *InstanceNoSerialPortsCheck {
	return &InstanceNoSerialPortsCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_no_serial_ports",
			CheckTitle:      "VM instance has serial ports disabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "VM instances should have interactive serial console disabled for security.",
			Risk:            "VM instances should have interactive serial console disabled for security.",
			RemediationText: "Disable the interactive serial console on production VMs (serial-port-enable=false).",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "access"},
		},
	}
}

func (c *InstanceNoSerialPortsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceNoSerialPortsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_no_serial_ports in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceNoSerialPortsCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceNoSerialPortsCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstancePreemptibleDisabledCheck struct
type InstancePreemptibleDisabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstancePreemptibleDisabledCheck() *InstancePreemptibleDisabledCheck {
	return &InstancePreemptibleDisabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_preemptible_disabled",
			CheckTitle:      "VM instance is not configured as preemptible or Spot VM",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "VM instances should not be configured as preemptible or Spot VMs for production workloads.",
			Risk:            "VM instances should not be configured as preemptible or Spot VMs for production workloads.",
			RemediationText: "Use standard provisioning model for production and business-critical VM instances.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "availability"},
		},
	}
}

func (c *InstancePreemptibleDisabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstancePreemptibleDisabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_preemptible_disabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstancePreemptibleDisabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstancePreemptibleDisabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceShieldedVmEnabledCheck struct
type InstanceShieldedVmEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceShieldedVmEnabledCheck() *InstanceShieldedVmEnabledCheck {
	return &InstanceShieldedVmEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_shielded_vm_enabled",
			CheckTitle:      "Compute instance has vTPM and Integrity Monitoring enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VM instances have vTPM and Integrity Monitoring enabled as part of Shielded VM configuration.",
			Risk:            "Compute Engine VM instances have vTPM and Integrity Monitoring enabled as part of Shielded VM configuration.",
			RemediationText: "Enable Shielded VM with vTPM and Integrity Monitoring set to enabled on all VMs.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "security"},
		},
	}
}

func (c *InstanceShieldedVmEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceShieldedVmEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_shielded_vm_enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceShieldedVmEnabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceShieldedVmEnabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// InstanceStorageDiskNoDefaultEncryptionCheck struct
type InstanceStorageDiskNoDefaultEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceStorageDiskNoDefaultEncryptionCheck() *InstanceStorageDiskNoDefaultEncryptionCheck {
	return &InstanceStorageDiskNoDefaultEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_instance_storage_disk_no_default_encryption",
			CheckTitle:      "VM instance storage disks use encryption",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Instance",
			ResourceGroup:   "Compute",
			Description:     "Compute Engine VM attached disks should not rely on default encryption only.",
			Risk:            "Compute Engine VM attached disks should not rely on default encryption only.",
			RemediationText: "Configure CMEK encryption for VM disks containing sensitive data.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "encryption"},
		},
	}
}

func (c *InstanceStorageDiskNoDefaultEncryptionCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *InstanceStorageDiskNoDefaultEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_instance_storage_disk_no_default_encryption in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *InstanceStorageDiskNoDefaultEncryptionCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *InstanceStorageDiskNoDefaultEncryptionCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// NetworkGlobalRoutingModeCheck struct
type NetworkGlobalRoutingModeCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkGlobalRoutingModeCheck() *NetworkGlobalRoutingModeCheck {
	return &NetworkGlobalRoutingModeCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_network_global_routing_mode",
			CheckTitle:      "VPC network uses regional routing mode",
			ServiceName:     "compute",
			Severity:        "low",
			ResourceType:    "Network",
			ResourceGroup:   "Compute",
			Description:     "VPC networks should use regional routing mode for better performance and security.",
			Risk:            "VPC networks should use regional routing mode for better performance and security.",
			RemediationText: "Configure VPC networks with regional routing mode (GLOBAL routing is legacy).",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *NetworkGlobalRoutingModeCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NetworkGlobalRoutingModeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_network_global_routing_mode in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *NetworkGlobalRoutingModeCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *NetworkGlobalRoutingModeCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// NetworkNoDefaultSubnetsCheck struct
type NetworkNoDefaultSubnetsCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkNoDefaultSubnetsCheck() *NetworkNoDefaultSubnetsCheck {
	return &NetworkNoDefaultSubnetsCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_network_no_default_subnets",
			CheckTitle:      "Project does not use default subnet ranges",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Network",
			ResourceGroup:   "Compute",
			Description:     "VPC networks should use custom subnets rather than auto-created default subnets.",
			Risk:            "VPC networks should use custom subnets rather than auto-created default subnets.",
			RemediationText: "Create custom subnets with specific IP ranges and remove default subnets.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *NetworkNoDefaultSubnetsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NetworkNoDefaultSubnetsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_network_no_default_subnets in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *NetworkNoDefaultSubnetsCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *NetworkNoDefaultSubnetsCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// NetworkNoUnusedFirewallRulesCheck struct
type NetworkNoUnusedFirewallRulesCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkNoUnusedFirewallRulesCheck() *NetworkNoUnusedFirewallRulesCheck {
	return &NetworkNoUnusedFirewallRulesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_network_no_unused_firewall_rules",
			CheckTitle:      "VPC network has no unused firewall rules",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Firewall",
			ResourceGroup:   "Compute",
			Description:     "VPC firewall rules should be reviewed and unused rules removed to reduce attack surface.",
			Risk:            "VPC firewall rules should be reviewed and unused rules removed to reduce attack surface.",
			RemediationText: "Regularly audit and remove unused firewall rules.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *NetworkNoUnusedFirewallRulesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NetworkNoUnusedFirewallRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_network_no_unused_firewall_rules in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *NetworkNoUnusedFirewallRulesCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *NetworkNoUnusedFirewallRulesCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// NetworkNoUnusedRoutesCheck struct
type NetworkNoUnusedRoutesCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkNoUnusedRoutesCheck() *NetworkNoUnusedRoutesCheck {
	return &NetworkNoUnusedRoutesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_network_no_unused_routes",
			CheckTitle:      "VPC network has no unused routes",
			ServiceName:     "compute",
			Severity:        "low",
			ResourceType:    "Route",
			ResourceGroup:   "Compute",
			Description:     "VPC routes should be reviewed and unused routes removed.",
			Risk:            "VPC routes should be reviewed and unused routes removed.",
			RemediationText: "Regularly audit and remove unused routes.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *NetworkNoUnusedRoutesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NetworkNoUnusedRoutesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_network_no_unused_routes in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *NetworkNoUnusedRoutesCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *NetworkNoUnusedRoutesCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// NetworkNoVpcPeeringWithDefaultNetworkCheck struct
type NetworkNoVpcPeeringWithDefaultNetworkCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkNoVpcPeeringWithDefaultNetworkCheck() *NetworkNoVpcPeeringWithDefaultNetworkCheck {
	return &NetworkNoVpcPeeringWithDefaultNetworkCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_network_no_vpc_peering_with_default_network",
			CheckTitle:      "VPC peering is not configured with default network",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Network",
			ResourceGroup:   "Compute",
			Description:     "VPC peering should not be established with the default VPC network.",
			Risk:            "VPC peering should not be established with the default VPC network.",
			RemediationText: "Remove any VPC peering connections with the default network.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *NetworkNoVpcPeeringWithDefaultNetworkCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NetworkNoVpcPeeringWithDefaultNetworkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_network_no_vpc_peering_with_default_network in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *NetworkNoVpcPeeringWithDefaultNetworkCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *NetworkNoVpcPeeringWithDefaultNetworkCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// ProjectLevelOsLoginEnabledCheck struct
type ProjectLevelOsLoginEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewProjectLevelOsLoginEnabledCheck() *ProjectLevelOsLoginEnabledCheck {
	return &ProjectLevelOsLoginEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_project_level_os_login_enabled",
			CheckTitle:      "Project has OS Login enabled",
			ServiceName:     "compute",
			Severity:        "low",
			ResourceType:    "Project",
			ResourceGroup:   "Compute",
			Description:     "Project metadata has OS Login enabled (enable-oslogin) for centralized SSH access via IAM.",
			Risk:            "Project metadata has OS Login enabled (enable-oslogin) for centralized SSH access via IAM.",
			RemediationText: "Enable OS Login at the project level to centralize SSH through IAM.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "access"},
		},
	}
}

func (c *ProjectLevelOsLoginEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *ProjectLevelOsLoginEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_project_level_os_login_enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *ProjectLevelOsLoginEnabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *ProjectLevelOsLoginEnabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// ProjectLevelSerialPortLoggingEnabledCheck struct
type ProjectLevelSerialPortLoggingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewProjectLevelSerialPortLoggingEnabledCheck() *ProjectLevelSerialPortLoggingEnabledCheck {
	return &ProjectLevelSerialPortLoggingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_project_level_serial_port_logging_enabled",
			CheckTitle:      "Project has serial port logging enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Project",
			ResourceGroup:   "Compute",
			Description:     "Serial port output should be logged to Cloud Logging for security monitoring.",
			Risk:            "Serial port output should be logged to Cloud Logging for security monitoring.",
			RemediationText: "Enable serial port logging at the project level for security visibility.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "logging"},
		},
	}
}

func (c *ProjectLevelSerialPortLoggingEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *ProjectLevelSerialPortLoggingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_project_level_serial_port_logging_enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *ProjectLevelSerialPortLoggingEnabledCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *ProjectLevelSerialPortLoggingEnabledCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// SshKeysAtProjectLevelCheck struct
type SshKeysAtProjectLevelCheck struct {
	metadata models.CheckMetadata
}

func NewSshKeysAtProjectLevelCheck() *SshKeysAtProjectLevelCheck {
	return &SshKeysAtProjectLevelCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_ssh_keys_at_project_level",
			CheckTitle:      "Project-level SSH keys are not used",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Project",
			ResourceGroup:   "Compute",
			Description:     "Project-level SSH keys grant access to all instances. OS Login should be used instead.",
			Risk:            "Project-level SSH keys grant access to all instances. OS Login should be used instead.",
			RemediationText: "Remove project-level SSH keys and use OS Login or instance-level keys.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "access"},
		},
	}
}

func (c *SshKeysAtProjectLevelCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SshKeysAtProjectLevelCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_ssh_keys_at_project_level in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *SshKeysAtProjectLevelCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *SshKeysAtProjectLevelCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// SubnetFlowLogsEnabledCheck struct
type SubnetFlowLogsEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewSubnetFlowLogsEnabledCheck() *SubnetFlowLogsEnabledCheck {
	return &SubnetFlowLogsEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_subnet_flow_logs_enabled",
			CheckTitle:      "Subnet has VPC Flow Logs enabled",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Subnetwork",
			ResourceGroup:   "Compute",
			Description:     "GCP VPC subnets have VPC Flow Logs enabled to capture connection metadata.",
			Risk:            "GCP VPC subnets have VPC Flow Logs enabled to capture connection metadata.",
			RemediationText: "Enable VPC Flow Logs on all production subnets.",
			RemediationURL:  "https://cloud.google.com/vpc/docs/using-flow-logs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *SubnetFlowLogsEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SubnetFlowLogsEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	regions, err := computeClient.Regions.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regions: %w", err)
	}

	for _, region := range regions.Items {
		subnets, err := computeClient.Subnetworks.List(projectID, region.Name).Do()
		if err != nil {
			continue
		}

		for _, subnet := range subnets.Items {
			if !subnet.EnableFlowLogs {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Subnet %s in %s does not have VPC Flow Logs enabled", subnet.Name, region.Name),
					ResourceID:     subnet.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", projectID, region.Name, subnet.Name),
					Region:         region.Name,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All subnets have VPC Flow Logs enabled in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// SubnetNoIpRangeConflictsCheck struct
type SubnetNoIpRangeConflictsCheck struct {
	metadata models.CheckMetadata
}

func NewSubnetNoIpRangeConflictsCheck() *SubnetNoIpRangeConflictsCheck {
	return &SubnetNoIpRangeConflictsCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_subnet_no_ip_range_conflicts",
			CheckTitle:      "Subnets do not have overlapping IP ranges",
			ServiceName:     "compute",
			Severity:        "medium",
			ResourceType:    "Subnetwork",
			ResourceGroup:   "Compute",
			Description:     "VPC subnets should not have overlapping IP address ranges with other subnets.",
			Risk:            "VPC subnets should not have overlapping IP address ranges with other subnets.",
			RemediationText: "Ensure all subnets have unique, non-overlapping IP ranges.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *SubnetNoIpRangeConflictsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SubnetNoIpRangeConflictsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_subnet_no_ip_range_conflicts in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *SubnetNoIpRangeConflictsCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *SubnetNoIpRangeConflictsCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// SubnetNoUnusedIpRangesCheck struct
type SubnetNoUnusedIpRangesCheck struct {
	metadata models.CheckMetadata
}

func NewSubnetNoUnusedIpRangesCheck() *SubnetNoUnusedIpRangesCheck {
	return &SubnetNoUnusedIpRangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_subnet_no_unused_ip_ranges",
			CheckTitle:      "Subnets do not have unused IP ranges",
			ServiceName:     "compute",
			Severity:        "low",
			ResourceType:    "Subnetwork",
			ResourceGroup:   "Compute",
			Description:     "VPC subnets should not have excessively large unused IP ranges.",
			Risk:            "VPC subnets should not have excessively large unused IP ranges.",
			RemediationText: "Right-size subnets to match actual usage requirements.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "networking"},
		},
	}
}

func (c *SubnetNoUnusedIpRangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SubnetNoUnusedIpRangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_subnet_no_unused_ip_ranges in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *SubnetNoUnusedIpRangesCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *SubnetNoUnusedIpRangesCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// TargetHttpsProxySslPolicyNoWeakCheck struct
type TargetHttpsProxySslPolicyNoWeakCheck struct {
	metadata models.CheckMetadata
}

func NewTargetHttpsProxySslPolicyNoWeakCheck() *TargetHttpsProxySslPolicyNoWeakCheck {
	return &TargetHttpsProxySslPolicyNoWeakCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_target_https_proxy_ssl_policy_no_weak",
			CheckTitle:      "Target HTTPS proxy SSL policy does not allow weak protocols or ciphers",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "TargetHttpsProxy",
			ResourceGroup:   "Compute",
			Description:     "Target HTTPS proxy SSL policies should not allow weak SSL protocols or ciphers.",
			Risk:            "Target HTTPS proxy SSL policies should not allow weak SSL protocols or ciphers.",
			RemediationText: "Configure SSL policies with minimum TLS 1.2 and strong cipher suites.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "ssl"},
		},
	}
}

func (c *TargetHttpsProxySslPolicyNoWeakCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *TargetHttpsProxySslPolicyNoWeakCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_target_https_proxy_ssl_policy_no_weak in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *TargetHttpsProxySslPolicyNoWeakCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *TargetHttpsProxySslPolicyNoWeakCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// TargetHttpsProxySslPolicyTls12Check struct
type TargetHttpsProxySslPolicyTls12Check struct {
	metadata models.CheckMetadata
}

func NewTargetHttpsProxySslPolicyTls12Check() *TargetHttpsProxySslPolicyTls12Check {
	return &TargetHttpsProxySslPolicyTls12Check{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_target_https_proxy_ssl_policy_tls_1_2",
			CheckTitle:      "Target HTTPS proxy uses TLS 1.2 or higher",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "TargetHttpsProxy",
			ResourceGroup:   "Compute",
			Description:     "Target HTTPS proxy SSL policies should require TLS 1.2 or higher.",
			Risk:            "Target HTTPS proxy SSL policies should require TLS 1.2 or higher.",
			RemediationText: "Set SSL policy minimum version to TLS 1.2 for all target HTTPS proxies.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "ssl"},
		},
	}
}

func (c *TargetHttpsProxySslPolicyTls12Check) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *TargetHttpsProxySslPolicyTls12Check) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_target_https_proxy_ssl_policy_tls_1_2 in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *TargetHttpsProxySslPolicyTls12Check) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *TargetHttpsProxySslPolicyTls12Check) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

// TargetSslProxyNoWeakCipherCheck struct
type TargetSslProxyNoWeakCipherCheck struct {
	metadata models.CheckMetadata
}

func NewTargetSslProxyNoWeakCipherCheck() *TargetSslProxyNoWeakCipherCheck {
	return &TargetSslProxyNoWeakCipherCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "compute_target_ssl_proxy_no_weak_cipher",
			CheckTitle:      "Target SSL proxy SSL policy does not allow weak ciphers",
			ServiceName:     "compute",
			Severity:        "high",
			ResourceType:    "TargetSslProxy",
			ResourceGroup:   "Compute",
			Description:     "Target SSL proxy SSL policies should not allow weak SSL ciphers.",
			Risk:            "Target SSL proxy SSL policies should not allow weak SSL ciphers.",
			RemediationText: "Configure SSL policies with strong cipher suites for target SSL proxies.",
			RemediationURL:  "https://cloud.google.com/compute/docs",
			Categories:      []string{"compute", "ssl"},
		},
	}
}

func (c *TargetSslProxyNoWeakCipherCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *TargetSslProxyNoWeakCipherCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(computeProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa computeProvider")
	}

	findings := []models.Finding{}
	projectID := p.ProjectID()

	computeClient, err := p.Compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar compute client: %w", err)
	}

	// List all instances across all zones
	instances, err := computeClient.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias: %w", err)
	}

	// Check logic based on check type
	for zone, zoneInstances := range instances.Items {
		for _, instance := range zoneInstances.Instances {
			if c.isNonCompliant(instance) {
				zoneName := strings.Split(zone, "/")[1]
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: c.getStatusMessage(instance),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, instance.Name),
					Region:         zoneName,
					Provider:       "gcp",
					Service:        "compute",
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
			StatusExtended: fmt.Sprintf("All instances comply with compute_target_ssl_proxy_no_weak_cipher in project %s", projectID),
			ResourceID:     projectID,
			ResourceARN:    fmt.Sprintf("projects/%s", projectID),
			Provider:       "gcp",
			Service:        "compute",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

func (c *TargetSslProxyNoWeakCipherCheck) isNonCompliant(instance *compute.Instance) bool {
	// Check based on the specific check type
	switch {
	case strings.Contains(c.metadata.CheckID, "automatic_restart"):
		return instance.Scheduling == nil || instance.Scheduling.AutomaticRestart == nil || !*instance.Scheduling.AutomaticRestart
	case strings.Contains(c.metadata.CheckID, "deletion_protection"):
		return !instance.DeletionProtection
	case strings.Contains(c.metadata.CheckID, "shielded_vm"):
		return instance.ShieldedInstanceConfig == nil || !instance.ShieldedInstanceConfig.EnableVtpm || !instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
	case strings.Contains(c.metadata.CheckID, "confidential_computing"):
		return instance.ConfidentialInstanceConfig == nil || !instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	case strings.Contains(c.metadata.CheckID, "default_service_account"):
		if len(instance.ServiceAccounts) > 0 {
			defaultSA := strings.Contains(instance.ServiceAccounts[0].Email, "-compute@developer.gserviceaccount.com")
			return defaultSA
		}
	case strings.Contains(c.metadata.CheckID, "ip_forwarding"):
		return instance.CanIpForward
	case strings.Contains(c.metadata.CheckID, "no_public_ip"):
		for _, nic := range instance.NetworkInterfaces {
			if len(nic.AccessConfigs) > 0 {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "no_serial_ports"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "serial-port-enable" && (item.Value == nil || *item.Value == "true" || *item.Value == "1") {
				return true
			}
		}
	case strings.Contains(c.metadata.CheckID, "preemptible"):
		return instance.Scheduling != nil && (instance.Scheduling.Preemptible || instance.Scheduling.ProvisioningModel == "SPOT")
	case strings.Contains(c.metadata.CheckID, "block_project_wide_ssh_keys"):
		for _, item := range instance.Metadata.Items {
			if item.Key == "block-project-ssh-keys" && item.Value != nil && (*item.Value == "true" || *item.Value == "TRUE") {
				return false
			}
		}
		return true
	}
	return false
}

func (c *TargetSslProxyNoWeakCipherCheck) getStatusMessage(instance *compute.Instance) string {
	return fmt.Sprintf("Instance %s does not comply with %s", instance.Name, c.metadata.CheckID)
}

