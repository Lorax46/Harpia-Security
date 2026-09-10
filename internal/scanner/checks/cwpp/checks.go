package cwpp

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cwppProvider interface {
	Cwpp(ctx context.Context) (interface{}, error)
}

// CwppProvider interface

// FalcoRuntimeEnabledCheck - Falco runtime security is enabled
type FalcoRuntimeEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewFalcoRuntimeEnabledCheck() *FalcoRuntimeEnabledCheck {
	return &FalcoRuntimeEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_falco_runtime_enabled",
			CheckTitle:      "Falco runtime security is enabled",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Cluster",
			Description:     "Falco runtime security is enabled",
			RemediationText: "Review and remediate falco runtime security is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *FalcoRuntimeEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FalcoRuntimeEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_falco_runtime_enabled
	_ = findings
	return findings, nil
}

// FalcoRulesDefaultCheck - Falco default rules are active
type FalcoRulesDefaultCheck struct {
	metadata models.CheckMetadata
}

func NewFalcoRulesDefaultCheck() *FalcoRulesDefaultCheck {
	return &FalcoRulesDefaultCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_falco_rules_default",
			CheckTitle:      "Falco default rules are active",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Falco default rules are active",
			RemediationText: "Review and remediate falco default rules are active",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *FalcoRulesDefaultCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FalcoRulesDefaultCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_falco_rules_default
	_ = findings
	return findings, nil
}

// FalcoCustomRulesCheck - Falco custom rules are configured
type FalcoCustomRulesCheck struct {
	metadata models.CheckMetadata
}

func NewFalcoCustomRulesCheck() *FalcoCustomRulesCheck {
	return &FalcoCustomRulesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_falco_custom_rules",
			CheckTitle:      "Falco custom rules are configured",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Cluster",
			Description:     "Falco custom rules are configured",
			RemediationText: "Review and remediate falco custom rules are configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *FalcoCustomRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FalcoCustomRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_falco_custom_rules
	_ = findings
	return findings, nil
}

// FalcoNotificationsCheck - Falco notifications are configured
type FalcoNotificationsCheck struct {
	metadata models.CheckMetadata
}

func NewFalcoNotificationsCheck() *FalcoNotificationsCheck {
	return &FalcoNotificationsCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_falco_notifications",
			CheckTitle:      "Falco notifications are configured",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Falco notifications are configured",
			RemediationText: "Review and remediate falco notifications are configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *FalcoNotificationsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FalcoNotificationsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_falco_notifications
	_ = findings
	return findings, nil
}

// FalcoOutputSiemCheck - Falco outputs to SIEM
type FalcoOutputSiemCheck struct {
	metadata models.CheckMetadata
}

func NewFalcoOutputSiemCheck() *FalcoOutputSiemCheck {
	return &FalcoOutputSiemCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_falco_output_siem",
			CheckTitle:      "Falco outputs to SIEM",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Cluster",
			Description:     "Falco outputs to SIEM",
			RemediationText: "Review and remediate falco outputs to siem",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *FalcoOutputSiemCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FalcoOutputSiemCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_falco_output_siem
	_ = findings
	return findings, nil
}

// ContainerImageScanCheck - Container images are scanned
type ContainerImageScanCheck struct {
	metadata models.CheckMetadata
}

func NewContainerImageScanCheck() *ContainerImageScanCheck {
	return &ContainerImageScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_image_scan",
			CheckTitle:      "Container images are scanned",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Container",
			Description:     "Container images are scanned",
			RemediationText: "Review and remediate container images are scanned",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerImageScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerImageScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_image_scan
	_ = findings
	return findings, nil
}

// ContainerVulnerabilityCheck - Container vulnerabilities are managed
type ContainerVulnerabilityCheck struct {
	metadata models.CheckMetadata
}

func NewContainerVulnerabilityCheck() *ContainerVulnerabilityCheck {
	return &ContainerVulnerabilityCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_vulnerability",
			CheckTitle:      "Container vulnerabilities are managed",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Container vulnerabilities are managed",
			RemediationText: "Review and remediate container vulnerabilities are managed",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerVulnerabilityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerVulnerabilityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_vulnerability
	_ = findings
	return findings, nil
}

// ContainerRuntimeProtectionCheck - Container runtime protection is enabled
type ContainerRuntimeProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewContainerRuntimeProtectionCheck() *ContainerRuntimeProtectionCheck {
	return &ContainerRuntimeProtectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_runtime_protection",
			CheckTitle:      "Container runtime protection is enabled",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Container",
			Description:     "Container runtime protection is enabled",
			RemediationText: "Review and remediate container runtime protection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerRuntimeProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerRuntimeProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_runtime_protection
	_ = findings
	return findings, nil
}

// ContainerSeccompCheck - Seccomp profiles are applied
type ContainerSeccompCheck struct {
	metadata models.CheckMetadata
}

func NewContainerSeccompCheck() *ContainerSeccompCheck {
	return &ContainerSeccompCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_seccomp",
			CheckTitle:      "Seccomp profiles are applied",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Seccomp profiles are applied",
			RemediationText: "Review and remediate seccomp profiles are applied",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerSeccompCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerSeccompCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_seccomp
	_ = findings
	return findings, nil
}

// ContainerApparmorCheck - AppArmor profiles are applied
type ContainerApparmorCheck struct {
	metadata models.CheckMetadata
}

func NewContainerApparmorCheck() *ContainerApparmorCheck {
	return &ContainerApparmorCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_apparmor",
			CheckTitle:      "AppArmor profiles are applied",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "AppArmor profiles are applied",
			RemediationText: "Review and remediate apparmor profiles are applied",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerApparmorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerApparmorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_apparmor
	_ = findings
	return findings, nil
}

// ContainerCapabilitiesCheck - Container capabilities are restricted
type ContainerCapabilitiesCheck struct {
	metadata models.CheckMetadata
}

func NewContainerCapabilitiesCheck() *ContainerCapabilitiesCheck {
	return &ContainerCapabilitiesCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_capabilities",
			CheckTitle:      "Container capabilities are restricted",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Container capabilities are restricted",
			RemediationText: "Review and remediate container capabilities are restricted",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerCapabilitiesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerCapabilitiesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_capabilities
	_ = findings
	return findings, nil
}

// ContainerPrivilegedCheck - No privileged containers
type ContainerPrivilegedCheck struct {
	metadata models.CheckMetadata
}

func NewContainerPrivilegedCheck() *ContainerPrivilegedCheck {
	return &ContainerPrivilegedCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_privileged",
			CheckTitle:      "No privileged containers",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Container",
			Description:     "No privileged containers",
			RemediationText: "Review and remediate no privileged containers",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerPrivilegedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerPrivilegedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_privileged
	_ = findings
	return findings, nil
}

// ContainerHostNamespaceCheck - Containers do not share host namespaces
type ContainerHostNamespaceCheck struct {
	metadata models.CheckMetadata
}

func NewContainerHostNamespaceCheck() *ContainerHostNamespaceCheck {
	return &ContainerHostNamespaceCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_host_namespace",
			CheckTitle:      "Containers do not share host namespaces",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Containers do not share host namespaces",
			RemediationText: "Review and remediate containers do not share host namespaces",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerHostNamespaceCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerHostNamespaceCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_host_namespace
	_ = findings
	return findings, nil
}

// ContainerReadOnlyCheck - Containers use read-only root filesystem
type ContainerReadOnlyCheck struct {
	metadata models.CheckMetadata
}

func NewContainerReadOnlyCheck() *ContainerReadOnlyCheck {
	return &ContainerReadOnlyCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_read_only",
			CheckTitle:      "Containers use read-only root filesystem",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Container",
			Description:     "Containers use read-only root filesystem",
			RemediationText: "Review and remediate containers use read-only root filesystem",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerReadOnlyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerReadOnlyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_read_only
	_ = findings
	return findings, nil
}

// ContainerResourceLimitsCheck - Containers have resource limits
type ContainerResourceLimitsCheck struct {
	metadata models.CheckMetadata
}

func NewContainerResourceLimitsCheck() *ContainerResourceLimitsCheck {
	return &ContainerResourceLimitsCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_container_resource_limits",
			CheckTitle:      "Containers have resource limits",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Container",
			Description:     "Containers have resource limits",
			RemediationText: "Review and remediate containers have resource limits",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ContainerResourceLimitsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerResourceLimitsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_container_resource_limits
	_ = findings
	return findings, nil
}

// HostHardeningCheck - Host OS is hardened
type HostHardeningCheck struct {
	metadata models.CheckMetadata
}

func NewHostHardeningCheck() *HostHardeningCheck {
	return &HostHardeningCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_hardening",
			CheckTitle:      "Host OS is hardened",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Host OS is hardened",
			RemediationText: "Review and remediate host os is hardened",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostHardeningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostHardeningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_hardening
	_ = findings
	return findings, nil
}

// HostSelinuxCheck - SELinux is enabled on hosts
type HostSelinuxCheck struct {
	metadata models.CheckMetadata
}

func NewHostSelinuxCheck() *HostSelinuxCheck {
	return &HostSelinuxCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_selinux",
			CheckTitle:      "SELinux is enabled on hosts",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "SELinux is enabled on hosts",
			RemediationText: "Review and remediate selinux is enabled on hosts",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostSelinuxCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostSelinuxCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_selinux
	_ = findings
	return findings, nil
}

// HostGrsecurityCheck - Grsecurity is enabled
type HostGrsecurityCheck struct {
	metadata models.CheckMetadata
}

func NewHostGrsecurityCheck() *HostGrsecurityCheck {
	return &HostGrsecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_grsecurity",
			CheckTitle:      "Grsecurity is enabled",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Host",
			Description:     "Grsecurity is enabled",
			RemediationText: "Review and remediate grsecurity is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostGrsecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostGrsecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_grsecurity
	_ = findings
	return findings, nil
}

// HostKernelHardeningCheck - Kernel hardening is applied
type HostKernelHardeningCheck struct {
	metadata models.CheckMetadata
}

func NewHostKernelHardeningCheck() *HostKernelHardeningCheck {
	return &HostKernelHardeningCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_kernel_hardening",
			CheckTitle:      "Kernel hardening is applied",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Kernel hardening is applied",
			RemediationText: "Review and remediate kernel hardening is applied",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostKernelHardeningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostKernelHardeningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_kernel_hardening
	_ = findings
	return findings, nil
}

// HostFileIntegrityCheck - File integrity monitoring is enabled
type HostFileIntegrityCheck struct {
	metadata models.CheckMetadata
}

func NewHostFileIntegrityCheck() *HostFileIntegrityCheck {
	return &HostFileIntegrityCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_file_integrity",
			CheckTitle:      "File integrity monitoring is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "File integrity monitoring is enabled",
			RemediationText: "Review and remediate file integrity monitoring is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostFileIntegrityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostFileIntegrityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_file_integrity
	_ = findings
	return findings, nil
}

// HostAuditLoggingCheck - Host audit logging is enabled
type HostAuditLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewHostAuditLoggingCheck() *HostAuditLoggingCheck {
	return &HostAuditLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_audit_logging",
			CheckTitle:      "Host audit logging is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Host audit logging is enabled",
			RemediationText: "Review and remediate host audit logging is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostAuditLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostAuditLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_audit_logging
	_ = findings
	return findings, nil
}

// HostSshHardeningCheck - SSH is hardened
type HostSshHardeningCheck struct {
	metadata models.CheckMetadata
}

func NewHostSshHardeningCheck() *HostSshHardeningCheck {
	return &HostSshHardeningCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_ssh_hardening",
			CheckTitle:      "SSH is hardened",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "SSH is hardened",
			RemediationText: "Review and remediate ssh is hardened",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostSshHardeningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostSshHardeningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_ssh_hardening
	_ = findings
	return findings, nil
}

// HostPasswordPolicyCheck - Host password policy is enforced
type HostPasswordPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewHostPasswordPolicyCheck() *HostPasswordPolicyCheck {
	return &HostPasswordPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_host_password_policy",
			CheckTitle:      "Host password policy is enforced",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Host",
			Description:     "Host password policy is enforced",
			RemediationText: "Review and remediate host password policy is enforced",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *HostPasswordPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostPasswordPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_host_password_policy
	_ = findings
	return findings, nil
}

// AnomalyDetectionCheck - Anomaly detection is enabled
type AnomalyDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewAnomalyDetectionCheck() *AnomalyDetectionCheck {
	return &AnomalyDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_anomaly_detection",
			CheckTitle:      "Anomaly detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Anomaly detection is enabled",
			RemediationText: "Review and remediate anomaly detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AnomalyDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AnomalyDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_anomaly_detection
	_ = findings
	return findings, nil
}

// AnomalyNetworkCheck - Network anomaly detection is enabled
type AnomalyNetworkCheck struct {
	metadata models.CheckMetadata
}

func NewAnomalyNetworkCheck() *AnomalyNetworkCheck {
	return &AnomalyNetworkCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_anomaly_network",
			CheckTitle:      "Network anomaly detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Network anomaly detection is enabled",
			RemediationText: "Review and remediate network anomaly detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AnomalyNetworkCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AnomalyNetworkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_anomaly_network
	_ = findings
	return findings, nil
}

// AnomalyProcessCheck - Process anomaly detection is enabled
type AnomalyProcessCheck struct {
	metadata models.CheckMetadata
}

func NewAnomalyProcessCheck() *AnomalyProcessCheck {
	return &AnomalyProcessCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_anomaly_process",
			CheckTitle:      "Process anomaly detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Process anomaly detection is enabled",
			RemediationText: "Review and remediate process anomaly detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AnomalyProcessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AnomalyProcessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_anomaly_process
	_ = findings
	return findings, nil
}

// AnomalyFileCheck - File anomaly detection is enabled
type AnomalyFileCheck struct {
	metadata models.CheckMetadata
}

func NewAnomalyFileCheck() *AnomalyFileCheck {
	return &AnomalyFileCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_anomaly_file",
			CheckTitle:      "File anomaly detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "File anomaly detection is enabled",
			RemediationText: "Review and remediate file anomaly detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AnomalyFileCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AnomalyFileCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_anomaly_file
	_ = findings
	return findings, nil
}

// NetworkMicrosegmentationCheck - Network microsegmentation is implemented
type NetworkMicrosegmentationCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkMicrosegmentationCheck() *NetworkMicrosegmentationCheck {
	return &NetworkMicrosegmentationCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_network_microsegmentation",
			CheckTitle:      "Network microsegmentation is implemented",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Network",
			Description:     "Network microsegmentation is implemented",
			RemediationText: "Review and remediate network microsegmentation is implemented",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *NetworkMicrosegmentationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkMicrosegmentationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_network_microsegmentation
	_ = findings
	return findings, nil
}

// NetworkEgressFilteringCheck - Egress filtering is configured
type NetworkEgressFilteringCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkEgressFilteringCheck() *NetworkEgressFilteringCheck {
	return &NetworkEgressFilteringCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_network_egress_filtering",
			CheckTitle:      "Egress filtering is configured",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Network",
			Description:     "Egress filtering is configured",
			RemediationText: "Review and remediate egress filtering is configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *NetworkEgressFilteringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkEgressFilteringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_network_egress_filtering
	_ = findings
	return findings, nil
}

// NetworkIngressFilteringCheck - Ingress filtering is configured
type NetworkIngressFilteringCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkIngressFilteringCheck() *NetworkIngressFilteringCheck {
	return &NetworkIngressFilteringCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_network_ingress_filtering",
			CheckTitle:      "Ingress filtering is configured",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Network",
			Description:     "Ingress filtering is configured",
			RemediationText: "Review and remediate ingress filtering is configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *NetworkIngressFilteringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkIngressFilteringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_network_ingress_filtering
	_ = findings
	return findings, nil
}

// RuntimeSyscallMonitorCheck - Syscall monitoring is enabled
type RuntimeSyscallMonitorCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeSyscallMonitorCheck() *RuntimeSyscallMonitorCheck {
	return &RuntimeSyscallMonitorCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_syscall_monitor",
			CheckTitle:      "Syscall monitoring is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Syscall monitoring is enabled",
			RemediationText: "Review and remediate syscall monitoring is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeSyscallMonitorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeSyscallMonitorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_syscall_monitor
	_ = findings
	return findings, nil
}

// RuntimeProcessMonitorCheck - Process monitoring is enabled
type RuntimeProcessMonitorCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeProcessMonitorCheck() *RuntimeProcessMonitorCheck {
	return &RuntimeProcessMonitorCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_process_monitor",
			CheckTitle:      "Process monitoring is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Process monitoring is enabled",
			RemediationText: "Review and remediate process monitoring is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeProcessMonitorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeProcessMonitorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_process_monitor
	_ = findings
	return findings, nil
}

// RuntimeFileMonitorCheck - File monitoring is enabled
type RuntimeFileMonitorCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeFileMonitorCheck() *RuntimeFileMonitorCheck {
	return &RuntimeFileMonitorCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_file_monitor",
			CheckTitle:      "File monitoring is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "File monitoring is enabled",
			RemediationText: "Review and remediate file monitoring is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeFileMonitorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeFileMonitorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_file_monitor
	_ = findings
	return findings, nil
}

// RuntimeNetworkMonitorCheck - Network monitoring is enabled
type RuntimeNetworkMonitorCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeNetworkMonitorCheck() *RuntimeNetworkMonitorCheck {
	return &RuntimeNetworkMonitorCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_network_monitor",
			CheckTitle:      "Network monitoring is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Network monitoring is enabled",
			RemediationText: "Review and remediate network monitoring is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeNetworkMonitorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeNetworkMonitorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_network_monitor
	_ = findings
	return findings, nil
}

// AdmissionControllerCheck - Admission controller is configured
type AdmissionControllerCheck struct {
	metadata models.CheckMetadata
}

func NewAdmissionControllerCheck() *AdmissionControllerCheck {
	return &AdmissionControllerCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_admission_controller",
			CheckTitle:      "Admission controller is configured",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Cluster",
			Description:     "Admission controller is configured",
			RemediationText: "Review and remediate admission controller is configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AdmissionControllerCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdmissionControllerCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_admission_controller
	_ = findings
	return findings, nil
}

// AdmissionDenyPrivilegedCheck - Admission denies privileged containers
type AdmissionDenyPrivilegedCheck struct {
	metadata models.CheckMetadata
}

func NewAdmissionDenyPrivilegedCheck() *AdmissionDenyPrivilegedCheck {
	return &AdmissionDenyPrivilegedCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_admission_deny_privileged",
			CheckTitle:      "Admission denies privileged containers",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Cluster",
			Description:     "Admission denies privileged containers",
			RemediationText: "Review and remediate admission denies privileged containers",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AdmissionDenyPrivilegedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdmissionDenyPrivilegedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_admission_deny_privileged
	_ = findings
	return findings, nil
}

// AdmissionDenyHostAccessCheck - Admission denies host access
type AdmissionDenyHostAccessCheck struct {
	metadata models.CheckMetadata
}

func NewAdmissionDenyHostAccessCheck() *AdmissionDenyHostAccessCheck {
	return &AdmissionDenyHostAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_admission_deny_host_access",
			CheckTitle:      "Admission denies host access",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Admission denies host access",
			RemediationText: "Review and remediate admission denies host access",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AdmissionDenyHostAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdmissionDenyHostAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_admission_deny_host_access
	_ = findings
	return findings, nil
}

// AdmissionDenyExecCheck - Admission denies exec into containers
type AdmissionDenyExecCheck struct {
	metadata models.CheckMetadata
}

func NewAdmissionDenyExecCheck() *AdmissionDenyExecCheck {
	return &AdmissionDenyExecCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_admission_deny_exec",
			CheckTitle:      "Admission denies exec into containers",
			ServiceName:     "cwpp",
			Severity:        "medium",
			ResourceType:    "Cluster",
			Description:     "Admission denies exec into containers",
			RemediationText: "Review and remediate admission denies exec into containers",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *AdmissionDenyExecCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AdmissionDenyExecCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_admission_deny_exec
	_ = findings
	return findings, nil
}

// PolicyOpaCheck - OPA policies are configured
type PolicyOpaCheck struct {
	metadata models.CheckMetadata
}

func NewPolicyOpaCheck() *PolicyOpaCheck {
	return &PolicyOpaCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_policy_opa",
			CheckTitle:      "OPA policies are configured",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "OPA policies are configured",
			RemediationText: "Review and remediate opa policies are configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *PolicyOpaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyOpaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_policy_opa
	_ = findings
	return findings, nil
}

// PolicyKyvernoCheck - Kyverno policies are configured
type PolicyKyvernoCheck struct {
	metadata models.CheckMetadata
}

func NewPolicyKyvernoCheck() *PolicyKyvernoCheck {
	return &PolicyKyvernoCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_policy_kyverno",
			CheckTitle:      "Kyverno policies are configured",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Kyverno policies are configured",
			RemediationText: "Review and remediate kyverno policies are configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *PolicyKyvernoCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyKyvernoCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_policy_kyverno
	_ = findings
	return findings, nil
}

// PolicyGatekeeperCheck - Gatekeeper policies are configured
type PolicyGatekeeperCheck struct {
	metadata models.CheckMetadata
}

func NewPolicyGatekeeperCheck() *PolicyGatekeeperCheck {
	return &PolicyGatekeeperCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_policy_gatekeeper",
			CheckTitle:      "Gatekeeper policies are configured",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "Gatekeeper policies are configured",
			RemediationText: "Review and remediate gatekeeper policies are configured",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *PolicyGatekeeperCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PolicyGatekeeperCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_policy_gatekeeper
	_ = findings
	return findings, nil
}

// ComplianceCisCheck - CIS benchmarks are enforced
type ComplianceCisCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceCisCheck() *ComplianceCisCheck {
	return &ComplianceCisCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_compliance_cis",
			CheckTitle:      "CIS benchmarks are enforced",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "CIS benchmarks are enforced",
			RemediationText: "Review and remediate cis benchmarks are enforced",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ComplianceCisCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceCisCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_compliance_cis
	_ = findings
	return findings, nil
}

// ComplianceNistCheck - NIST compliance is enforced
type ComplianceNistCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceNistCheck() *ComplianceNistCheck {
	return &ComplianceNistCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_compliance_nist",
			CheckTitle:      "NIST compliance is enforced",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "NIST compliance is enforced",
			RemediationText: "Review and remediate nist compliance is enforced",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ComplianceNistCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceNistCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_compliance_nist
	_ = findings
	return findings, nil
}

// CompliancePciCheck - PCI compliance is enforced
type CompliancePciCheck struct {
	metadata models.CheckMetadata
}

func NewCompliancePciCheck() *CompliancePciCheck {
	return &CompliancePciCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_compliance_pci",
			CheckTitle:      "PCI compliance is enforced",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "PCI compliance is enforced",
			RemediationText: "Review and remediate pci compliance is enforced",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *CompliancePciCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CompliancePciCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_compliance_pci
	_ = findings
	return findings, nil
}

// ComplianceHipaaCheck - HIPAA compliance is enforced
type ComplianceHipaaCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceHipaaCheck() *ComplianceHipaaCheck {
	return &ComplianceHipaaCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_compliance_hipaa",
			CheckTitle:      "HIPAA compliance is enforced",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "HIPAA compliance is enforced",
			RemediationText: "Review and remediate hipaa compliance is enforced",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ComplianceHipaaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceHipaaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_compliance_hipaa
	_ = findings
	return findings, nil
}

// ComplianceSoc2Check - SOC2 compliance is enforced
type ComplianceSoc2Check struct {
	metadata models.CheckMetadata
}

func NewComplianceSoc2Check() *ComplianceSoc2Check {
	return &ComplianceSoc2Check{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_compliance_soc2",
			CheckTitle:      "SOC2 compliance is enforced",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "SOC2 compliance is enforced",
			RemediationText: "Review and remediate soc2 compliance is enforced",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *ComplianceSoc2Check) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceSoc2Check) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_compliance_soc2
	_ = findings
	return findings, nil
}

// RuntimeContainerEscapeCheck - Container escape detection is enabled
type RuntimeContainerEscapeCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeContainerEscapeCheck() *RuntimeContainerEscapeCheck {
	return &RuntimeContainerEscapeCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_container_escape",
			CheckTitle:      "Container escape detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Container",
			Description:     "Container escape detection is enabled",
			RemediationText: "Review and remediate container escape detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeContainerEscapeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeContainerEscapeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_container_escape
	_ = findings
	return findings, nil
}

// RuntimeReverseShellCheck - Reverse shell detection is enabled
type RuntimeReverseShellCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeReverseShellCheck() *RuntimeReverseShellCheck {
	return &RuntimeReverseShellCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_reverse_shell",
			CheckTitle:      "Reverse shell detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "critical",
			ResourceType:    "Container",
			Description:     "Reverse shell detection is enabled",
			RemediationText: "Review and remediate reverse shell detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeReverseShellCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeReverseShellCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_reverse_shell
	_ = findings
	return findings, nil
}

// RuntimeSensitiveMountCheck - Sensitive mount detection is enabled
type RuntimeSensitiveMountCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeSensitiveMountCheck() *RuntimeSensitiveMountCheck {
	return &RuntimeSensitiveMountCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_sensitive_mount",
			CheckTitle:      "Sensitive mount detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Sensitive mount detection is enabled",
			RemediationText: "Review and remediate sensitive mount detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeSensitiveMountCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeSensitiveMountCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_sensitive_mount
	_ = findings
	return findings, nil
}

// RuntimeBinaryExecutionCheck - Unexpected binary execution detection is enabled
type RuntimeBinaryExecutionCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeBinaryExecutionCheck() *RuntimeBinaryExecutionCheck {
	return &RuntimeBinaryExecutionCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_binary_execution",
			CheckTitle:      "Unexpected binary execution detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Unexpected binary execution detection is enabled",
			RemediationText: "Review and remediate unexpected binary execution detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeBinaryExecutionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeBinaryExecutionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_binary_execution
	_ = findings
	return findings, nil
}

// RuntimeNetworkScanningCheck - Network scanning detection is enabled
type RuntimeNetworkScanningCheck struct {
	metadata models.CheckMetadata
}

func NewRuntimeNetworkScanningCheck() *RuntimeNetworkScanningCheck {
	return &RuntimeNetworkScanningCheck{
		metadata: models.CheckMetadata{
			Provider:        "cwpp",
			CheckID:         "cwpp_runtime_network_scanning",
			CheckTitle:      "Network scanning detection is enabled",
			ServiceName:     "cwpp",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Network scanning detection is enabled",
			RemediationText: "Review and remediate network scanning detection is enabled",
			Categories:      []string{"cwpp", "security"},
		},
	}
}

func (c *RuntimeNetworkScanningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RuntimeNetworkScanningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cwppProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cwppProvider")
	}
	client, err := p.Cwpp(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement cwpp_runtime_network_scanning
	_ = findings
	return findings, nil
}
