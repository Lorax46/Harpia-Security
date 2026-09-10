package vuln

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type vulnProvider interface {
	Vuln(ctx context.Context) (interface{}, error)
}

// VulnProvider interface

// ContainerImageScanCheck - Container images are scanned for vulnerabilities
type ContainerImageScanCheck struct {
	metadata models.CheckMetadata
}

func NewContainerImageScanCheck() *ContainerImageScanCheck {
	return &ContainerImageScanCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_image_scan",
			CheckTitle:      "Container images are scanned for vulnerabilities",
			ServiceName:     "vuln",
			Severity:        "critical",
			ResourceType:    "Container",
			Description:     "Container images are scanned for vulnerabilities",
			RemediationText: "Review and remediate container images are scanned for vulnerabilities",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerImageScanCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerImageScanCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_image_scan
	_ = findings
	return findings, nil
}

// ContainerOsVulnCheck - Container OS vulnerabilities are managed
type ContainerOsVulnCheck struct {
	metadata models.CheckMetadata
}

func NewContainerOsVulnCheck() *ContainerOsVulnCheck {
	return &ContainerOsVulnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_os_vuln",
			CheckTitle:      "Container OS vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Container OS vulnerabilities are managed",
			RemediationText: "Review and remediate container os vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerOsVulnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerOsVulnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_os_vuln
	_ = findings
	return findings, nil
}

// ContainerAppVulnCheck - Container application vulnerabilities are managed
type ContainerAppVulnCheck struct {
	metadata models.CheckMetadata
}

func NewContainerAppVulnCheck() *ContainerAppVulnCheck {
	return &ContainerAppVulnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_app_vuln",
			CheckTitle:      "Container application vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Container application vulnerabilities are managed",
			RemediationText: "Review and remediate container application vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerAppVulnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerAppVulnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_app_vuln
	_ = findings
	return findings, nil
}

// ContainerDependencyVulnCheck - Container dependency vulnerabilities are managed
type ContainerDependencyVulnCheck struct {
	metadata models.CheckMetadata
}

func NewContainerDependencyVulnCheck() *ContainerDependencyVulnCheck {
	return &ContainerDependencyVulnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_dependency_vuln",
			CheckTitle:      "Container dependency vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Container dependency vulnerabilities are managed",
			RemediationText: "Review and remediate container dependency vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerDependencyVulnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerDependencyVulnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_dependency_vuln
	_ = findings
	return findings, nil
}

// ContainerBaseImageCheck - Container base image is up to date
type ContainerBaseImageCheck struct {
	metadata models.CheckMetadata
}

func NewContainerBaseImageCheck() *ContainerBaseImageCheck {
	return &ContainerBaseImageCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_base_image",
			CheckTitle:      "Container base image is up to date",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Container",
			Description:     "Container base image is up to date",
			RemediationText: "Review and remediate container base image is up to date",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerBaseImageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerBaseImageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_base_image
	_ = findings
	return findings, nil
}

// ContainerDistrolessCheck - Distroless images are used
type ContainerDistrolessCheck struct {
	metadata models.CheckMetadata
}

func NewContainerDistrolessCheck() *ContainerDistrolessCheck {
	return &ContainerDistrolessCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_distroless",
			CheckTitle:      "Distroless images are used",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Container",
			Description:     "Distroless images are used",
			RemediationText: "Review and remediate distroless images are used",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerDistrolessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerDistrolessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_distroless
	_ = findings
	return findings, nil
}

// ContainerMultiStageCheck - Multi-stage builds are used
type ContainerMultiStageCheck struct {
	metadata models.CheckMetadata
}

func NewContainerMultiStageCheck() *ContainerMultiStageCheck {
	return &ContainerMultiStageCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_multi_stage",
			CheckTitle:      "Multi-stage builds are used",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Container",
			Description:     "Multi-stage builds are used",
			RemediationText: "Review and remediate multi-stage builds are used",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerMultiStageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerMultiStageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_multi_stage
	_ = findings
	return findings, nil
}

// ContainerHealthCheckCheck - Container health checks are configured
type ContainerHealthCheckCheck struct {
	metadata models.CheckMetadata
}

func NewContainerHealthCheckCheck() *ContainerHealthCheckCheck {
	return &ContainerHealthCheckCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_container_health_check",
			CheckTitle:      "Container health checks are configured",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Container",
			Description:     "Container health checks are configured",
			RemediationText: "Review and remediate container health checks are configured",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *ContainerHealthCheckCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ContainerHealthCheckCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_container_health_check
	_ = findings
	return findings, nil
}

// HostOsVulnCheck - Host OS vulnerabilities are managed
type HostOsVulnCheck struct {
	metadata models.CheckMetadata
}

func NewHostOsVulnCheck() *HostOsVulnCheck {
	return &HostOsVulnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_host_os_vuln",
			CheckTitle:      "Host OS vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Host OS vulnerabilities are managed",
			RemediationText: "Review and remediate host os vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *HostOsVulnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostOsVulnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_host_os_vuln
	_ = findings
	return findings, nil
}

// HostKernelVulnCheck - Host kernel vulnerabilities are managed
type HostKernelVulnCheck struct {
	metadata models.CheckMetadata
}

func NewHostKernelVulnCheck() *HostKernelVulnCheck {
	return &HostKernelVulnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_host_kernel_vuln",
			CheckTitle:      "Host kernel vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Host kernel vulnerabilities are managed",
			RemediationText: "Review and remediate host kernel vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *HostKernelVulnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostKernelVulnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_host_kernel_vuln
	_ = findings
	return findings, nil
}

// HostPackageVulnCheck - Host package vulnerabilities are managed
type HostPackageVulnCheck struct {
	metadata models.CheckMetadata
}

func NewHostPackageVulnCheck() *HostPackageVulnCheck {
	return &HostPackageVulnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_host_package_vuln",
			CheckTitle:      "Host package vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Host",
			Description:     "Host package vulnerabilities are managed",
			RemediationText: "Review and remediate host package vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *HostPackageVulnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostPackageVulnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_host_package_vuln
	_ = findings
	return findings, nil
}

// HostConfigurationCheck - Host configuration vulnerabilities are managed
type HostConfigurationCheck struct {
	metadata models.CheckMetadata
}

func NewHostConfigurationCheck() *HostConfigurationCheck {
	return &HostConfigurationCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_host_configuration",
			CheckTitle:      "Host configuration vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Host",
			Description:     "Host configuration vulnerabilities are managed",
			RemediationText: "Review and remediate host configuration vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *HostConfigurationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HostConfigurationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_host_configuration
	_ = findings
	return findings, nil
}

// CodeSastCheck - SAST scanning is enabled
type CodeSastCheck struct {
	metadata models.CheckMetadata
}

func NewCodeSastCheck() *CodeSastCheck {
	return &CodeSastCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_sast",
			CheckTitle:      "SAST scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "SAST scanning is enabled",
			RemediationText: "Review and remediate sast scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeSastCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeSastCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_sast
	_ = findings
	return findings, nil
}

// CodeDastCheck - DAST scanning is enabled
type CodeDastCheck struct {
	metadata models.CheckMetadata
}

func NewCodeDastCheck() *CodeDastCheck {
	return &CodeDastCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_dast",
			CheckTitle:      "DAST scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "DAST scanning is enabled",
			RemediationText: "Review and remediate dast scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeDastCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeDastCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_dast
	_ = findings
	return findings, nil
}

// CodeScaCheck - SCA scanning is enabled
type CodeScaCheck struct {
	metadata models.CheckMetadata
}

func NewCodeScaCheck() *CodeScaCheck {
	return &CodeScaCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_sca",
			CheckTitle:      "SCA scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "SCA scanning is enabled",
			RemediationText: "Review and remediate sca scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeScaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeScaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_sca
	_ = findings
	return findings, nil
}

// CodeIacCheck - IaC scanning is enabled
type CodeIacCheck struct {
	metadata models.CheckMetadata
}

func NewCodeIacCheck() *CodeIacCheck {
	return &CodeIacCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_iac",
			CheckTitle:      "IaC scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "IaC scanning is enabled",
			RemediationText: "Review and remediate iac scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeIacCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeIacCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_iac
	_ = findings
	return findings, nil
}

// CodeSecretsCheck - Secret scanning is enabled
type CodeSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewCodeSecretsCheck() *CodeSecretsCheck {
	return &CodeSecretsCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_secrets",
			CheckTitle:      "Secret scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "critical",
			ResourceType:    "Code",
			Description:     "Secret scanning is enabled",
			RemediationText: "Review and remediate secret scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_secrets
	_ = findings
	return findings, nil
}

// CodeDependencyCheck - Dependency scanning is enabled
type CodeDependencyCheck struct {
	metadata models.CheckMetadata
}

func NewCodeDependencyCheck() *CodeDependencyCheck {
	return &CodeDependencyCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_dependency",
			CheckTitle:      "Dependency scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "Dependency scanning is enabled",
			RemediationText: "Review and remediate dependency scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeDependencyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeDependencyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_dependency
	_ = findings
	return findings, nil
}

// CodeLicenseCheck - License compliance scanning is enabled
type CodeLicenseCheck struct {
	metadata models.CheckMetadata
}

func NewCodeLicenseCheck() *CodeLicenseCheck {
	return &CodeLicenseCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_license",
			CheckTitle:      "License compliance scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Code",
			Description:     "License compliance scanning is enabled",
			RemediationText: "Review and remediate license compliance scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeLicenseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeLicenseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_license
	_ = findings
	return findings, nil
}

// CodeQualityCheck - Code quality scanning is enabled
type CodeQualityCheck struct {
	metadata models.CheckMetadata
}

func NewCodeQualityCheck() *CodeQualityCheck {
	return &CodeQualityCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_code_quality",
			CheckTitle:      "Code quality scanning is enabled",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Code",
			Description:     "Code quality scanning is enabled",
			RemediationText: "Review and remediate code quality scanning is enabled",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *CodeQualityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeQualityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_code_quality
	_ = findings
	return findings, nil
}

// InfrastructureComputeCheck - Compute infrastructure vulnerabilities are managed
type InfrastructureComputeCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureComputeCheck() *InfrastructureComputeCheck {
	return &InfrastructureComputeCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_compute",
			CheckTitle:      "Compute infrastructure vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Compute",
			Description:     "Compute infrastructure vulnerabilities are managed",
			RemediationText: "Review and remediate compute infrastructure vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureComputeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureComputeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_compute
	_ = findings
	return findings, nil
}

// InfrastructureNetworkCheck - Network infrastructure vulnerabilities are managed
type InfrastructureNetworkCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureNetworkCheck() *InfrastructureNetworkCheck {
	return &InfrastructureNetworkCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_network",
			CheckTitle:      "Network infrastructure vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Network",
			Description:     "Network infrastructure vulnerabilities are managed",
			RemediationText: "Review and remediate network infrastructure vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureNetworkCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureNetworkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_network
	_ = findings
	return findings, nil
}

// InfrastructureStorageCheck - Storage infrastructure vulnerabilities are managed
type InfrastructureStorageCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureStorageCheck() *InfrastructureStorageCheck {
	return &InfrastructureStorageCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_storage",
			CheckTitle:      "Storage infrastructure vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Storage",
			Description:     "Storage infrastructure vulnerabilities are managed",
			RemediationText: "Review and remediate storage infrastructure vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureStorageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureStorageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_storage
	_ = findings
	return findings, nil
}

// InfrastructureDatabaseCheck - Database infrastructure vulnerabilities are managed
type InfrastructureDatabaseCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureDatabaseCheck() *InfrastructureDatabaseCheck {
	return &InfrastructureDatabaseCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_database",
			CheckTitle:      "Database infrastructure vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Database",
			Description:     "Database infrastructure vulnerabilities are managed",
			RemediationText: "Review and remediate database infrastructure vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureDatabaseCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureDatabaseCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_database
	_ = findings
	return findings, nil
}

// InfrastructureLoadbalancerCheck - Load balancer vulnerabilities are managed
type InfrastructureLoadbalancerCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureLoadbalancerCheck() *InfrastructureLoadbalancerCheck {
	return &InfrastructureLoadbalancerCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_loadbalancer",
			CheckTitle:      "Load balancer vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "LoadBalancer",
			Description:     "Load balancer vulnerabilities are managed",
			RemediationText: "Review and remediate load balancer vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureLoadbalancerCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureLoadbalancerCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_loadbalancer
	_ = findings
	return findings, nil
}

// InfrastructureCdnCheck - CDN vulnerabilities are managed
type InfrastructureCdnCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureCdnCheck() *InfrastructureCdnCheck {
	return &InfrastructureCdnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_cdn",
			CheckTitle:      "CDN vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "CDN",
			Description:     "CDN vulnerabilities are managed",
			RemediationText: "Review and remediate cdn vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureCdnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureCdnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_cdn
	_ = findings
	return findings, nil
}

// InfrastructureDnsCheck - DNS vulnerabilities are managed
type InfrastructureDnsCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureDnsCheck() *InfrastructureDnsCheck {
	return &InfrastructureDnsCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_dns",
			CheckTitle:      "DNS vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "DNS",
			Description:     "DNS vulnerabilities are managed",
			RemediationText: "Review and remediate dns vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureDnsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureDnsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_dns
	_ = findings
	return findings, nil
}

// InfrastructureFirewallCheck - Firewall vulnerabilities are managed
type InfrastructureFirewallCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureFirewallCheck() *InfrastructureFirewallCheck {
	return &InfrastructureFirewallCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_firewall",
			CheckTitle:      "Firewall vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Firewall",
			Description:     "Firewall vulnerabilities are managed",
			RemediationText: "Review and remediate firewall vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureFirewallCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureFirewallCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_firewall
	_ = findings
	return findings, nil
}

// InfrastructureWafCheck - WAF vulnerabilities are managed
type InfrastructureWafCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureWafCheck() *InfrastructureWafCheck {
	return &InfrastructureWafCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_waf",
			CheckTitle:      "WAF vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "WAF",
			Description:     "WAF vulnerabilities are managed",
			RemediationText: "Review and remediate waf vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureWafCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureWafCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_waf
	_ = findings
	return findings, nil
}

// InfrastructureVpnCheck - VPN vulnerabilities are managed
type InfrastructureVpnCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureVpnCheck() *InfrastructureVpnCheck {
	return &InfrastructureVpnCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_vpn",
			CheckTitle:      "VPN vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "VPN",
			Description:     "VPN vulnerabilities are managed",
			RemediationText: "Review and remediate vpn vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureVpnCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureVpnCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_vpn
	_ = findings
	return findings, nil
}

// InfrastructureIamCheck - IAM vulnerabilities are managed
type InfrastructureIamCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureIamCheck() *InfrastructureIamCheck {
	return &InfrastructureIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_iam",
			CheckTitle:      "IAM vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "IAM",
			Description:     "IAM vulnerabilities are managed",
			RemediationText: "Review and remediate iam vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_iam
	_ = findings
	return findings, nil
}

// InfrastructureKmsCheck - KMS vulnerabilities are managed
type InfrastructureKmsCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureKmsCheck() *InfrastructureKmsCheck {
	return &InfrastructureKmsCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_kms",
			CheckTitle:      "KMS vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "KMS",
			Description:     "KMS vulnerabilities are managed",
			RemediationText: "Review and remediate kms vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureKmsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureKmsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_kms
	_ = findings
	return findings, nil
}

// InfrastructureLoggingCheck - Logging vulnerabilities are managed
type InfrastructureLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureLoggingCheck() *InfrastructureLoggingCheck {
	return &InfrastructureLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_logging",
			CheckTitle:      "Logging vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Logging",
			Description:     "Logging vulnerabilities are managed",
			RemediationText: "Review and remediate logging vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_logging
	_ = findings
	return findings, nil
}

// InfrastructureMonitoringCheck - Monitoring vulnerabilities are managed
type InfrastructureMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureMonitoringCheck() *InfrastructureMonitoringCheck {
	return &InfrastructureMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_monitoring",
			CheckTitle:      "Monitoring vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Monitoring",
			Description:     "Monitoring vulnerabilities are managed",
			RemediationText: "Review and remediate monitoring vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_monitoring
	_ = findings
	return findings, nil
}

// InfrastructureBackupCheck - Backup vulnerabilities are managed
type InfrastructureBackupCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureBackupCheck() *InfrastructureBackupCheck {
	return &InfrastructureBackupCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_backup",
			CheckTitle:      "Backup vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Backup",
			Description:     "Backup vulnerabilities are managed",
			RemediationText: "Review and remediate backup vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureBackupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureBackupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_backup
	_ = findings
	return findings, nil
}

// InfrastructureDisasterRecoveryCheck - Disaster recovery vulnerabilities are managed
type InfrastructureDisasterRecoveryCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureDisasterRecoveryCheck() *InfrastructureDisasterRecoveryCheck {
	return &InfrastructureDisasterRecoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_disaster_recovery",
			CheckTitle:      "Disaster recovery vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "DR",
			Description:     "Disaster recovery vulnerabilities are managed",
			RemediationText: "Review and remediate disaster recovery vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureDisasterRecoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureDisasterRecoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_disaster_recovery
	_ = findings
	return findings, nil
}

// InfrastructureAutoScalingCheck - Auto scaling vulnerabilities are managed
type InfrastructureAutoScalingCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureAutoScalingCheck() *InfrastructureAutoScalingCheck {
	return &InfrastructureAutoScalingCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_auto_scaling",
			CheckTitle:      "Auto scaling vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "AutoScaling",
			Description:     "Auto scaling vulnerabilities are managed",
			RemediationText: "Review and remediate auto scaling vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureAutoScalingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureAutoScalingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_auto_scaling
	_ = findings
	return findings, nil
}

// InfrastructureCachingCheck - Caching vulnerabilities are managed
type InfrastructureCachingCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureCachingCheck() *InfrastructureCachingCheck {
	return &InfrastructureCachingCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_caching",
			CheckTitle:      "Caching vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Cache",
			Description:     "Caching vulnerabilities are managed",
			RemediationText: "Review and remediate caching vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureCachingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureCachingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_caching
	_ = findings
	return findings, nil
}

// InfrastructureQueuesCheck - Queue vulnerabilities are managed
type InfrastructureQueuesCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureQueuesCheck() *InfrastructureQueuesCheck {
	return &InfrastructureQueuesCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_queues",
			CheckTitle:      "Queue vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Queue",
			Description:     "Queue vulnerabilities are managed",
			RemediationText: "Review and remediate queue vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureQueuesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureQueuesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_queues
	_ = findings
	return findings, nil
}

// InfrastructureServerlessCheck - Serverless vulnerabilities are managed
type InfrastructureServerlessCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureServerlessCheck() *InfrastructureServerlessCheck {
	return &InfrastructureServerlessCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_serverless",
			CheckTitle:      "Serverless vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "Serverless",
			Description:     "Serverless vulnerabilities are managed",
			RemediationText: "Review and remediate serverless vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureServerlessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureServerlessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_serverless
	_ = findings
	return findings, nil
}

// InfrastructureContainersCheck - Container infrastructure vulnerabilities are managed
type InfrastructureContainersCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureContainersCheck() *InfrastructureContainersCheck {
	return &InfrastructureContainersCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_containers",
			CheckTitle:      "Container infrastructure vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Container infrastructure vulnerabilities are managed",
			RemediationText: "Review and remediate container infrastructure vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureContainersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureContainersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_containers
	_ = findings
	return findings, nil
}

// InfrastructureOrchestrationCheck - Orchestration vulnerabilities are managed
type InfrastructureOrchestrationCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureOrchestrationCheck() *InfrastructureOrchestrationCheck {
	return &InfrastructureOrchestrationCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_orchestration",
			CheckTitle:      "Orchestration vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "Orchestration",
			Description:     "Orchestration vulnerabilities are managed",
			RemediationText: "Review and remediate orchestration vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureOrchestrationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureOrchestrationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_orchestration
	_ = findings
	return findings, nil
}

// InfrastructureServiceMeshCheck - Service mesh vulnerabilities are managed
type InfrastructureServiceMeshCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureServiceMeshCheck() *InfrastructureServiceMeshCheck {
	return &InfrastructureServiceMeshCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_service_mesh",
			CheckTitle:      "Service mesh vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "ServiceMesh",
			Description:     "Service mesh vulnerabilities are managed",
			RemediationText: "Review and remediate service mesh vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureServiceMeshCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureServiceMeshCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_service_mesh
	_ = findings
	return findings, nil
}

// InfrastructureApiGatewayCheck - API gateway vulnerabilities are managed
type InfrastructureApiGatewayCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureApiGatewayCheck() *InfrastructureApiGatewayCheck {
	return &InfrastructureApiGatewayCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_api_gateway",
			CheckTitle:      "API gateway vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "high",
			ResourceType:    "APIGateway",
			Description:     "API gateway vulnerabilities are managed",
			RemediationText: "Review and remediate api gateway vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureApiGatewayCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureApiGatewayCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_api_gateway
	_ = findings
	return findings, nil
}

// InfrastructureCdnEdgeCheck - CDN edge vulnerabilities are managed
type InfrastructureCdnEdgeCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureCdnEdgeCheck() *InfrastructureCdnEdgeCheck {
	return &InfrastructureCdnEdgeCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_cdn_edge",
			CheckTitle:      "CDN edge vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "CDNEdge",
			Description:     "CDN edge vulnerabilities are managed",
			RemediationText: "Review and remediate cdn edge vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureCdnEdgeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureCdnEdgeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_cdn_edge
	_ = findings
	return findings, nil
}

// InfrastructureEdgeComputingCheck - Edge computing vulnerabilities are managed
type InfrastructureEdgeComputingCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureEdgeComputingCheck() *InfrastructureEdgeComputingCheck {
	return &InfrastructureEdgeComputingCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_edge_computing",
			CheckTitle:      "Edge computing vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Edge",
			Description:     "Edge computing vulnerabilities are managed",
			RemediationText: "Review and remediate edge computing vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureEdgeComputingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureEdgeComputingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_edge_computing
	_ = findings
	return findings, nil
}

// InfrastructureIotCheck - IoT vulnerabilities are managed
type InfrastructureIotCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureIotCheck() *InfrastructureIotCheck {
	return &InfrastructureIotCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_iot",
			CheckTitle:      "IoT vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "IoT",
			Description:     "IoT vulnerabilities are managed",
			RemediationText: "Review and remediate iot vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureIotCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureIotCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_iot
	_ = findings
	return findings, nil
}

// InfrastructureBlockchainCheck - Blockchain vulnerabilities are managed
type InfrastructureBlockchainCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureBlockchainCheck() *InfrastructureBlockchainCheck {
	return &InfrastructureBlockchainCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_blockchain",
			CheckTitle:      "Blockchain vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Blockchain",
			Description:     "Blockchain vulnerabilities are managed",
			RemediationText: "Review and remediate blockchain vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureBlockchainCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureBlockchainCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_blockchain
	_ = findings
	return findings, nil
}

// InfrastructureQuantumCheck - Quantum vulnerabilities are managed
type InfrastructureQuantumCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureQuantumCheck() *InfrastructureQuantumCheck {
	return &InfrastructureQuantumCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_quantum",
			CheckTitle:      "Quantum vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "low",
			ResourceType:    "Quantum",
			Description:     "Quantum vulnerabilities are managed",
			RemediationText: "Review and remediate quantum vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureQuantumCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureQuantumCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_quantum
	_ = findings
	return findings, nil
}

// InfrastructureAiMlCheck - AI/ML vulnerabilities are managed
type InfrastructureAiMlCheck struct {
	metadata models.CheckMetadata
}

func NewInfrastructureAiMlCheck() *InfrastructureAiMlCheck {
	return &InfrastructureAiMlCheck{
		metadata: models.CheckMetadata{
			Provider:        "vuln",
			CheckID:         "vuln_infrastructure_ai_ml",
			CheckTitle:      "AI/ML vulnerabilities are managed",
			ServiceName:     "vuln",
			Severity:        "medium",
			ResourceType:    "AIML",
			Description:     "AI/ML vulnerabilities are managed",
			RemediationText: "Review and remediate ai/ml vulnerabilities are managed",
			Categories:      []string{"vuln", "security"},
		},
	}
}

func (c *InfrastructureAiMlCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InfrastructureAiMlCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vulnProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vulnProvider")
	}
	client, err := p.Vuln(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement vuln_infrastructure_ai_ml
	_ = findings
	return findings, nil
}
