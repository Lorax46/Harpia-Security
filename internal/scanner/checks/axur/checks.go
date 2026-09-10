package axur

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type axurProvider interface {
	Axur(ctx context.Context) (interface{}, error)
}

// AttackSurfaceCheck - Attack surface is monitored
type AttackSurfaceCheck struct {
	metadata models.CheckMetadata
}

func NewAttackSurfaceCheck() *AttackSurfaceCheck {
	return &AttackSurfaceCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_attack_surface",
			CheckTitle:      "Attack surface is monitored",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "AttackSurface",
			Description:     "Attack surface is monitored",
			RemediationText: "Review and remediate attack surface is monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *AttackSurfaceCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AttackSurfaceCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_attack_surface
	_ = findings
	return findings, nil
}

// AssetDiscoveryCheck - Asset discovery is enabled
type AssetDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewAssetDiscoveryCheck() *AssetDiscoveryCheck {
	return &AssetDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_asset_discovery",
			CheckTitle:      "Asset discovery is enabled",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Asset",
			Description:     "Asset discovery is enabled",
			RemediationText: "Review and remediate asset discovery is enabled",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *AssetDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AssetDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_asset_discovery
	_ = findings
	return findings, nil
}

// AssetInventoryCheck - Asset inventory is maintained
type AssetInventoryCheck struct {
	metadata models.CheckMetadata
}

func NewAssetInventoryCheck() *AssetInventoryCheck {
	return &AssetInventoryCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_asset_inventory",
			CheckTitle:      "Asset inventory is maintained",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Inventory",
			Description:     "Asset inventory is maintained",
			RemediationText: "Review and remediate asset inventory is maintained",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *AssetInventoryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AssetInventoryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_asset_inventory
	_ = findings
	return findings, nil
}

// DomainMonitoringCheck - Domain monitoring is enabled
type DomainMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewDomainMonitoringCheck() *DomainMonitoringCheck {
	return &DomainMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_domain_monitoring",
			CheckTitle:      "Domain monitoring is enabled",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Domain",
			Description:     "Domain monitoring is enabled",
			RemediationText: "Review and remediate domain monitoring is enabled",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *DomainMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DomainMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_domain_monitoring
	_ = findings
	return findings, nil
}

// SubdomainTakeoverCheck - Subdomain takeover is detected
type SubdomainTakeoverCheck struct {
	metadata models.CheckMetadata
}

func NewSubdomainTakeoverCheck() *SubdomainTakeoverCheck {
	return &SubdomainTakeoverCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_subdomain_takeover",
			CheckTitle:      "Subdomain takeover is detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Subdomain",
			Description:     "Subdomain takeover is detected",
			RemediationText: "Review and remediate subdomain takeover is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *SubdomainTakeoverCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SubdomainTakeoverCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_subdomain_takeover
	_ = findings
	return findings, nil
}

// SslMonitoringCheck - SSL certificates are monitored
type SslMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewSslMonitoringCheck() *SslMonitoringCheck {
	return &SslMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_ssl_monitoring",
			CheckTitle:      "SSL certificates are monitored",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "SSL",
			Description:     "SSL certificates are monitored",
			RemediationText: "Review and remediate ssl certificates are monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *SslMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SslMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_ssl_monitoring
	_ = findings
	return findings, nil
}

// PortMonitoringCheck - Ports are monitored
type PortMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewPortMonitoringCheck() *PortMonitoringCheck {
	return &PortMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_port_monitoring",
			CheckTitle:      "Ports are monitored",
			ServiceName:     "axur",
			Severity:        "medium",
			ResourceType:    "Port",
			Description:     "Ports are monitored",
			RemediationText: "Review and remediate ports are monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *PortMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PortMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_port_monitoring
	_ = findings
	return findings, nil
}

// ServiceMonitoringCheck - Services are monitored
type ServiceMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewServiceMonitoringCheck() *ServiceMonitoringCheck {
	return &ServiceMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_service_monitoring",
			CheckTitle:      "Services are monitored",
			ServiceName:     "axur",
			Severity:        "medium",
			ResourceType:    "Service",
			Description:     "Services are monitored",
			RemediationText: "Review and remediate services are monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ServiceMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_service_monitoring
	_ = findings
	return findings, nil
}

// TechnologyMonitoringCheck - Technologies are monitored
type TechnologyMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewTechnologyMonitoringCheck() *TechnologyMonitoringCheck {
	return &TechnologyMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_technology_monitoring",
			CheckTitle:      "Technologies are monitored",
			ServiceName:     "axur",
			Severity:        "low",
			ResourceType:    "Technology",
			Description:     "Technologies are monitored",
			RemediationText: "Review and remediate technologies are monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *TechnologyMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TechnologyMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_technology_monitoring
	_ = findings
	return findings, nil
}

// DnsMonitoringCheck - DNS is monitored
type DnsMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewDnsMonitoringCheck() *DnsMonitoringCheck {
	return &DnsMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_dns_monitoring",
			CheckTitle:      "DNS is monitored",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "DNS",
			Description:     "DNS is monitored",
			RemediationText: "Review and remediate dns is monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *DnsMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DnsMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_dns_monitoring
	_ = findings
	return findings, nil
}

// IpMonitoringCheck - IP addresses are monitored
type IpMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewIpMonitoringCheck() *IpMonitoringCheck {
	return &IpMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_ip_monitoring",
			CheckTitle:      "IP addresses are monitored",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "IP",
			Description:     "IP addresses are monitored",
			RemediationText: "Review and remediate ip addresses are monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *IpMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IpMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_ip_monitoring
	_ = findings
	return findings, nil
}

// CloudMonitoringCheck - Cloud resources are monitored
type CloudMonitoringCheck struct {
	metadata models.CheckMetadata
}

func NewCloudMonitoringCheck() *CloudMonitoringCheck {
	return &CloudMonitoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_cloud_monitoring",
			CheckTitle:      "Cloud resources are monitored",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Cloud",
			Description:     "Cloud resources are monitored",
			RemediationText: "Review and remediate cloud resources are monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *CloudMonitoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudMonitoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_cloud_monitoring
	_ = findings
	return findings, nil
}

// DarkWebCheck - Dark web is monitored
type DarkWebCheck struct {
	metadata models.CheckMetadata
}

func NewDarkWebCheck() *DarkWebCheck {
	return &DarkWebCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_dark_web",
			CheckTitle:      "Dark web is monitored",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "DarkWeb",
			Description:     "Dark web is monitored",
			RemediationText: "Review and remediate dark web is monitored",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *DarkWebCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DarkWebCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_dark_web
	_ = findings
	return findings, nil
}

// LeakedCredentialsCheck - Leaked credentials are detected
type LeakedCredentialsCheck struct {
	metadata models.CheckMetadata
}

func NewLeakedCredentialsCheck() *LeakedCredentialsCheck {
	return &LeakedCredentialsCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_leaked_credentials",
			CheckTitle:      "Leaked credentials are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Credential",
			Description:     "Leaked credentials are detected",
			RemediationText: "Review and remediate leaked credentials are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *LeakedCredentialsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LeakedCredentialsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_leaked_credentials
	_ = findings
	return findings, nil
}

// DataExposureCheck - Data exposure is detected
type DataExposureCheck struct {
	metadata models.CheckMetadata
}

func NewDataExposureCheck() *DataExposureCheck {
	return &DataExposureCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_data_exposure",
			CheckTitle:      "Data exposure is detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Exposure",
			Description:     "Data exposure is detected",
			RemediationText: "Review and remediate data exposure is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *DataExposureCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataExposureCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_data_exposure
	_ = findings
	return findings, nil
}

// CodeExposureCheck - Code exposure is detected
type CodeExposureCheck struct {
	metadata models.CheckMetadata
}

func NewCodeExposureCheck() *CodeExposureCheck {
	return &CodeExposureCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_code_exposure",
			CheckTitle:      "Code exposure is detected",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Code",
			Description:     "Code exposure is detected",
			RemediationText: "Review and remediate code exposure is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *CodeExposureCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CodeExposureCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_code_exposure
	_ = findings
	return findings, nil
}

// ConfigExposureCheck - Configuration exposure is detected
type ConfigExposureCheck struct {
	metadata models.CheckMetadata
}

func NewConfigExposureCheck() *ConfigExposureCheck {
	return &ConfigExposureCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_config_exposure",
			CheckTitle:      "Configuration exposure is detected",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Config",
			Description:     "Configuration exposure is detected",
			RemediationText: "Review and remediate configuration exposure is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ConfigExposureCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfigExposureCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_config_exposure
	_ = findings
	return findings, nil
}

// ApiExposureCheck - API exposure is detected
type ApiExposureCheck struct {
	metadata models.CheckMetadata
}

func NewApiExposureCheck() *ApiExposureCheck {
	return &ApiExposureCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_api_exposure",
			CheckTitle:      "API exposure is detected",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "API",
			Description:     "API exposure is detected",
			RemediationText: "Review and remediate api exposure is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ApiExposureCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiExposureCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_api_exposure
	_ = findings
	return findings, nil
}

// ExposedSecretsCheck - Exposed secrets are detected
type ExposedSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewExposedSecretsCheck() *ExposedSecretsCheck {
	return &ExposedSecretsCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_secrets",
			CheckTitle:      "Exposed secrets are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Secret",
			Description:     "Exposed secrets are detected",
			RemediationText: "Review and remediate exposed secrets are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_secrets
	_ = findings
	return findings, nil
}

// ExposedTokensCheck - Exposed tokens are detected
type ExposedTokensCheck struct {
	metadata models.CheckMetadata
}

func NewExposedTokensCheck() *ExposedTokensCheck {
	return &ExposedTokensCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_tokens",
			CheckTitle:      "Exposed tokens are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Token",
			Description:     "Exposed tokens are detected",
			RemediationText: "Review and remediate exposed tokens are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedTokensCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedTokensCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_tokens
	_ = findings
	return findings, nil
}

// ExposedKeysCheck - Exposed keys are detected
type ExposedKeysCheck struct {
	metadata models.CheckMetadata
}

func NewExposedKeysCheck() *ExposedKeysCheck {
	return &ExposedKeysCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_keys",
			CheckTitle:      "Exposed keys are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Key",
			Description:     "Exposed keys are detected",
			RemediationText: "Review and remediate exposed keys are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedKeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedKeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_keys
	_ = findings
	return findings, nil
}

// ExposedCertificatesCheck - Exposed certificates are detected
type ExposedCertificatesCheck struct {
	metadata models.CheckMetadata
}

func NewExposedCertificatesCheck() *ExposedCertificatesCheck {
	return &ExposedCertificatesCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_certificates",
			CheckTitle:      "Exposed certificates are detected",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Exposed certificates are detected",
			RemediationText: "Review and remediate exposed certificates are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedCertificatesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedCertificatesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_certificates
	_ = findings
	return findings, nil
}

// ExposedDatabasesCheck - Exposed databases are detected
type ExposedDatabasesCheck struct {
	metadata models.CheckMetadata
}

func NewExposedDatabasesCheck() *ExposedDatabasesCheck {
	return &ExposedDatabasesCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_databases",
			CheckTitle:      "Exposed databases are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Database",
			Description:     "Exposed databases are detected",
			RemediationText: "Review and remediate exposed databases are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedDatabasesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedDatabasesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_databases
	_ = findings
	return findings, nil
}

// ExposedStorageCheck - Exposed storage is detected
type ExposedStorageCheck struct {
	metadata models.CheckMetadata
}

func NewExposedStorageCheck() *ExposedStorageCheck {
	return &ExposedStorageCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_storage",
			CheckTitle:      "Exposed storage is detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Storage",
			Description:     "Exposed storage is detected",
			RemediationText: "Review and remediate exposed storage is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedStorageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedStorageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_storage
	_ = findings
	return findings, nil
}

// ExposedBucketsCheck - Exposed buckets are detected
type ExposedBucketsCheck struct {
	metadata models.CheckMetadata
}

func NewExposedBucketsCheck() *ExposedBucketsCheck {
	return &ExposedBucketsCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_buckets",
			CheckTitle:      "Exposed buckets are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Bucket",
			Description:     "Exposed buckets are detected",
			RemediationText: "Review and remediate exposed buckets are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedBucketsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedBucketsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_buckets
	_ = findings
	return findings, nil
}

// ExposedContainersCheck - Exposed containers are detected
type ExposedContainersCheck struct {
	metadata models.CheckMetadata
}

func NewExposedContainersCheck() *ExposedContainersCheck {
	return &ExposedContainersCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_containers",
			CheckTitle:      "Exposed containers are detected",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Container",
			Description:     "Exposed containers are detected",
			RemediationText: "Review and remediate exposed containers are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedContainersCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedContainersCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_containers
	_ = findings
	return findings, nil
}

// ExposedApisCheck - Exposed APIs are detected
type ExposedApisCheck struct {
	metadata models.CheckMetadata
}

func NewExposedApisCheck() *ExposedApisCheck {
	return &ExposedApisCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_apis",
			CheckTitle:      "Exposed APIs are detected",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "API",
			Description:     "Exposed APIs are detected",
			RemediationText: "Review and remediate exposed apis are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedApisCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedApisCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_apis
	_ = findings
	return findings, nil
}

// ExposedAdminCheck - Exposed admin interfaces are detected
type ExposedAdminCheck struct {
	metadata models.CheckMetadata
}

func NewExposedAdminCheck() *ExposedAdminCheck {
	return &ExposedAdminCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_admin",
			CheckTitle:      "Exposed admin interfaces are detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Admin",
			Description:     "Exposed admin interfaces are detected",
			RemediationText: "Review and remediate exposed admin interfaces are detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedAdminCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedAdminCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_admin
	_ = findings
	return findings, nil
}

// ExposedRemoteCheck - Exposed remote access is detected
type ExposedRemoteCheck struct {
	metadata models.CheckMetadata
}

func NewExposedRemoteCheck() *ExposedRemoteCheck {
	return &ExposedRemoteCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_exposed_remote",
			CheckTitle:      "Exposed remote access is detected",
			ServiceName:     "axur",
			Severity:        "critical",
			ResourceType:    "Remote",
			Description:     "Exposed remote access is detected",
			RemediationText: "Review and remediate exposed remote access is detected",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *ExposedRemoteCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExposedRemoteCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_exposed_remote
	_ = findings
	return findings, nil
}

// RiskScoringCheck - Risk scoring is calculated
type RiskScoringCheck struct {
	metadata models.CheckMetadata
}

func NewRiskScoringCheck() *RiskScoringCheck {
	return &RiskScoringCheck{
		metadata: models.CheckMetadata{
			Provider:        "axur",
			CheckID:         "axur_risk_scoring",
			CheckTitle:      "Risk scoring is calculated",
			ServiceName:     "axur",
			Severity:        "high",
			ResourceType:    "Risk",
			Description:     "Risk scoring is calculated",
			RemediationText: "Review and remediate risk scoring is calculated",
			Categories:      []string{"axur", "security"},
		},
	}
}

func (c *RiskScoringCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RiskScoringCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(axurProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement axurProvider")
	}
	client, err := p.Axur(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement axur_risk_scoring
	_ = findings
	return findings, nil
}
