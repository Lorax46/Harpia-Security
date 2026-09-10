package cloudsql

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/sqladmin/v1"
)

// === cloudsql_instance_automated_backups ===

type CloudSQLInstanceAutomatedBackupsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceAutomatedBackupsCheck() *CloudSQLInstanceAutomatedBackupsCheck {
	return &CloudSQLInstanceAutomatedBackupsCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_automated_backups",
			CheckTitle:      "Cloud SQL database instance has automated backups configured",
			ServiceName:     "cloudsql",
			Severity:        "high",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances are checked for automated backups being configured to run on a schedule and support point-in-time recovery.",
			Risk:            "Without automated backups, data loss may occur in case of accidental deletion, corruption, or infrastructure failure",
			RemediationText: "Enable automated backups on all Cloud SQL instances holding important data. Set retention and schedules to meet RPO/RTO, and enable point-in-time recovery.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
			Categories:      []string{"cloudsql", "backup", "disaster-recovery"},
		},
	}
}

func (c *CloudSQLInstanceAutomatedBackupsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceAutomatedBackupsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			backupConfig := instance.Settings.BackupConfiguration
			if backupConfig == nil || !backupConfig.Enabled {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' does not have automated backups enabled", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has automated backups enabled (start time: %s)", instance.Name, backupConfig.StartTime),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_cmek_encryption_enabled ===

type CloudSQLInstanceCmekEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceCmekEncryptionCheck() *CloudSQLInstanceCmekEncryptionCheck {
	return &CloudSQLInstanceCmekEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_cmek_encryption_enabled",
			CheckTitle:      "Cloud SQL instance is encrypted with a customer-managed key (CMEK)",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances use customer-managed encryption keys (CMEK) via Cloud KMS for at-rest encryption.",
			Risk:            "Without CMEK, encryption key management is fully controlled by Google, reducing customer control over data-at-rest encryption",
			RemediationText: "For instances storing personal or sensitive data, create new Cloud SQL instances with CMEK using a Cloud KMS key in the same region.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/cmek",
			Categories:      []string{"cloudsql", "encryption", "kms"},
		},
	}
}

func (c *CloudSQLInstanceCmekEncryptionCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceCmekEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			diskEncryption := instance.DiskEncryptionConfiguration
			if diskEncryption == nil || diskEncryption.KmsKeyName == "" {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' is not encrypted with a customer-managed key (CMEK)", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' is encrypted with CMEK: %s", instance.Name, diskEncryption.KmsKeyName),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_high_availability_enabled ===

type CloudSQLInstanceHighAvailabilityCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceHighAvailabilityCheck() *CloudSQLInstanceHighAvailabilityCheck {
	return &CloudSQLInstanceHighAvailabilityCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_high_availability_enabled",
			CheckTitle:      "Cloud SQL instance has high availability (REGIONAL) configured",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Ensures that Cloud SQL instances have high availability configured by setting availabilityType to REGIONAL.",
			Risk:            "Instances without high availability are vulnerable to zone-level outages, resulting in extended downtime",
			RemediationText: "Set availabilityType to REGIONAL for all production Cloud SQL instances. This creates a standby replica in a different zone and enables automatic failover.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/high-availability",
			Categories:      []string{"cloudsql", "high-availability", "reliability"},
		},
	}
}

func (c *CloudSQLInstanceHighAvailabilityCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceHighAvailabilityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			haEnabled := instance.Settings.AvailabilityType == "REGIONAL"
			if !haEnabled {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' does not have high availability configured (availabilityType: %s)", instance.Name, instance.Settings.AvailabilityType),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has high availability configured (REGIONAL)", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_no_public_ip ===

type CloudSQLInstanceNoPublicIPCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceNoPublicIPCheck() *CloudSQLInstanceNoPublicIPCheck {
	return &CloudSQLInstanceNoPublicIPCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_no_public_ip",
			CheckTitle:      "Cloud SQL database instance does not have a public IP address",
			ServiceName:     "cloudsql",
			Severity:        "high",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances are evaluated for exposure via public IP addresses instead of private IP connectivity within a VPC.",
			Risk:            "Instances with public IPs are directly accessible from the internet, increasing the attack surface and risk of unauthorized access",
			RemediationText: "Prefer private IP and disable public endpoints. Access databases over VPC, VPN/Interconnect, or Private Service Connect.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/configure-private-ip",
			Categories:      []string{"cloudsql", "network", "exposure"},
		},
	}
}

func (c *CloudSQLInstanceNoPublicIPCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceNoPublicIPCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			hasPublicIP := false
			for _, addr := range instance.IpAddresses {
				if addr.Type == "PRIMARY" {
					hasPublicIP = true
					break
				}
			}
			if hasPublicIP {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has a public IP address", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' does not have a public IP address", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_no_ip_forwarding ===

type CloudSQLInstanceNoIPForwardingCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceNoIPForwardingCheck() *CloudSQLInstanceNoIPForwardingCheck {
	return &CloudSQLInstanceNoIPForwardingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_no_ip_forwarding",
			CheckTitle:      "Cloud SQL instance has IP forwarding disabled",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances are evaluated for IP forwarding being disabled to prevent packet routing through the instance.",
			Risk:            "IP forwarding enabled on a database instance could allow it to act as a network router, potentially enabling traffic interception or exfiltration",
			RemediationText: "Disable IP forwarding on all Cloud SQL instances unless explicitly required.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/flags",
			Categories:      []string{"cloudsql", "network", "hardening"},
		},
	}
}

func (c *CloudSQLInstanceNoIPForwardingCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceNoIPForwardingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			ipForwardingEnabled := false
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == "cloudsql.enable_ip_forward" && flag.Value == "on" {
					ipForwardingEnabled = true
					break
				}
			}
			if ipForwardingEnabled {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has IP forwarding enabled", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has IP forwarding disabled", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_network_egress_controlled ===

type CloudSQLInstanceNetworkEgressControlledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceNetworkEgressControlledCheck() *CloudSQLInstanceNetworkEgressControlledCheck {
	return &CloudSQLInstanceNetworkEgressControlledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_network_egress_controlled",
			CheckTitle:      "Cloud SQL instance has network egress controlled",
			ServiceName:     "cloudsql",
			Severity:        "medium",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances are evaluated for network egress controls to prevent unauthorized data exfiltration.",
			Risk:            "Uncontrolled egress from Cloud SQL instances may allow data exfiltration through external connections",
			RemediationText: "Configure Cloud SQL instances with network egress controls and restrict outbound connections. Use VPC Service Controls and firewall rules.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/configure-outbound-connections",
			Categories:      []string{"cloudsql", "network", "egress"},
		},
	}
}

func (c *CloudSQLInstanceNetworkEgressControlledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceNetworkEgressControlledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			hasPublicIP := false
			hasPrivateIP := false
			for _, addr := range instance.IpAddresses {
				if addr.Type == "PRIMARY" {
					hasPublicIP = true
				}
				if addr.Type == "PRIVATE" {
					hasPrivateIP = true
				}
			}
			egressControlled := hasPrivateIP && !hasPublicIP
			if !egressControlled {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' does not have network egress controlled (has public IP)", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' has network egress controlled (private IP only)", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}

// === cloudsql_instance_ssl_connections_required ===

type CloudSQLInstanceSSLConnectionsRequiredCheck struct {
	metadata models.CheckMetadata
}

func NewCloudSQLInstanceSSLConnectionsRequiredCheck() *CloudSQLInstanceSSLConnectionsRequiredCheck {
	return &CloudSQLInstanceSSLConnectionsRequiredCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudsql_instance_ssl_connections_required",
			CheckTitle:      "Cloud SQL database instance requires SSL for all incoming connections",
			ServiceName:     "cloudsql",
			Severity:        "high",
			ResourceType:    "SQLInstance",
			ResourceGroup:   "CloudSQL",
			Description:     "Cloud SQL instances enforce SSL/TLS-only connections, rejecting plaintext traffic.",
			Risk:            "Without SSL/TLS enforcement, database traffic could be intercepted, exposing credentials and sensitive data in transit",
			RemediationText: "Require TLS for all connections. Prefer TRUSTED_CLIENT_CERTIFICATE_REQUIRED or use Cloud SQL Auth Proxy/Connectors.",
			RemediationURL:  "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
			Categories:      []string{"cloudsql", "encryption", "tls"},
		},
	}
}

func (c *CloudSQLInstanceSSLConnectionsRequiredCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *CloudSQLInstanceSSLConnectionsRequiredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		SQL(ctx context.Context) (*sqladmin.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa SQL() ou ProjectID()")
	}

	sqlService, err := p.SQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente SQL: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	listReq := sqlService.Instances.List(projectID)
	if err := listReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, instance := range page.Items {
			requireSSL := instance.Settings.IpConfiguration.RequireSsl
			if !requireSSL {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' does not require SSL connections", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
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
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud SQL instance '%s' requires SSL connections", instance.Name),
					ResourceID:     instance.Name,
					ResourceARN:    fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
					Provider:       "gcp",
					Service:        "cloudsql",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar instâncias SQL: %w", err)
	}

	return findings, nil
}