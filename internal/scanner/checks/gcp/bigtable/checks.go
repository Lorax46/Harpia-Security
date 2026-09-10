package bigtable

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/bigtableadmin/v2"
)

type bigtableProvider interface {
	BigTable(ctx context.Context) (*bigtableadmin.Service, error)
	ProjectID() string
}

// InstanceCheck verifica se existem instâncias BigTable
type InstanceCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceCheck() *InstanceCheck {
	return &InstanceCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigtable_instance_exists",
			CheckTitle:      "BigTable instances exist",
			ServiceName:     "bigtable",
			Severity:        "medium",
			Description:     "BigTable instances should exist for data storage",
			RemediationText: "Create BigTable instances for data storage",
			Categories:      []string{"database"},
		},
	}
}

func (c *InstanceCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigtableProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement bigtableProvider")
	}
	svc, err := p.BigTable(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s", projectID)
	instances, err := svc.Projects.Instances.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list bigtable instances: %w", err)
	}

	for _, inst := range instances.Instances {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: fmt.Sprintf("BigTable instance %s exists", inst.Name),
			ResourceID: inst.Name,
			Provider: "gcp", Service: "bigtable",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No BigTable instances found",
			Provider: "gcp", Service: "bigtable",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// InstanceIamCheck verifica IAM das instâncias - verifica se há acesso público
type InstanceIamCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceIamCheck() *InstanceIamCheck {
	return &InstanceIamCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigtable_instance_iam",
			CheckTitle:      "BigTable instances have proper IAM",
			ServiceName:     "bigtable",
			Severity:        "medium",
			Description:     "BigTable instances should have proper IAM configuration without public access",
			RemediationText: "Configure IAM for BigTable instances removing allUsers and allAuthenticatedUsers",
			Categories:      []string{"identity"},
		},
	}
}

func (c *InstanceIamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceIamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigtableProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement bigtableProvider")
	}
	svc, err := p.BigTable(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s", projectID)
	instances, err := svc.Projects.Instances.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list bigtable instances: %w", err)
	}

	for _, inst := range instances.Instances {
		iamPolicy, err := svc.Projects.Instances.GetIamPolicy(inst.Name, &bigtableadmin.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			continue
		}

		hasPublicAccess := false
		publicPrincipals := []string{}
		for _, binding := range iamPolicy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					hasPublicAccess = true
					publicPrincipals = append(publicPrincipals, member)
				}
			}
		}

		status := models.StatusPass
		ext := "BigTable instance has proper IAM configuration"
		if hasPublicAccess {
			status = models.StatusFail
			ext = fmt.Sprintf("BigTable instance has public IAM access: %s", strings.Join(publicPrincipals, ", "))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: inst.Name,
			Provider: "gcp", Service: "bigtable",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// InstanceEncryptionCheck verifica criptografia das instâncias (via clusters)
type InstanceEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceEncryptionCheck() *InstanceEncryptionCheck {
	return &InstanceEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigtable_instance_encryption",
			CheckTitle:      "BigTable instances are encrypted with CMEK",
			ServiceName:     "bigtable",
			Severity:        "high",
			Description:     "BigTable instances should be encrypted with customer-managed encryption keys (CMEK)",
			RemediationText: "Enable encryption for BigTable instances using CMEK",
			Categories:      []string{"encryption"},
		},
	}
}

func (c *InstanceEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigtableProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement bigtableProvider")
	}
	svc, err := p.BigTable(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s", projectID)
	instances, err := svc.Projects.Instances.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list bigtable instances: %w", err)
	}

	for _, inst := range instances.Instances {
		clusters, err := svc.Projects.Instances.Clusters.List(inst.Name).Do()
		if err != nil {
			continue
		}

		for _, cluster := range clusters.Clusters {
			hasCMEK := cluster.EncryptionConfig != nil && cluster.EncryptionConfig.KmsKeyName != ""
			status := models.StatusPass
			ext := fmt.Sprintf("BigTable cluster %s uses customer-managed encryption key (CMEK)", cluster.Name)
			if !hasCMEK {
				status = models.StatusFail
				ext = fmt.Sprintf("BigTable cluster %s does not use customer-managed encryption key (CMEK)", cluster.Name)
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: cluster.Name,
				Provider: "gcp", Service: "bigtable",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// InstanceBackupCheck verifica backup das instâncias (via clusters)
type InstanceBackupCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceBackupCheck() *InstanceBackupCheck {
	return &InstanceBackupCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigtable_instance_backup",
			CheckTitle:      "BigTable instances have backup",
			ServiceName:     "bigtable",
			Severity:        "medium",
			Description:     "BigTable instances should have backup enabled with automated backup policies",
			RemediationText: "Enable backup for BigTable instances",
			Categories:      []string{"resilience"},
		},
	}
}

func (c *InstanceBackupCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceBackupCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigtableProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement bigtableProvider")
	}
	svc, err := p.BigTable(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s", projectID)
	instances, err := svc.Projects.Instances.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list bigtable instances: %w", err)
	}

	for _, inst := range instances.Instances {
		clusters, err := svc.Projects.Instances.Clusters.List(inst.Name).Do()
		if err != nil {
			continue
		}

		for _, cluster := range clusters.Clusters {
			backups, err := svc.Projects.Instances.Clusters.Backups.List(cluster.Name).Context(ctx).Do()
			if err != nil {
				continue
			}

			hasBackups := len(backups.Backups) > 0
			status := models.StatusPass
			ext := fmt.Sprintf("BigTable cluster %s has %d backup(s)", cluster.Name, len(backups.Backups))
			if !hasBackups {
				status = models.StatusFail
				ext = fmt.Sprintf("BigTable cluster %s does not have any backups configured", cluster.Name)
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: cluster.Name,
				Provider: "gcp", Service: "bigtable",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// InstanceLoggingCheck verifica logging das instâncias
type InstanceLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewInstanceLoggingCheck() *InstanceLoggingCheck {
	return &InstanceLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "bigtable_instance_logging",
			CheckTitle:      "BigTable instances have logging",
			ServiceName:     "bigtable",
			Severity:        "low",
			Description:     "BigTable instances should have audit logging enabled for data access monitoring",
			RemediationText: "Enable audit logging for BigTable instances",
			Categories:      []string{"logging"},
		},
	}
}

func (c *InstanceLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *InstanceLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(bigtableProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement bigtableProvider")
	}
	svc, err := p.BigTable(ctx)
	if err != nil {
		return nil, err
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	parent := fmt.Sprintf("projects/%s", projectID)
	instances, err := svc.Projects.Instances.List(parent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list bigtable instances: %w", err)
	}

	for _, inst := range instances.Instances {
		iamPolicy, err := svc.Projects.Instances.GetIamPolicy(inst.Name, &bigtableadmin.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			continue
		}

		hasAuditLogging := false
		for _, binding := range iamPolicy.Bindings {
			for _, member := range binding.Members {
				if strings.Contains(member, "audit") || strings.Contains(member, "log") {
					hasAuditLogging = true
					break
				}
			}
			if hasAuditLogging {
				break
			}
		}

		status := models.StatusPass
		ext := "BigTable instance has audit logging configured"
		if !hasAuditLogging {
			status = models.StatusFail
			ext = "BigTable instance does not have audit logging configured"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: inst.Name,
			Provider: "gcp", Service: "bigtable",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}
