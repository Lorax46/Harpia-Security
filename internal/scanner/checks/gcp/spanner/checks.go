package spanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"google.golang.org/api/spanner/v1"
)

type spannerProvider interface {
	Spanner(ctx context.Context) (*spanner.Service, error)
	ProjectID() string
}

// -----------------------------------------------------------------------------
// 1. SpannerInstanceEncryptionCheck – verifica se a instância usa CMEK
//    (verifica label "encryption=cmek" pois o campo EncryptionConfig não
//    está disponível nesta versão da lib; Spanner criptografa por padrão,
//    mas CMEK requer configuração explícita via label ou database-level)
// -----------------------------------------------------------------------------

type SpannerInstanceEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewSpannerInstanceEncryptionCheck() *SpannerInstanceEncryptionCheck {
	return &SpannerInstanceEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "spanner_instance_encryption",
			CheckTitle:      "Spanner instance should use CMEK encryption",
			ServiceName:     "spanner",
			Severity:        "high",
			ResourceType:    "Instance",
			Description:     "Spanner instances should use CMEK encryption",
			RemediationText: "Enable CMEK encryption for Spanner instances",
			Categories:      []string{"spanner", "encryption"},
		},
	}
}

func (c *SpannerInstanceEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpannerInstanceEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(spannerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa spannerProvider")
	}
	spannerService, err := p.Spanner(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := spannerService.Projects.Instances.List("projects/" + p.ProjectID())
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			hasEncryption := false
			// Verifica se a instância possui label indicando CMEK
			if v, ok := instance.Labels["encryption"]; ok && v == "cmek" {
				hasEncryption = true
			}
			status := models.StatusPass
			ext := "Instance uses CMEK encryption"
			if !hasEncryption {
				status = models.StatusFail
				ext = "Instance does not use CMEK encryption"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "spanner",
				ResourceID:     instance.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// -----------------------------------------------------------------------------
// 2. SpannerInstancePublicAccessCheck – verifica se a instância não é pública
//    (verifica label "network_type=private" para considerar não-público)
// -----------------------------------------------------------------------------

type SpannerInstancePublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewSpannerInstancePublicAccessCheck() *SpannerInstancePublicAccessCheck {
	return &SpannerInstancePublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "spanner_instance_public_access",
			CheckTitle:      "Spanner instance should not be publicly accessible",
			ServiceName:     "spanner",
			Severity:        "critical",
			ResourceType:    "Instance",
			Description:     "Spanner instances should not be exposed to the public internet",
			RemediationText: "Restrict Spanner instance access to private IP / VPC",
			Categories:      []string{"spanner", "network"},
		},
	}
}

func (c *SpannerInstancePublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpannerInstancePublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(spannerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa spannerProvider")
	}
	spannerService, err := p.Spanner(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := spannerService.Projects.Instances.List("projects/" + p.ProjectID())
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			isPublic := true
			// Considera não-público se houver label de rede privada
			if v, ok := instance.Labels["network_type"]; ok && v == "private" {
				isPublic = false
			}
			status := models.StatusPass
			ext := "Instance is not publicly accessible"
			if isPublic {
				status = models.StatusFail
				ext = "Instance may be publicly accessible"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "spanner",
				ResourceID:     instance.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// -----------------------------------------------------------------------------
// 3. SpannerInstanceLoggingCheck – verifica se o logging está habilitado
// -----------------------------------------------------------------------------

type SpannerInstanceLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewSpannerInstanceLoggingCheck() *SpannerInstanceLoggingCheck {
	return &SpannerInstanceLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "spanner_instance_logging",
			CheckTitle:      "Spanner instance should have audit logging enabled",
			ServiceName:     "spanner",
			Severity:        "medium",
			ResourceType:    "Instance",
			Description:     "Spanner instances should have audit logging enabled via Data Access logs",
			RemediationText: "Enable Data Access audit logs for Spanner instances",
			Categories:      []string{"spanner", "logging"},
		},
	}
}

func (c *SpannerInstanceLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpannerInstanceLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(spannerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa spannerProvider")
	}
	spannerService, err := p.Spanner(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := spannerService.Projects.Instances.List("projects/" + p.ProjectID())
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			hasLogging := false
			// Verifica label que indica logging habilitado
			if v, ok := instance.Labels["audit_logging"]; ok && v == "enabled" {
				hasLogging = true
			}
			status := models.StatusPass
			ext := "Audit logging is enabled for the instance"
			if !hasLogging {
				status = models.StatusFail
				ext = "Audit logging is not enabled for the instance"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "spanner",
				ResourceID:     instance.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// -----------------------------------------------------------------------------
// 4. SpannerInstanceAutoscalingCheck – verifica se autoscaling está habilitado
// -----------------------------------------------------------------------------

type SpannerInstanceAutoscalingCheck struct {
	metadata models.CheckMetadata
}

func NewSpannerInstanceAutoscalingCheck() *SpannerInstanceAutoscalingCheck {
	return &SpannerInstanceAutoscalingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "spanner_instance_autoscaling",
			CheckTitle:      "Spanner instance should use autoscaling",
			ServiceName:     "spanner",
			Severity:        "low",
			ResourceType:    "Instance",
			Description:     "Spanner instances should use autoscaling for cost efficiency",
			RemediationText: "Configure autoscaling for the Spanner instance",
			Categories:      []string{"spanner", "autoscaling"},
		},
	}
}

func (c *SpannerInstanceAutoscalingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpannerInstanceAutoscalingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(spannerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa spannerProvider")
	}
	spannerService, err := p.Spanner(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := spannerService.Projects.Instances.List("projects/" + p.ProjectID())
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			hasAutoscaling := instance.AutoscalingConfig != nil &&
				instance.AutoscalingConfig.AutoscalingLimits != nil
			status := models.StatusPass
			ext := "Instance uses autoscaling"
			if !hasAutoscaling {
				status = models.StatusFail
				ext = "Instance does not use autoscaling"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "spanner",
				ResourceID:     instance.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// -----------------------------------------------------------------------------
// 5. SpannerDatabaseEncryptionCheck – verifica se bancos de dados usam CMEK
// -----------------------------------------------------------------------------

type SpannerDatabaseEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewSpannerDatabaseEncryptionCheck() *SpannerDatabaseEncryptionCheck {
	return &SpannerDatabaseEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "spanner_database_encryption",
			CheckTitle:      "Spanner database should use CMEK encryption",
			ServiceName:     "spanner",
			Severity:        "high",
			ResourceType:    "Database",
			Description:     "Spanner databases should use CMEK encryption",
			RemediationText: "Enable CMEK encryption for Spanner databases",
			Categories:      []string{"spanner", "encryption"},
		},
	}
}

func (c *SpannerDatabaseEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SpannerDatabaseEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(spannerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa spannerProvider")
	}
	spannerService, err := p.Spanner(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// Itera sobre todas as instâncias
	instancesReq := spannerService.Projects.Instances.List("projects/" + p.ProjectID())
	err = instancesReq.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			// Lista bancos de dados dentro da instância
			dbsReq := spannerService.Projects.Instances.Databases.List(instance.Name)
			dbErr := dbsReq.Pages(ctx, func(dbPage *spanner.ListDatabasesResponse) error {
				for _, db := range dbPage.Databases {
					hasEncryption := db.EncryptionConfig != nil && db.EncryptionConfig.KmsKeyName != ""
					status := models.StatusPass
					ext := "Database uses CMEK encryption"
					if !hasEncryption {
						status = models.StatusFail
						ext = "Database does not use CMEK encryption"
					}
					findings = append(findings, models.Finding{
						ID:             c.metadata.CheckID,
						Title:          c.metadata.CheckTitle,
						Description:    c.metadata.Description,
						Severity:       c.metadata.Severity,
						Status:         status,
						StatusExtended: ext,
						Provider:       "gcp",
						Service:        "spanner",
						ResourceID:     db.Name,
						Remediation:    c.metadata.RemediationText,
						Categories:     c.metadata.Categories,
						FoundAt:        time.Now(),
					})
				}
				return nil
			})
			if dbErr != nil {
				return dbErr
			}
		}
		return nil
	})
	return findings, err
}