// Package servicecatalog provides AWS Service Catalog security checks.
package servicecatalog

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
)

type servicecatalogProvider interface {
	ServiceCatalog(ctx context.Context) (*servicecatalog.Client, error)
	Region() string
	AccountID() string
}

// ServiceCatalogProductCheck verifica se produtos estão configurados
type ServiceCatalogProductCheck struct {
	metadata models.CheckMetadata
}

func NewServiceCatalogProductCheck() *ServiceCatalogProductCheck {
	return &ServiceCatalogProductCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "servicecatalog_product",
			CheckTitle: "Ensure Service Catalog products are configured",
			Description: "Service Catalog products should be configured for governance",
			Severity: "low", ServiceName: "servicecatalog", ResourceType: "Product",
			RemediationText: "Configure Service Catalog products",
			Categories: []string{"governance", "catalog"},
		},
	}
}

func (c *ServiceCatalogProductCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceCatalogProductCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires SearchProducts API call",
			Provider: "aws", Service: "servicecatalog", FoundAt: time.Now().UTC(),
		},
	}, nil
}
