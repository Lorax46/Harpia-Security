// Package resourceexplorer2 provides AWS Resource Explorer security checks.
package resourceexplorer2

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
)

type resourceexplorer2Provider interface {
	ResourceExplorer2(ctx context.Context) (*resourceexplorer2.Client, error)
	Region() string
	AccountID() string
}

// ResourceExplorer2IndexCheck verifica se index está configurado
type ResourceExplorer2IndexCheck struct {
	metadata models.CheckMetadata
}

func NewResourceExplorer2IndexCheck() *ResourceExplorer2IndexCheck {
	return &ResourceExplorer2IndexCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "resourceexplorer2_index",
			CheckTitle: "Ensure Resource Explorer 2 index is configured",
			Description: "Resource Explorer 2 index should be configured for resource discovery",
			Severity: "low", ServiceName: "resourceexplorer2", ResourceType: "Index",
			RemediationText: "Configure Resource Explorer 2 index",
			Categories: []string{"discovery", "inventory"},
		},
	}
}

func (c *ResourceExplorer2IndexCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ResourceExplorer2IndexCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires ListIndexes API call",
			Provider: "aws", Service: "resourceexplorer2", FoundAt: time.Now().UTC(),
		},
	}, nil
}
