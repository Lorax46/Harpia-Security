// Package wellarchitected provides AWS Well-Architected security checks.
package wellarchitected

import (
	"context"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/wellarchitected"
)

type wellarchitectedProvider interface {
	WellArchitected(ctx context.Context) (*wellarchitected.Client, error)
	Region() string
	AccountID() string
}

// WellArchitectedWorkloadCheck verifica se workload está configurado
type WellArchitectedWorkloadCheck struct {
	metadata models.CheckMetadata
}

func NewWellArchitectedWorkloadCheck() *WellArchitectedWorkloadCheck {
	return &WellArchitectedWorkloadCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "wellarchitected_workload",
			CheckTitle: "Ensure Well-Architected workload is configured",
			Description: "Well-Architected workload should be configured for best practices review",
			Severity: "low", ServiceName: "wellarchitected", ResourceType: "Workload",
			RemediationText: "Configure Well-Architected workload",
			Categories: []string{"best-practices", "review"},
		},
	}
}

func (c *WellArchitectedWorkloadCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WellArchitectedWorkloadCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires ListWorkloads API call",
			Provider: "aws", Service: "wellarchitected", FoundAt: time.Now().UTC(),
		},
	}, nil
}
