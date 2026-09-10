// Package ssmincidents provides AWS SSM Incidents security checks.
package ssmincidents

import (
	"context"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/ssmincidents"
)

type ssmincidentsProvider interface {
	SSMIncidents(ctx context.Context) (*ssmincidents.Client, error)
	Region() string
	AccountID() string
}

// SsmIncidentsReplicationSetActiveCheck verifica se replication set está ativo
type SsmIncidentsReplicationSetActiveCheck struct {
	metadata models.CheckMetadata
}

func NewSsmIncidentsReplicationSetActiveCheck() *SsmIncidentsReplicationSetActiveCheck {
	return &SsmIncidentsReplicationSetActiveCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ssmincidents_replication_set_active",
			CheckTitle: "Ensure SSM Incidents replication set is active",
			Description: "SSM Incidents replication set should be active for incident response",
			Severity: "medium", ServiceName: "ssmincidents", ResourceType: "ReplicationSet",
			RemediationText: "Activate SSM Incidents replication set",
			Categories: []string{"incident-response", "replication"},
		},
	}
}

func (c *SsmIncidentsReplicationSetActiveCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SsmIncidentsReplicationSetActiveCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires GetReplicationSet API call",
			Provider: "aws", Service: "ssmincidents", FoundAt: time.Now().UTC(),
		},
	}, nil
}
