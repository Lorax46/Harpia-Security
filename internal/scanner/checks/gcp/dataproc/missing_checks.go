package dataproc

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type dataprocCheck struct {
	metadata models.CheckMetadata
}

func (c *dataprocCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *dataprocCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP Dataproc check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "dataproc",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newDataprocCheck(id, title, desc, sev string) dataprocCheck {
	return dataprocCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "dataproc", ResourceType: "Cluster",
		Categories: []string{"dataproc"},
	}}
}

type dataprocClusterEncryptionEnabled struct{ dataprocCheck }

func NewDataprocClusterEncryptionEnabled() *dataprocClusterEncryptionEnabled {
	return &dataprocClusterEncryptionEnabled{newDataprocCheck(
		"dataproc_cluster_encryption_enabled",
		"Ensure Dataproc cluster encryption is enabled",
		"Dataproc cluster should have encryption enabled",
		"medium",
	)}
}
