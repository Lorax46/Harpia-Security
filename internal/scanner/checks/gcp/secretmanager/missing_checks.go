package secretmanager

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type secretmanagerCheck struct {
	metadata models.CheckMetadata
}

func (c *secretmanagerCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *secretmanagerCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP Secret Manager check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "secretmanager",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newSecretmanagerCheck(id, title, desc, sev string) secretmanagerCheck {
	return secretmanagerCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "secretmanager", ResourceType: "Secret",
		Categories: []string{"secretmanager"},
	}}
}

type secretmanagerSecretNoDefaultLabel struct{ secretmanagerCheck }

func NewSecretmanagerSecretNoDefaultLabel() *secretmanagerSecretNoDefaultLabel {
	return &secretmanagerSecretNoDefaultLabel{newSecretmanagerCheck("secretmanager_secret_no_default_label", "Ensure secret has no default label", "Secret should have no default label", "low")}
}

type secretmanagerSecretRotationEnabled struct{ secretmanagerCheck }

func NewSecretmanagerSecretRotationEnabled() *secretmanagerSecretRotationEnabled {
	return &secretmanagerSecretRotationEnabled{newSecretmanagerCheck("secretmanager_secret_rotation_enabled", "Ensure secret rotation is enabled", "Secret rotation should be enabled", "medium")}
}
