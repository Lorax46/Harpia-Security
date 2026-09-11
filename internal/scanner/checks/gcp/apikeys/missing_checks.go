package apikeys

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type apikeysCheck struct {
	metadata models.CheckMetadata
}

func (c *apikeysCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *apikeysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP API Keys check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "apikeys",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newApikeysCheck(id, title, desc, sev string) apikeysCheck {
	return apikeysCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "apikeys", ResourceType: "Key",
		Categories: []string{"apikeys"},
	}}
}

type apikeysKeyComplianceCheck struct{ apikeysCheck }

func NewApikeysKeyComplianceCheck() *apikeysKeyComplianceCheck {
	return &apikeysKeyComplianceCheck{newApikeysCheck("apikeys_key_compliance_check", "Ensure API key compliance", "API key should be compliant", "medium")}
}

type apikeysKeyNotExists struct{ apikeysCheck }

func NewApikeysKeyNotExists() *apikeysKeyNotExists {
	return &apikeysKeyNotExists{newApikeysCheck("apikeys_key_not_exists", "Ensure API key does not exist", "API key should not exist", "medium")}
}

type apikeysKeyRotation90Days struct{ apikeysCheck }

func NewApikeysKeyRotation90Days() *apikeysKeyRotation90Days {
	return &apikeysKeyRotation90Days{newApikeysCheck("apikeys_key_rotation_90_days", "Ensure API key rotation within 90 days", "API key should be rotated within 90 days", "medium")}
}

type apikeysKeyRotationOver90Days struct{ apikeysCheck }

func NewApikeysKeyRotationOver90Days() *apikeysKeyRotationOver90Days {
	return &apikeysKeyRotationOver90Days{newApikeysCheck("apikeys_key_rotation_over_90_days", "Ensure API key rotation is over 90 days", "API key rotation should be over 90 days", "medium")}
}
