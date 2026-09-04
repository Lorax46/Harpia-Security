package kms

import (
	"context"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// KmsKeyRotationEnabled - high
type KmsKeyRotationEnabled struct {
	metadata models.CheckMetadata
}

// NewKmsKeyRotationEnabled cria nova instância
func NewKmsKeyRotationEnabled() *KmsKeyRotationEnabled {
	return &KmsKeyRotationEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "kms_key_rotation_enabled",
			CheckTitle:     "Customer-managed KMS key has rotation enabled with interval of 365 days or less",
			ServiceName:    "kms",
			Severity:       "high",
			Description:    "**OCI KMS customer-managed keys** configured for **automatic rotation**, with a rotation interval set to `<= 365` days, or **manually rotated** within",
			RemediationText: "Enable **automatic key rotation** and set an interval `<= 365` days (*shorter for sensitive data*). ",
			Categories:     []string{"kms"},
		},
	}
}

// Metadata retorna os metadados
func (c *KmsKeyRotationEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *KmsKeyRotationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "kms",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

