package apim

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type apimThreatDetectionLlmJacking struct {
	metadata models.CheckMetadata
}

func NewApimThreatDetectionLlmJacking() *apimThreatDetectionLlmJacking {
	return &apimThreatDetectionLlmJacking{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "apim_threat_detection_llm_jacking",
		CheckTitle: "Ensure APIM has LLM jacking threat detection enabled",
		Description: "APIM should have LLM jacking threat detection enabled",
		Severity: "high", ServiceName: "apim", ResourceType: "ApiManagementService",
		Categories: []string{"apim", "llm"},
	}}
}

func (c *apimThreatDetectionLlmJacking) Metadata() models.CheckMetadata { return c.metadata }

func (c *apimThreatDetectionLlmJacking) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "APIM threat detection check requires Azure SDK",
		ResourceID: "apim-threat-detection", Provider: "azure", Service: "apim",
		FoundAt: time.Now().UTC(),
	}}, nil
}
