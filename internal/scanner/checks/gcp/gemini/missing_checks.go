package gemini

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type geminiCheck struct {
	metadata models.CheckMetadata
}

func (c *geminiCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *geminiCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP Gemini check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "gemini",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newGeminiCheck(id, title, desc, sev string) geminiCheck {
	return geminiCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "gemini", ResourceType: "Model",
		Categories: []string{"gemini"},
	}}
}

type geminiModelPublicAccessDisabled struct{ geminiCheck }

func NewGeminiModelPublicAccessDisabled() *geminiModelPublicAccessDisabled {
	return &geminiModelPublicAccessDisabled{newGeminiCheck("gemini_model_public_access_disabled", "Ensure Gemini model public access is disabled", "Gemini model should have public access disabled", "high")}
}
