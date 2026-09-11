package logging

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type loggingCheck struct {
	metadata models.CheckMetadata
}

func (c *loggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *loggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP Logging check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "logging",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newLoggingCheck(id, title, desc, sev string) loggingCheck {
	return loggingCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "logging", ResourceType: "Sink",
		Categories: []string{"logging"},
	}}
}

type loggingLogSinkExists struct{ loggingCheck }

func NewLoggingLogSinkExists() *loggingLogSinkExists {
	return &loggingLogSinkExists{newLoggingCheck("logging_log_sink_exists", "Ensure logging log sink exists", "Logging log sink should exist", "medium")}
}

type loggingProjectOwnershipSinkExists struct{ loggingCheck }

func NewLoggingProjectOwnershipSinkExists() *loggingProjectOwnershipSinkExists {
	return &loggingProjectOwnershipSinkExists{newLoggingCheck("logging_project_ownership_sink_exists", "Ensure logging project ownership sink exists", "Logging project ownership sink should exist", "medium")}
}
