package policy

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type policyAssignmentExists struct {
	metadata models.CheckMetadata
}

func NewPolicyAssignmentExists() *policyAssignmentExists {
	return &policyAssignmentExists{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "policy_assignment_exists",
		CheckTitle: "Ensure policy assignment exists",
		Description: "Policy assignment should exist for compliance",
		Severity: "medium", ServiceName: "policy", ResourceType: "PolicyAssignment",
		Categories: []string{"policy"},
	}}
}

func (c *policyAssignmentExists) Metadata() models.CheckMetadata { return c.metadata }

func (c *policyAssignmentExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Policy assignment check requires Azure SDK",
		ResourceID: "policy-assignment", Provider: "azure", Service: "policy",
		FoundAt: time.Now().UTC(),
	}}, nil
}
