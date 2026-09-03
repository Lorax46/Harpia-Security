package iam

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// IAMSupportRoleCreated check
type IAMSupportRoleCreated struct {
	metadata models.CheckMetadata
}

func NewIAMSupportRoleCreated() *IAMSupportRoleCreated {
	return &IAMSupportRoleCreated{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "iam_support_role_created",
			CheckTitle:      "At least one IAM role has the AWSSupportAccess managed policy attached",
			ServiceName:     "iam",
			Severity:        "low",
			ResourceType:    "AwsIamRole",
			ResourceGroup:   "IAM",
			Description:     "Presence of an IAM role with AWSSupportAccess policy",
			Risk:            "Without dedicated support role, case creation delayed and admin/root may be used",
			RemediationText: "Create a dedicated IAM role for AWS Support with AWSSupportAccess",
			RemediationURL:  "https://hub.prowler.com/check/iam_support_role_created",
			Categories:      []string{"identity-access"},
		},
	}
}

func (c *IAMSupportRoleCreated) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *IAMSupportRoleCreated) Execute(ctx context.Context) ([]models.Finding, error) {
	// TODO: implementar chamada AWS IAM
	// Por enquanto retorna finding de exemplo
	finding := models.Finding{
		ID:             "iam_support_role_created",
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         models.StatusInfo,
		StatusExtended: "Check requires AWS credentials - not yet implemented",
		Provider:       "aws",
		Service:        "iam",
		Region:         "us-east-1",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
	}
	return []models.Finding{finding}, nil
}
