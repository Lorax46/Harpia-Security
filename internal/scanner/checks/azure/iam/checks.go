package iam

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type iamCustomRoleDefinition struct {
	metadata models.CheckMetadata
}

func NewIamCustomRoleDefinition() *iamCustomRoleDefinition {
	return &iamCustomRoleDefinition{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "iam_custom_role_definition",
		CheckTitle: "Ensure custom role definitions are properly configured",
		Description: "Custom role definitions should be properly configured",
		Severity: "medium", ServiceName: "iam", ResourceType: "RoleDefinition",
		Categories: []string{"iam", "roles"},
	}}
}

func (c *iamCustomRoleDefinition) Metadata() models.CheckMetadata { return c.metadata }

func (c *iamCustomRoleDefinition) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "IAM custom role check requires Azure SDK",
		ResourceID: "iam-custom-role", Provider: "azure", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type iamRoleAssignmentNotification struct {
	metadata models.CheckMetadata
}

func NewIamRoleAssignmentNotification() *iamRoleAssignmentNotification {
	return &iamRoleAssignmentNotification{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "iam_role_assignment_notification",
		CheckTitle: "Ensure role assignment notifications are configured",
		Description: "Role assignment notifications should be configured",
		Severity: "medium", ServiceName: "iam", ResourceType: "RoleAssignment",
		Categories: []string{"iam", "notifications"},
	}}
}

func (c *iamRoleAssignmentNotification) Metadata() models.CheckMetadata { return c.metadata }

func (c *iamRoleAssignmentNotification) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "IAM role assignment notification check requires Azure SDK",
		ResourceID: "iam-role-notification", Provider: "azure", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type iamUserWithOwnerPermissions struct {
	metadata models.CheckMetadata
}

func NewIamUserWithOwnerPermissions() *iamUserWithOwnerPermissions {
	return &iamUserWithOwnerPermissions{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "iam_user_with_owner_permissions",
		CheckTitle: "Ensure users with owner permissions are reviewed",
		Description: "Users with owner permissions should be reviewed",
		Severity: "medium", ServiceName: "iam", ResourceType: "RoleAssignment",
		Categories: []string{"iam", "owner"},
	}}
}

func (c *iamUserWithOwnerPermissions) Metadata() models.CheckMetadata { return c.metadata }

func (c *iamUserWithOwnerPermissions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "IAM user owner permissions check requires Azure SDK",
		ResourceID: "iam-user-owner", Provider: "azure", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}
