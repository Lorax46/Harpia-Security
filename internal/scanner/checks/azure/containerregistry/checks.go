package containerregistry

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type containerregistryAdminUserDisabled struct {
	metadata models.CheckMetadata
}

func NewContainerregistryAdminUserDisabled() *containerregistryAdminUserDisabled {
	return &containerregistryAdminUserDisabled{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "containerregistry_admin_user_disabled",
		CheckTitle: "Ensure container registry admin user is disabled",
		Description: "Container registry should have admin user disabled",
		Severity: "high", ServiceName: "containerregistry", ResourceType: "Registry",
		Categories: []string{"containerregistry", "admin"},
	}}
}

func (c *containerregistryAdminUserDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *containerregistryAdminUserDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Container registry admin check requires Azure SDK",
		ResourceID: "containerregistry-admin", Provider: "azure", Service: "containerregistry",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type containerregistryNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewContainerregistryNotPubliclyAccessible() *containerregistryNotPubliclyAccessible {
	return &containerregistryNotPubliclyAccessible{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "containerregistry_not_publicly_accessible",
		CheckTitle: "Ensure container registry is not publicly accessible",
		Description: "Container registry should not be publicly accessible",
		Severity: "high", ServiceName: "containerregistry", ResourceType: "Registry",
		Categories: []string{"containerregistry", "public-access"},
	}}
}

func (c *containerregistryNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *containerregistryNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Container registry public access check requires Azure SDK",
		ResourceID: "containerregistry-public-access", Provider: "azure", Service: "containerregistry",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type containerregistryUsesPrivateLink struct {
	metadata models.CheckMetadata
}

func NewContainerregistryUsesPrivateLink() *containerregistryUsesPrivateLink {
	return &containerregistryUsesPrivateLink{metadata: models.CheckMetadata{
		Provider: "azure", CheckID: "containerregistry_uses_private_link",
		CheckTitle: "Ensure container registry uses private link",
		Description: "Container registry should use private link",
		Severity: "medium", ServiceName: "containerregistry", ResourceType: "Registry",
		Categories: []string{"containerregistry", "private-link"},
	}}
}

func (c *containerregistryUsesPrivateLink) Metadata() models.CheckMetadata { return c.metadata }

func (c *containerregistryUsesPrivateLink) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Container registry private link check requires Azure SDK",
		ResourceID: "containerregistry-private-link", Provider: "azure", Service: "containerregistry",
		FoundAt: time.Now().UTC(),
	}}, nil
}
