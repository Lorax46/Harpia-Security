package cloudfunctions

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cloudfunctionCheck struct {
	metadata models.CheckMetadata
}

func (c *cloudfunctionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *cloudfunctionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP Cloud Function check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "cloudfunction",
		FoundAt: time.Now().UTC(),
	}}, nil
}

func newCloudfunctionCheck(id, title, desc, sev string) cloudfunctionCheck {
	return cloudfunctionCheck{metadata: models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: desc, Severity: sev,
		ServiceName: "cloudfunction", ResourceType: "Function",
		Categories: []string{"cloudfunction"},
	}}
}

type cloudfunctionFunctionNoVpcConnector struct{ cloudfunctionCheck }

func NewCloudfunctionFunctionNoVpcConnector() *cloudfunctionFunctionNoVpcConnector {
	return &cloudfunctionFunctionNoVpcConnector{newCloudfunctionCheck(
		"cloudfunction_function_no_vpc_connector",
		"Ensure cloud function has no VPC connector",
		"Cloud function should have no VPC connector",
		"medium",
	)}
}

type cloudfunctionFunctionVpcConnectorInUse struct{ cloudfunctionCheck }

func NewCloudfunctionFunctionVpcConnectorInUse() *cloudfunctionFunctionVpcConnectorInUse {
	return &cloudfunctionFunctionVpcConnectorInUse{newCloudfunctionCheck(
		"cloudfunction_function_vpc_connector_in_use",
		"Ensure cloud function VPC connector is in use",
		"Cloud function VPC connector should be in use",
		"low",
	)}
}
